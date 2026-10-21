// Copyright 2010-2024 The ZAP Development Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a Rust derivative of the ZAP core. It changes the language
// and the architecture (Apache License 2.0, section 4). It is not an
// official OWASP ZAP build.

//! Dispatch `http://zap/JSON/<component>/<type>/<name>/`.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use serde_json::{json, Map, Value};
use zap_core::{HistoryRow, HttpMessage, HttpResponse};
use zap_store::{AlertRow, Confidence, Risk, Session};

/// Answers API requests for one session.
pub struct ApiService {
    session: Arc<Session>,
    version: String,
    on_shutdown: Arc<dyn Fn() + Send + Sync>,
}

struct Outcome {
    response: HttpResponse,
    shutdown: bool,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn bad_format() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_format", "Bad Format")
    }

    fn bad_type() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_type", "Bad Type")
    }

    fn bad_view() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_view", "Bad View")
    }

    fn bad_action() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_action", "Bad Action")
    }

    fn no_implementor() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "no_implementor", "No Implementor")
    }

    fn missing_parameter() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "missing_parameter",
            "Missing Parameter",
        )
    }

    fn illegal_parameter() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "illegal_parameter",
            "Provided parameter has illegal or unrecognized value",
        )
    }

    fn does_not_exist() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "does_not_exist", "Does Not Exist")
    }

    fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal Error",
        )
    }

    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    fn response(self) -> HttpResponse {
        json_response(
            self.status,
            json!({ "code": self.code, "message": self.message }),
        )
    }
}

impl ApiService {
    pub fn new(
        session: Arc<Session>,
        version: impl Into<String>,
        on_shutdown: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            session,
            version: version.into(),
            on_shutdown,
        }
    }

    /// Handle `msg` when its host is `zap`.
    ///
    /// Returns true when this was an API request. The response is set on
    /// `msg` and the caller must not contact an origin. `core/action/shutdown`
    /// invokes the shutdown hook after the response is ready.
    pub fn handle(&self, msg: &mut HttpMessage) -> bool {
        if !is_zap_host(&msg.uri) {
            return false;
        }
        let outcome = self.dispatch(msg);
        if outcome.shutdown {
            (self.on_shutdown)();
        }
        msg.response = Some(outcome.response);
        true
    }

    fn dispatch(&self, msg: &HttpMessage) -> Outcome {
        match self.route(msg) {
            Ok(outcome) => outcome,
            Err(err) => Outcome {
                response: err.response(),
                shutdown: false,
            },
        }
    }

    fn route(&self, msg: &HttpMessage) -> Result<Outcome, ApiError> {
        let mut parts = msg.uri.path().split('/').filter(|part| !part.is_empty());
        let Some(format) = parts.next() else {
            return Err(ApiError::bad_format());
        };
        if !format.eq_ignore_ascii_case("json") {
            return Err(ApiError::bad_format());
        }
        let component = parts.next().ok_or_else(ApiError::no_implementor)?;
        let kind = parts.next().ok_or_else(ApiError::bad_type)?;
        let name = parts.next().ok_or_else(|| match kind {
            "view" => ApiError::bad_view(),
            "action" => ApiError::bad_action(),
            _ => ApiError::bad_type(),
        })?;
        if kind != "view" && kind != "action" {
            return Err(ApiError::bad_type());
        }
        let params = params_of(msg);
        let body = match (component, kind, name) {
            ("core", "view", "version") => json!({ "version": self.version }),
            ("core", "view", "hosts") => self.hosts()?,
            ("core", "view", "messages") => self.messages(&params)?,
            ("core", "action", "shutdown") => {
                return Ok(Outcome {
                    response: json_response(StatusCode::OK, json!({ "Result": "OK" })),
                    shutdown: true,
                });
            }
            ("alert", "view", "alerts") => self.alerts(&params)?,
            ("alert", "view", "alert") => self.alert(&params)?,
            ("core", "view", _) => return Err(ApiError::bad_view()),
            ("alert", "view", _) => return Err(ApiError::bad_view()),
            ("core", "action", _) | ("alert", "action", _) => return Err(ApiError::bad_action()),
            _ => return Err(ApiError::no_implementor()),
        };
        Ok(Outcome {
            response: json_response(StatusCode::OK, body),
            shutdown: false,
        })
    }

    fn hosts(&self) -> Result<Value, ApiError> {
        let nodes = self
            .session
            .site_nodes()
            .map_err(|_| ApiError::internal())?;
        let hosts: Vec<String> = nodes
            .into_iter()
            .filter(|node| node.parent_id.is_none())
            .map(|node| host_name(&node.segment))
            .collect();
        Ok(json!({ "hosts": hosts }))
    }

    fn messages(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let start = optional_i32(params, "start")?.unwrap_or(-1);
        let count = optional_i32(params, "count")?.unwrap_or(-1);
        let base = params
            .get("baseurl")
            .map(String::as_str)
            .filter(|s| !s.is_empty());
        let rows = self
            .session
            .history_rows()
            .map_err(|_| ApiError::internal())?;
        let filtered = rows.into_iter().filter(|row| {
            !is_image(&row.request_headers)
                && !is_image(&row.response_headers)
                && base.is_none_or(|prefix| row.url.starts_with(prefix))
        });
        let page = paginate(filtered, start, count);
        Ok(string_list(
            "messages",
            page.iter().map(message_value).collect(),
        ))
    }

    fn alerts(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let start = optional_i32(params, "start")?.unwrap_or(-1);
        let count = optional_i32(params, "count")?.unwrap_or(-1);
        let risk_id = match optional_i32(params, "riskId")? {
            None => None,
            Some(-1) => None,
            Some(code) if Risk::from_code(code).is_some() => Some(code),
            Some(_) => return Err(ApiError::illegal_parameter()),
        };
        let include_false_positive = params
            .get("falsePositive")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"));
        let base = params
            .get("baseurl")
            .map(String::as_str)
            .filter(|s| !s.is_empty());
        let rows = self.session.alerts().map_err(|_| ApiError::internal())?;
        let filtered = rows.into_iter().filter(|row| {
            (include_false_positive || row.confidence != Confidence::FalsePositive.code())
                && risk_id.is_none_or(|risk| row.risk == risk)
                && base.is_none_or(|prefix| row.url.starts_with(prefix))
        });
        let page = paginate(filtered, start, count);
        Ok(string_list(
            "alerts",
            page.iter().map(alert_value).collect(),
        ))
    }

    fn alert(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let Some(raw) = params.get("id").filter(|value| !value.is_empty()) else {
            return Err(ApiError::missing_parameter());
        };
        let id: i64 = raw.parse().map_err(|_| ApiError::illegal_parameter())?;
        let row = self
            .session
            .alert(id)
            .map_err(|_| ApiError::internal())?
            .ok_or_else(ApiError::does_not_exist)?;
        Ok(json!({ "alert": alert_value(&row).to_string() }))
    }
}

fn is_zap_host(uri: &Uri) -> bool {
    let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
    let host_ok = uri
        .host()
        .is_some_and(|host| host.eq_ignore_ascii_case("zap"));
    scheme_ok && host_ok
}

fn host_name(segment: &str) -> String {
    let mut site = segment;
    if let Some(index) = site.find("//") {
        site = &site[index + 2..];
    }
    if let Some(index) = site.find(':') {
        site = &site[..index];
    }
    site.to_string()
}

fn params_of(msg: &HttpMessage) -> HashMap<String, String> {
    let content_type = msg
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if msg.method == http::Method::POST
        && content_type.starts_with("application/x-www-form-urlencoded")
    {
        return parse_pairs(&String::from_utf8_lossy(&msg.body));
    }
    parse_pairs(msg.uri.query().unwrap_or(""))
}

fn parse_pairs(input: &str) -> HashMap<String, String> {
    input
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let name = percent_decode(parts.next().unwrap_or(""));
            let value = percent_decode(parts.next().unwrap_or(""));
            (name, value)
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (from_hex(bytes[index + 1]), from_hex(bytes[index + 2]))
                {
                    out.push((high << 4) | low);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn optional_i32(params: &HashMap<String, String>, key: &str) -> Result<Option<i32>, ApiError> {
    match params
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
    {
        None => Ok(None),
        Some(value) => value
            .parse()
            .map(Some)
            .map_err(|_| ApiError::illegal_parameter()),
    }
}

fn paginate<T>(items: impl Iterator<Item = T>, start: i32, count: i32) -> Vec<T> {
    let mut page_started = start <= 0;
    let start_record = if start > 0 { start } else { 0 };
    let (has_end, final_record) = if count > 0 {
        let final_record = if page_started {
            count
        } else {
            start + count - 1
        };
        (true, final_record)
    } else {
        (false, 0)
    };
    let mut processed = 0;
    let mut out = Vec::new();
    for item in items {
        processed += 1;
        if !page_started {
            page_started = processed >= start_record;
        }
        let page_ended = has_end && processed >= final_record;
        if page_started {
            out.push(item);
        }
        if page_ended {
            break;
        }
    }
    out
}

fn is_image(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value.to_ascii_lowercase().starts_with("image/")
    })
}

fn message_value(row: &HistoryRow) -> Value {
    let path = row
        .url
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.path_and_query().map(|path| path.as_str().to_string()))
        .unwrap_or_else(|| "/".to_string());
    let request_start = format!("{} {path} HTTP/1.1", row.method);
    let response_start = format!("HTTP/1.1 {} {}", row.status, reason(row.status));
    json!({
        "id": row.id.to_string(),
        "type": "1",
        "timestamp": row.recorded_at_ms.to_string(),
        "rtt": "0",
        "cookieParams": "",
        "note": "",
        "requestHeader": header_block(&request_start, &row.request_headers),
        "requestBody": String::from_utf8_lossy(&row.request_body),
        "responseHeader": header_block(&response_start, &row.response_headers),
        "responseBody": String::from_utf8_lossy(&row.response_body),
        "tags": [],
    })
}

fn alert_value(row: &AlertRow) -> Value {
    let alert_ref = if row.plugin_id > -1 {
        row.plugin_id.to_string()
    } else {
        String::new()
    };
    json!({
        "id": row.id.to_string(),
        "pluginId": row.plugin_id.to_string(),
        "alertRef": alert_ref,
        "alert": "",
        "name": "",
        "nodeName": "",
        "description": "",
        "risk": risk_label(row.risk),
        "confidence": confidence_label(row.confidence),
        "url": row.url,
        "method": "",
        "other": "",
        "param": row.param,
        "attack": "",
        "evidence": "",
        "inputVector": "",
        "reference": "",
        "cweid": row.cwe_id.to_string(),
        "wascid": row.wasc_id.to_string(),
        "sourceid": "0",
        "solution": "",
        "messageId": "0",
        "sourceMessageId": 0,
        "tags": {},
    })
}

fn risk_label(code: i32) -> String {
    match Risk::from_code(code) {
        Some(Risk::Informational) => "Informational".to_string(),
        Some(Risk::Low) => "Low".to_string(),
        Some(Risk::Medium) => "Medium".to_string(),
        Some(Risk::High) => "High".to_string(),
        None => code.to_string(),
    }
}

fn confidence_label(code: i32) -> String {
    match Confidence::from_code(code) {
        Some(Confidence::FalsePositive) => "False Positive".to_string(),
        Some(Confidence::Low) => "Low".to_string(),
        Some(Confidence::Medium) => "Medium".to_string(),
        Some(Confidence::High) => "High".to_string(),
        Some(Confidence::UserConfirmed) => "Confirmed".to_string(),
        None => code.to_string(),
    }
}

fn reason(status: u16) -> &'static str {
    StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Unknown")
}

fn header_block(start: &str, headers: &[(String, String)]) -> String {
    let mut out = String::new();
    out.push_str(start);
    out.push_str("\r\n");
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

fn string_list(name: &str, items: Vec<Value>) -> Value {
    let mut map = Map::new();
    map.insert(
        name.to_string(),
        Value::Array(
            items
                .into_iter()
                .map(|item| Value::String(item.to_string()))
                .collect(),
        ),
    );
    Value::Object(map)
}

fn json_response(status: StatusCode, body: Value) -> HttpResponse {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    HttpResponse {
        status,
        headers,
        body: Bytes::from(bytes),
    }
}
