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

//! PHASE-11 packaged scan.
//!
//! `zap-baseline.py --autooff` spiders the target and reads passive-scan
//! results. Responses from that crawl, and from `core/action/accessUrl`,
//! are stored and scanned by the same passive listener the proxy uses.
//! The automation framework and the AJAX spider are not served.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};
use zap_core::{HttpMessage, HttpResponse, ProxyListener};
use zap_proxy::EarlyOverride;
use zap_pscan::{PassiveScanListener, PLUGIN_ID};
use zap_spider::{DefaultSender, FetchResponse, Spider, SpiderSender};
use zap_store::Session;

const RULE_NAME: &str = "X-Content-Type-Options Header Missing";

/// Spider and passive-scan API used by the packaged scan scripts.
pub struct PackagedScan {
    spider: Arc<Spider>,
    sender: Arc<RecordingSender>,
    scans: Arc<Mutex<HashMap<u64, bool>>>,
    next_id: AtomicU64,
}

struct RecordingSender {
    inner: DefaultSender,
    session: Arc<Session>,
    pscan: Arc<PassiveScanListener>,
}

/// Sets the scan to finished when the crawl thread ends, including on panic.
struct MarkDone {
    scans: Arc<Mutex<HashMap<u64, bool>>>,
    id: u64,
}

impl Drop for MarkDone {
    fn drop(&mut self) {
        if let Ok(mut scans) = self.scans.lock() {
            scans.insert(self.id, true);
        }
    }
}

impl SpiderSender for RecordingSender {
    fn fetch(&self, method: &str, url: &str, body: &[u8]) -> Result<FetchResponse, String> {
        let response = self.inner.fetch(method, url, body)?;
        let mut message = http_message(method, url, body, &response)?;
        self.session
            .record_exchange(&message)
            .map_err(|err| err.to_string())?;
        let _ = ProxyListener::on_http_response_receive(self.pscan.as_ref(), &mut message);
        Ok(response)
    }
}

/// Passive listener shared with the proxy, plus the packaged-scan API.
pub fn start(
    session: Arc<Session>,
) -> Result<(Arc<PackagedScan>, Arc<PassiveScanListener>), String> {
    let pscan = Arc::new(PassiveScanListener::new(Arc::clone(&session)));
    let sender = Arc::new(RecordingSender {
        inner: DefaultSender::from_current()?,
        session,
        pscan: Arc::clone(&pscan),
    });
    let spider_sender: Arc<dyn SpiderSender> = sender.clone();
    let packaged = Arc::new(PackagedScan {
        spider: Arc::new(Spider::new(spider_sender)),
        sender,
        scans: Arc::new(Mutex::new(HashMap::new())),
        next_id: AtomicU64::new(0),
    });
    Ok((packaged, pscan))
}

/// Answer spider, passive-scan, and `accessUrl`, then the previous override.
pub fn chain(inner: EarlyOverride, packaged: Arc<PackagedScan>) -> EarlyOverride {
    Arc::new(move |message| {
        if packaged.handle(message) {
            return true;
        }
        inner(message)
    })
}

/// One line for the daemon log. Only the ported baseline rule is named.
pub fn startup_line() -> &'static str {
    "Packaged scan: zapd daemon, no JDK; baseline rules in scope: 10021"
}

impl PackagedScan {
    /// Handle packaged-scan API calls. Other components return false.
    pub fn handle(&self, msg: &mut HttpMessage) -> bool {
        if !is_zap_host(&msg.uri) {
            return false;
        }
        let mut parts = msg.uri.path().split('/').filter(|part| !part.is_empty());
        let Some(format) = parts.next() else {
            return false;
        };
        if !format.eq_ignore_ascii_case("json") {
            return false;
        }
        let Some(component) = parts.next() else {
            return false;
        };
        let kind = parts.next();
        let name = parts.next();
        let outcome = match (component, kind, name) {
            ("spider", Some("action"), Some("scan")) => self.scan(&params_of(msg)),
            ("spider", Some("view"), Some("status")) => self.status(&params_of(msg)),
            ("pscan", Some("view"), Some("scanners")) => Ok(self.scanners()),
            ("pscan", Some("view"), Some("recordsToScan")) => Ok(json!({ "recordsToScan": "0" })),
            ("pscan", Some("action"), Some("disableAllTags")) => Ok(json!({ "Result": "OK" })),
            ("pscan", Some("action"), Some("setMaxAlertsPerRule")) => Ok(json!({ "Result": "OK" })),
            ("core", Some("action"), Some("accessUrl")) => self.access_url(&params_of(msg)),
            ("spider" | "pscan", _, _) => Err(unknown(kind)),
            _ => return false,
        };
        msg.response = Some(match outcome {
            Ok(body) => json_response(StatusCode::OK, body),
            Err(err) => err.response(),
        });
        true
    }

    fn scan(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let url = params.get("url").map(String::as_str).unwrap_or("").trim();
        if url.is_empty() {
            return Err(ApiError::missing_parameter());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut scans) = self.scans.lock() {
            scans.insert(id, false);
        }
        let spider = Arc::clone(&self.spider);
        let scans = Arc::clone(&self.scans);
        let seed = url.to_string();
        std::thread::spawn(move || {
            let _done = MarkDone { scans, id };
            let _ = spider.crawl(&seed, None);
        });
        Ok(json!({ "scan": id.to_string() }))
    }

    fn status(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let id = match params.get("scanId").map(String::as_str) {
            None | Some("") => self.latest_id().ok_or_else(ApiError::does_not_exist)?,
            Some(value) => value
                .parse::<u64>()
                .map_err(|_| ApiError::illegal_parameter())?,
        };
        let done = self
            .scans
            .lock()
            .map(|scans| scans.get(&id).copied().unwrap_or(false))
            .unwrap_or(false);
        let status = if done { "100" } else { "0" };
        Ok(json!({ "status": status }))
    }

    fn latest_id(&self) -> Option<u64> {
        let current = self.next_id.load(Ordering::Relaxed);
        current.checked_sub(1)
    }

    fn scanners(&self) -> Value {
        json!({
            "scanners": [{
                "id": PLUGIN_ID.to_string(),
                "name": RULE_NAME,
                "enabled": "true",
            }]
        })
    }

    fn access_url(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let url = params.get("url").map(String::as_str).unwrap_or("").trim();
        if url.is_empty() {
            return Err(ApiError::missing_parameter());
        }
        let body = match blocking_fetch(Arc::clone(&self.sender), "GET", url, &[]) {
            Ok(response) => String::from_utf8_lossy(&response.body).into_owned(),
            Err(err) => format!("ZAP Error: {err}"),
        };
        Ok(json!({ "accessUrl": body }))
    }
}

fn blocking_fetch(
    sender: Arc<RecordingSender>,
    method: &str,
    url: &str,
    body: &[u8],
) -> Result<FetchResponse, String> {
    let method = method.to_string();
    let url = url.to_string();
    let body = body.to_vec();
    let task = move || sender.fetch(&method, &url, &body);
    let joined = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| std::thread::spawn(task).join())
    } else {
        std::thread::spawn(task).join()
    };
    match joined {
        Ok(result) => result,
        Err(_) => Err("fetch thread panicked".to_string()),
    }
}

fn unknown(kind: Option<&str>) -> ApiError {
    match kind {
        Some("view") => ApiError::bad_view(),
        Some("action") => ApiError::bad_action(),
        _ => ApiError::bad_type(),
    }
}

fn http_message(
    method: &str,
    url: &str,
    body: &[u8],
    response: &FetchResponse,
) -> Result<HttpMessage, String> {
    let method = Method::from_bytes(method.as_bytes()).map_err(|err| err.to_string())?;
    let uri = url
        .parse()
        .map_err(|err: http::uri::InvalidUri| err.to_string())?;
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK);
    let mut headers = HeaderMap::new();
    for (name, value) in &response.headers {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            continue;
        };
        headers.append(name, value);
    }
    Ok(HttpMessage {
        method,
        uri,
        headers: HeaderMap::new(),
        body: Bytes::copy_from_slice(body),
        response: Some(HttpResponse {
            status,
            headers,
            body: Bytes::from(response.body.clone()),
        }),
    })
}

fn is_zap_host(uri: &http::Uri) -> bool {
    matches!(uri.scheme_str(), Some("http" | "https"))
        && uri
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case("zap"))
}

fn params_of(msg: &HttpMessage) -> HashMap<String, String> {
    let content_type = msg
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let input = if msg.method == Method::POST
        && content_type.starts_with("application/x-www-form-urlencoded")
    {
        String::from_utf8_lossy(&msg.body).into_owned()
    } else {
        msg.uri.query().unwrap_or("").to_string()
    };
    parse_pairs(&input)
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

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn bad_type() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_type", "Bad Type")
    }

    fn bad_view() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_view", "Bad View")
    }

    fn bad_action() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_action", "Bad Action")
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{HeaderMap, Method, StatusCode};
    use zap_core::HttpMessage;
    use zap_store::Session;

    use super::start;

    fn temp_db() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zap-phase11-{}-unit", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path.join("session.sqlite")
    }

    fn message(url: &str) -> HttpMessage {
        HttpMessage {
            method: Method::GET,
            uri: url.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: None,
        }
    }

    #[tokio::test]
    async fn packaged_scan_lists_only_the_ported_passive_rule() {
        let session = Arc::new(Session::open(temp_db()).unwrap());
        let (packaged, _) = start(session).unwrap();

        let mut scanners = message("http://zap/JSON/pscan/view/scanners/");
        assert!(packaged.handle(&mut scanners));
        let body: serde_json::Value =
            serde_json::from_slice(&scanners.response.unwrap().body).unwrap();
        assert_eq!(body["scanners"][0]["id"], "10021");
        assert_eq!(
            body["scanners"][0]["name"],
            "X-Content-Type-Options Header Missing"
        );
        assert_eq!(body["scanners"].as_array().unwrap().len(), 1);

        let mut pending = message("http://zap/JSON/pscan/view/recordsToScan/");
        assert!(packaged.handle(&mut pending));
        let body: serde_json::Value =
            serde_json::from_slice(&pending.response.unwrap().body).unwrap();
        assert_eq!(body["recordsToScan"], "0");

        let mut version = message("http://zap/JSON/core/view/version/");
        assert!(!packaged.handle(&mut version));
        assert!(version.response.is_none());

        let mut missing = message("http://zap/JSON/core/action/accessUrl/");
        assert!(packaged.handle(&mut missing));
        let response = missing.response.unwrap();
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }
}
