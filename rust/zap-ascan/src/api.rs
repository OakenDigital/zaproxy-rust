// Copyright 2012 The ZAP Development Team
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
// official OWASP ZAP build. The JSON keys follow `ActiveScanAPI` for
// `scan`, `status`, and `stop`.

//! `http://zap/JSON/ascan/` actions and the status view.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use serde_json::{json, Value};
use zap_core::{HttpMessage, HttpResponse};
use zap_store::Session;

use crate::coding::form_pairs;
use crate::context::ActivePlugin;
use crate::engine::{Engine, ScanOptions};
use crate::rules::{CrlfInjectionScanRule, XpathInjectionScanRule};
use crate::sender::ScanSender;

/// Active scan API and engine.
pub struct ActiveScanService {
    engine: Arc<Engine>,
}

impl ActiveScanService {
    pub fn new(session: Arc<Session>, sender: Arc<dyn ScanSender>) -> Self {
        Self::with_plugins(session, sender, Vec::new())
    }

    /// Built-in CRLF and XPath rules, then `extra` from installed add-ons.
    pub fn with_plugins(
        session: Arc<Session>,
        sender: Arc<dyn ScanSender>,
        extra: Vec<Arc<dyn ActivePlugin>>,
    ) -> Self {
        let mut plugins: Vec<Arc<dyn ActivePlugin>> = vec![
            Arc::new(CrlfInjectionScanRule),
            Arc::new(XpathInjectionScanRule),
        ];
        plugins.extend(extra);
        Self {
            engine: Arc::new(Engine::with_plugins(session, sender, plugins)),
        }
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Handle an `ascan` API call. Other hosts and components return false.
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
        if component != "ascan" {
            return false;
        }
        let outcome = match (parts.next(), parts.next()) {
            (Some("action"), Some("scan")) => self.scan(&params_of(msg)),
            (Some("action"), Some("stop")) => self.stop(&params_of(msg)),
            (Some("view"), Some("status")) => self.status(&params_of(msg)),
            (Some("action"), None) => Err(ApiError::bad_action()),
            (Some("view"), None) => Err(ApiError::bad_view()),
            (Some("action"), Some(_)) => Err(ApiError::bad_action()),
            (Some("view"), Some(_)) => Err(ApiError::bad_view()),
            _ => Err(ApiError::bad_type()),
        };
        msg.response = Some(match outcome {
            Ok(body) => json_response(StatusCode::OK, body),
            Err(err) => err.response(),
        });
        true
    }

    pub fn wait(&self, id: i32, timeout: Duration) -> bool {
        self.engine.wait(id, timeout)
    }

    fn scan(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let url = params.get("url").map(String::as_str).unwrap_or("").trim();
        if url.is_empty() {
            return Err(ApiError::missing_parameter());
        }
        let uri: Uri = url.parse().map_err(|_| ApiError::illegal_parameter())?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.host().is_none() {
            return Err(ApiError::illegal_parameter());
        }
        let method = method_of(params.get("method").map(String::as_str).unwrap_or(""))?;
        let body = params.get("postData").cloned().unwrap_or_default();
        let mut headers = HeaderMap::new();
        if !body.is_empty() {
            if let Ok(length) = HeaderValue::from_str(&body.len().to_string()) {
                headers.insert(http::header::CONTENT_LENGTH, length);
            }
        }
        let seed = HttpMessage {
            method,
            uri,
            headers,
            body: Bytes::from(body.into_bytes()),
            response: None,
        };
        let mut options = ScanOptions::default();
        if let Some(recurse) = params.get("recurse") {
            options.recurse = !recurse.eq_ignore_ascii_case("false");
        }
        let id = self.engine.start(seed, options);
        Ok(json!({ "scan": id.to_string() }))
    }

    fn stop(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let id = self.scan_id(params)?;
        if !self.engine.stop(id) {
            return Err(ApiError::does_not_exist());
        }
        Ok(json!({ "Result": "OK" }))
    }

    fn status(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let id = self.scan_id(params)?;
        let progress = self
            .engine
            .status(id)
            .ok_or_else(ApiError::does_not_exist)?;
        Ok(json!({ "status": progress.to_string() }))
    }

    fn scan_id(&self, params: &HashMap<String, String>) -> Result<i32, ApiError> {
        match params.get("scanId").map(String::as_str) {
            None | Some("") => self.engine.last_id().ok_or_else(ApiError::does_not_exist),
            Some(value) => value
                .parse::<i32>()
                .map_err(|_| ApiError::illegal_parameter()),
        }
    }
}

fn method_of(value: &str) -> Result<Method, ApiError> {
    if value.is_empty() {
        return Ok(Method::GET);
    }
    Method::from_bytes(value.as_bytes()).map_err(|_| ApiError::illegal_parameter())
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

fn is_zap_host(uri: &Uri) -> bool {
    matches!(uri.scheme_str(), Some("http" | "https"))
        && uri
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case("zap"))
}

fn params_of(msg: &HttpMessage) -> HashMap<String, String> {
    form_pairs(msg.uri.query().unwrap_or(""))
        .into_iter()
        .collect()
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
