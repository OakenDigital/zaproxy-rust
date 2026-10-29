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

//! META-ENGINE controls for features that already exist.
//!
//! `zapd` can start a traditional spider seed, start an AJAX spider seed
//! (HTML links and inline script string literals; a browser runtime is not
//! included), load a JavaScript file into the Boa `proxy` and `httpsender`
//! host, and load a ZAP context file so form or JSON login plus send-as-user
//! can run. `AlertOnHttpResponseCodeErrors.js` still does not run.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};
use zap_auth::{Context, User};
use zap_core::{HttpMessage, HttpResponse};
use zap_http::UpstreamClient;
use zap_proxy::EarlyOverride;
use zap_script::{ScriptHost, ScriptType, ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP};

use crate::phase11::PackagedScan;

/// Shared spider, script, and context controls.
pub struct EngineControls {
    scripts: Arc<ScriptHost>,
    packaged: Arc<PackagedScan>,
    context: Mutex<Option<Context>>,
    user_name: Mutex<String>,
    username: Mutex<String>,
    password: Mutex<String>,
}

impl EngineControls {
    pub fn new(scripts: Arc<ScriptHost>, packaged: Arc<PackagedScan>) -> Arc<Self> {
        Arc::new(Self {
            scripts,
            packaged,
            context: Mutex::new(None),
            user_name: Mutex::new("user".to_string()),
            username: Mutex::new(String::new()),
            password: Mutex::new(String::new()),
        })
    }

    /// Load `path` as `proxy` and `httpsender`, unless `kind` selects one.
    pub fn load_script_file(&self, path: &Path, kind: Option<ScriptType>) -> Result<(), String> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("script")
            .to_string();
        if name.contains("AlertOnHttpResponseCodeErrors") {
            return Err(ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP.to_string());
        }
        let source = std::fs::read_to_string(path).map_err(|err| format!("{path:?}: {err}"))?;
        self.load_script_source(&name, &source, kind)
    }

    pub fn load_script_source(
        &self,
        name: &str,
        source: &str,
        kind: Option<ScriptType>,
    ) -> Result<(), String> {
        if name.contains("AlertOnHttpResponseCodeErrors") {
            return Err(ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP.to_string());
        }
        let kinds = match kind {
            Some(kind) => vec![kind],
            None => vec![ScriptType::Proxy, ScriptType::HttpSender],
        };
        for kind in kinds {
            self.scripts
                .add_script(name, kind, source)
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    pub fn import_context_xml(&self, xml: &str) -> Result<(), String> {
        let context = Context::from_zap_config(xml).map_err(|err| err.to_string())?;
        self.packaged.set_context(Some(context.clone()));
        if let Ok(mut slot) = self.context.lock() {
            *slot = Some(context);
        }
        Ok(())
    }

    pub fn import_context_file(&self, path: &Path) -> Result<(), String> {
        let xml = std::fs::read_to_string(path).map_err(|err| format!("{path:?}: {err}"))?;
        self.import_context_xml(&xml)
    }

    pub fn set_user(&self, name: &str, username: &str, password: &str) {
        if let Ok(mut slot) = self.user_name.lock() {
            *slot = name.to_string();
        }
        if let Ok(mut slot) = self.username.lock() {
            *slot = username.to_string();
        }
        if let Ok(mut slot) = self.password.lock() {
            *slot = password.to_string();
        }
    }

    pub fn start_spider(&self, url: &str) -> Result<u64, String> {
        self.packaged.start_seed(url)
    }

    /// Context loaded by `-context`, if any.
    pub fn context(&self) -> Option<Context> {
        self.context.lock().ok().and_then(|guard| guard.clone())
    }

    /// Form or JSON login from the loaded context, then the follow-up request.
    pub async fn send_follow_up(&self, url: &str) -> Result<HttpResponse, String> {
        let context = self
            .context
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or_else(|| "no context loaded".to_string())?;
        let name = self
            .user_name
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_else(|_| "user".to_string());
        let username = self
            .username
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default();
        let password = self
            .password
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default();
        let mut user = User::from_context(&context, &name, &username, &password)
            .map_err(|err| err.to_string())?;
        let client = UpstreamClient::new(&[]).map_err(|err| err.to_string())?;
        let mut message = HttpMessage {
            method: Method::GET,
            uri: url
                .parse()
                .map_err(|err: http::uri::InvalidUri| err.to_string())?,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: None,
        };
        client
            .send_as_user(&mut message, &mut user)
            .await
            .map_err(|err| err.to_string())
    }

    /// Same follow-up, from the daemon thread that is already on a runtime.
    pub fn send_follow_up_blocking(&self, url: &str) -> Result<HttpResponse, String> {
        let url = url.to_string();
        let context = self
            .context
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or_else(|| "no context loaded".to_string())?;
        let name = self
            .user_name
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_else(|_| "user".to_string());
        let username = self
            .username
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default();
        let password = self
            .password
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default();
        let run = move || {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                let mut user = User::from_context(&context, &name, &username, &password)
                    .map_err(|err| err.to_string())?;
                let client = UpstreamClient::new(&[]).map_err(|err| err.to_string())?;
                let mut message = HttpMessage {
                    method: Method::GET,
                    uri: url
                        .parse()
                        .map_err(|err: http::uri::InvalidUri| err.to_string())?,
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                    response: None,
                };
                client
                    .send_as_user(&mut message, &mut user)
                    .await
                    .map_err(|err| err.to_string())
            })
        };
        let joined = if tokio::runtime::Handle::try_current().is_ok() {
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| {
                std::thread::spawn(move || {
                    let _entered = handle.enter();
                    run()
                })
                .join()
            })
        } else {
            std::thread::spawn(run).join()
        };
        match joined {
            Ok(result) => result,
            Err(_) => Err("send-as-user thread panicked".to_string()),
        }
    }

    /// `script` and `context` routes. Spider routes stay on the packaged scan.
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
            ("script", Some("action"), Some("load")) => self.script_load(&params_of(msg)),
            ("script", Some("view"), Some("listScripts")) => Ok(self.script_list()),
            ("context", Some("action"), Some("importContext")) => {
                self.import_action(&params_of(msg))
            }
            ("context", Some("action"), Some("setUser")) => self.set_user_action(&params_of(msg)),
            ("context", Some("action"), Some("sendAsUser")) => self.send_action(&params_of(msg)),
            ("script" | "context", _, _) => Err(unknown(kind)),
            _ => return false,
        };
        msg.response = Some(match outcome {
            Ok(body) => json_response(StatusCode::OK, body),
            Err(err) => err.response(),
        });
        true
    }

    fn script_load(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let file = params
            .get("fileName")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(ApiError::missing_parameter)?;
        let kind = match params.get("scriptType").map(String::as_str) {
            None | Some("") | Some("both") => None,
            Some("proxy") => Some(ScriptType::Proxy),
            Some("httpsender") => Some(ScriptType::HttpSender),
            Some(_) => return Err(ApiError::illegal_parameter()),
        };
        self.load_script_file(Path::new(file), kind)
            .map_err(ApiError::bad_script)?;
        Ok(json!({ "Result": "OK" }))
    }

    fn script_list(&self) -> Value {
        json!({ "scripts": [] })
    }

    fn import_action(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let file = params
            .get("contextFile")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(ApiError::missing_parameter)?;
        self.import_context_file(Path::new(file))
            .map_err(ApiError::bad_context)?;
        Ok(json!({ "Result": "OK" }))
    }

    fn set_user_action(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let username = params
            .get("username")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(ApiError::missing_parameter)?;
        let password = params.get("password").map(String::as_str).unwrap_or("");
        let name = params
            .get("userName")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(username);
        self.set_user(name, username, password);
        Ok(json!({ "Result": "OK" }))
    }

    fn send_action(&self, params: &HashMap<String, String>) -> Result<Value, ApiError> {
        let url = params
            .get("url")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(ApiError::missing_parameter)?;
        if let Some(username) = params
            .get("username")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
        {
            let name = params
                .get("userName")
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(username);
            let password = params.get("password").map(String::as_str).unwrap_or("");
            self.set_user(name, username, password);
        }
        let response = self
            .send_follow_up_blocking(url)
            .map_err(ApiError::bad_context)?;
        Ok(json!({
            "sendAsUser": response.status.as_u16().to_string(),
            "body": String::from_utf8_lossy(&response.body),
        }))
    }
}

/// Answer script and context routes, then the previous override.
pub fn chain(inner: EarlyOverride, controls: Arc<EngineControls>) -> EarlyOverride {
    Arc::new(move |message| {
        if controls.handle(message) {
            return true;
        }
        inner(message)
    })
}

pub fn startup_line() -> &'static str {
    "Engine controls: -spider seed, -ajaxspider seed (HTML and inline script literals; no browser runtime), -script file (proxy and httpsender), -context file, -send-as-user URL"
}

fn unknown(kind: Option<&str>) -> ApiError {
    match kind {
        Some("view") => ApiError::bad_view(),
        Some("action") => ApiError::bad_action(),
        _ => ApiError::bad_type(),
    }
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
    message: String,
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

    fn bad_script(message: String) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_script", message)
    }

    fn bad_context(message: String) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_external_data", message)
    }

    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http::{HeaderMap, Method, StatusCode};
    use zap_core::{HttpMessage, HttpResponse, ProxyListener};
    use zap_script::ScriptProxyListener;
    use zap_store::Session;

    use super::EngineControls;
    use crate::phase11;

    fn temp_db() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zapd-controls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path.join("session.sqlite")
    }

    fn rewrite_script() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../zap-script/scripts/rewrite-headers.js")
    }

    #[tokio::test]
    async fn loaded_rewrite_script_sets_request_and_response_headers() {
        let session = Arc::new(Session::open(temp_db()).unwrap());
        let (packaged, _) = phase11::start(Arc::clone(&session), Vec::new()).expect("runtime");
        let host = Arc::new(zap_script::ScriptHost::new());
        let controls = EngineControls::new(Arc::clone(&host), packaged);
        controls.load_script_file(&rewrite_script(), None).unwrap();
        let listener = ScriptProxyListener::new(host);
        let mut message = HttpMessage {
            method: Method::GET,
            uri: "http://example.test/page".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: Some(HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"ok"),
            }),
        };
        assert!(listener.on_http_request_send(&mut message));
        assert_eq!(
            message
                .headers
                .get("x-script-request")
                .and_then(|value| value.to_str().ok()),
            Some("rewritten")
        );
        assert_eq!(
            message
                .headers
                .get("x-sender-request")
                .and_then(|value| value.to_str().ok()),
            Some("rewritten")
        );
        assert!(listener.on_http_response_receive(&mut message));
        let response = message.response.unwrap();
        assert_eq!(
            response
                .headers
                .get("x-script-response")
                .and_then(|value| value.to_str().ok()),
            Some("rewritten")
        );
        assert_eq!(
            response
                .headers
                .get("x-sender-response")
                .and_then(|value| value.to_str().ok()),
            Some("rewritten")
        );

        let gap = controls.load_script_file(
            PathBuf::from("AlertOnHttpResponseCodeErrors.js").as_path(),
            None,
        );
        let gap = gap.expect_err("docker alert script stays unloaded");
        assert!(gap.contains("Java.type"), "{gap}");
    }

    #[tokio::test]
    async fn spider_seed_leaves_out_of_context_urls_unfetched() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = answer(stream);
            }
        });
        let origin = format!("http://127.0.0.1:{port}");
        let xml = format!(
            "<configuration><context><name>seed</name>\
             <incregexes>{origin}/.*</incregexes>\
             <excregexes>{origin}/secret.*</excregexes>\
             </context></configuration>"
        );
        let session = Arc::new(Session::open(temp_db()).unwrap());
        let (packaged, _) = phase11::start(Arc::clone(&session), Vec::new()).unwrap();
        let controls = EngineControls::new(Arc::new(zap_script::ScriptHost::new()), packaged);
        controls.import_context_xml(&xml).unwrap();
        let id = controls.start_spider(&format!("{origin}/app/")).unwrap();
        let started = Instant::now();
        while !controls.packaged.scan_done(id) {
            if started.elapsed() > Duration::from_secs(8) {
                let urls: Vec<String> = session
                    .history_rows()
                    .unwrap()
                    .into_iter()
                    .map(|row| row.url)
                    .collect();
                panic!("spider seed did not finish; history={urls:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let urls: Vec<String> = session
            .history_rows()
            .unwrap()
            .into_iter()
            .map(|row| row.url)
            .collect();
        assert!(
            urls.iter().any(|url| url.contains("/app/page")),
            "fetched {urls:?}"
        );
        assert!(
            urls.iter().all(|url| !url.contains("/secret")),
            "secret was fetched: {urls:?}"
        );
        assert!(
            urls.iter().all(|url| !url.contains("example.test")),
            "other host was fetched: {urls:?}"
        );
    }

    fn answer(mut stream: std::net::TcpStream) -> std::io::Result<()> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = Vec::new();
        let mut tmp = [0_u8; 1024];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let req = String::from_utf8_lossy(&buf);
        let target = req.split_whitespace().nth(1).unwrap_or("/");
        let path = target.split('?').next().unwrap_or("/");
        let body = if path.starts_with("/app") {
            "<html><body><a href=\"/app/page\">page</a><a href=\"/secret\">no</a><a href=\"http://example.test/out\">out</a></body></html>"
        } else {
            "ok"
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()
    }

    #[tokio::test]
    async fn context_file_form_and_json_login_authenticate_the_follow_up() {
        form_follow_up().await;
        json_follow_up().await;
    }

    async fn form_follow_up() {
        let (origin, seen) =
            auth_app("session=form-ok", "username=alice&password=s3cret-form").await;
        let xml = format!(
            "<configuration><context><name>form</name>\
             <authentication><type>2</type><form>\
             <loginurl>{origin}/login</loginurl>\
             <loginbody>username={{%username%}}&amp;password={{%password%}}</loginbody>\
             </form></authentication>\
             <session><type>0</type></session>\
             </context></configuration>"
        );
        let controls = controls_with_context(&xml, "Ada", "alice", "s3cret-form");
        let response = controls
            .send_follow_up(&format!("{origin}/private"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), b"secret");
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|item| item.contains("username=alice")));
        assert!(seen.iter().any(|item| item.contains("GET")
            && item.contains("/private")
            && item.contains("session=form-ok")));
    }

    async fn json_follow_up() {
        let expected = r#"{"username":"bob","password":"s3cret-json"}"#;
        let (origin, seen) = auth_app("session=json-ok", expected).await;
        let xml = format!(
            "<configuration><context><name>json</name>\
             <authentication><type>5</type><form>\
             <loginurl>{origin}/login</loginurl>\
             <loginbody>{{\"username\":\"{{%username%}}\",\"password\":\"{{%password%}}\"}}</loginbody>\
             </form></authentication>\
             <session><type>0</type></session>\
             </context></configuration>"
        );
        let controls = controls_with_context(&xml, "Bob", "bob", "s3cret-json");
        let response = controls
            .send_follow_up(&format!("{origin}/private"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), b"secret");
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|item| item.contains(expected)));
        assert!(seen
            .iter()
            .any(|item| item.contains("/private") && item.contains("session=json-ok")));
    }

    fn controls_with_context(
        xml: &str,
        name: &str,
        username: &str,
        password: &str,
    ) -> Arc<EngineControls> {
        let session = Arc::new(Session::open(temp_db()).unwrap());
        let (packaged, _) = phase11::start(session, Vec::new()).unwrap();
        let controls = EngineControls::new(Arc::new(zap_script::ScriptHost::new()), packaged);
        controls.import_context_xml(xml).unwrap();
        controls.set_user(name, username, password);
        controls
    }

    async fn auth_app(
        cookie: &'static str,
        expected_body: &'static str,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let request = read_http(&mut socket).await;
                let bytes = if request.contains("POST") && request.contains(expected_body) {
                    http_response(200, "logged-in", cookie)
                } else if request.contains("GET")
                    && request.contains("/private")
                    && request.contains(cookie)
                {
                    http_response(200, "secret", "")
                } else if request.contains("GET") && request.contains("/login") {
                    http_response(200, "login-page", "")
                } else {
                    http_response(401, "anonymous", "")
                };
                log.lock().unwrap().push(request);
                let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, &bytes).await;
            }
        });
        (format!("http://127.0.0.1:{port}"), seen)
    }

    async fn read_http(socket: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut header = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            socket.read_exact(&mut byte).await.unwrap();
            header.push(byte[0]);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&header).into_owned();
        let length = text
            .lines()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .map(|value| value.trim().to_string())
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        if length > 0 {
            socket.read_exact(&mut body).await.unwrap();
        }
        format!("{text}{}", String::from_utf8_lossy(&body))
    }

    fn http_response(status: u16, body: &str, cookie: &str) -> Vec<u8> {
        let set_cookie = if cookie.is_empty() {
            String::new()
        } else {
            format!("Set-Cookie: {cookie}\r\n")
        };
        format!(
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n{set_cookie}Connection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }
}
