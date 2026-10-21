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

//! Unit tests for proxy hooks, httpsender hooks, and the Docker script gap.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use zap_core::{HttpMessage, HttpResponse, ProxyListener, HISTORY_LISTENER_ORDER};

use crate::{
    ScriptHost, ScriptProxyListener, ScriptType, ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP,
    PROXY_INITIATOR, PROXY_SCRIPT_LISTENER_ORDER, SAMPLE_REWRITE_SCRIPT,
};

const DOCKER_HTTPSENDER_SCRIPT: &str = include_str!("../fixtures/AlertOnHttpResponseCodeErrors.js");

fn message(url: &str) -> HttpMessage {
    let mut headers = HeaderMap::new();
    headers.insert("host", "example.test".parse().unwrap());
    let mut response_headers = HeaderMap::new();
    response_headers.insert("content-type", "text/plain".parse().unwrap());
    HttpMessage {
        method: Method::GET,
        uri: url.parse().unwrap(),
        headers,
        body: Bytes::from_static(b"request"),
        response: Some(HttpResponse {
            status: StatusCode::OK,
            headers: response_headers,
            body: Bytes::from_static(b"response"),
        }),
    }
}

fn request_header(msg: &HttpMessage, name: &str) -> Option<String> {
    msg.headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn response_header(msg: &HttpMessage, name: &str) -> Option<String> {
    msg.response.as_ref().and_then(|response| {
        response
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    })
}

#[test]
fn listener_order_matches_zap_proxy_script_order() {
    assert_eq!(PROXY_SCRIPT_LISTENER_ORDER, HISTORY_LISTENER_ORDER - 2);
    assert_eq!(PROXY_SCRIPT_LISTENER_ORDER, 4998);
    assert_eq!(PROXY_INITIATOR, 1);
    let listener = ScriptProxyListener::new(Arc::new(ScriptHost::new()));
    assert_eq!(ProxyListener::order(&listener), 4998);
}

#[test]
fn sample_proxy_hooks_rewrite_request_and_response_headers() {
    let host = ScriptHost::new();
    host.add_script("rewrite", ScriptType::Proxy, SAMPLE_REWRITE_SCRIPT)
        .unwrap();
    let mut msg = message("http://example.test/out");
    assert!(host.proxy_request(&mut msg));
    assert_eq!(
        request_header(&msg, "x-script-request").as_deref(),
        Some("rewritten")
    );
    assert_eq!(
        request_header(&msg, "host").as_deref(),
        Some("example.test")
    );
    assert!(host.proxy_response(&mut msg));
    assert_eq!(
        response_header(&msg, "x-script-response").as_deref(),
        Some("rewritten")
    );
    assert_eq!(
        response_header(&msg, "content-type").as_deref(),
        Some("text/plain")
    );
    assert_eq!(msg.url(), "http://example.test/out");
}

#[test]
fn sample_httpsender_hooks_rewrite_request_and_response_headers() {
    let host = ScriptHost::new();
    host.add_script("rewrite", ScriptType::HttpSender, SAMPLE_REWRITE_SCRIPT)
        .unwrap();
    let mut msg = message("http://example.test/sender");
    host.sending_request(&mut msg, PROXY_INITIATOR);
    assert_eq!(
        request_header(&msg, "x-sender-request").as_deref(),
        Some("rewritten")
    );
    host.response_received(&mut msg, PROXY_INITIATOR);
    assert_eq!(
        response_header(&msg, "x-sender-response").as_deref(),
        Some("rewritten")
    );
}

#[test]
fn httpsender_hook_sees_proxy_initiator_and_helper() {
    let host = ScriptHost::new();
    host.add_script(
        "init",
        ScriptType::HttpSender,
        r#"
        function sendingRequest(msg, initiator, helper) {
            msg.setRequestHeader("X-Initiator", String(initiator));
            msg.setRequestHeader("X-Helper", typeof helper);
        }
        function responseReceived(msg, initiator, helper) {
            msg.setResponseHeader("X-Initiator", String(initiator));
        }
        "#,
    )
    .unwrap();
    let mut msg = message("http://example.test/init");
    host.sending_request(&mut msg, PROXY_INITIATOR);
    assert_eq!(request_header(&msg, "x-initiator").as_deref(), Some("1"));
    assert_eq!(request_header(&msg, "x-helper").as_deref(), Some("object"));
    host.response_received(&mut msg, PROXY_INITIATOR);
    assert_eq!(response_header(&msg, "x-initiator").as_deref(), Some("1"));
}

#[test]
fn proxy_request_false_stops_later_proxy_scripts() {
    let host = ScriptHost::new();
    host.add_script(
        "stop",
        ScriptType::Proxy,
        r#"
        function proxyRequest(msg) {
            msg.setRequestHeader("X-A", "1");
            return false;
        }
        function proxyResponse(msg) { return true; }
        "#,
    )
    .unwrap();
    host.add_script(
        "later",
        ScriptType::Proxy,
        r#"
        function proxyRequest(msg) {
            msg.setRequestHeader("X-B", "2");
            return true;
        }
        function proxyResponse(msg) { return true; }
        "#,
    )
    .unwrap();
    let mut msg = message("http://example.test/stop");
    assert!(!host.proxy_request(&mut msg));
    assert_eq!(request_header(&msg, "x-a").as_deref(), Some("1"));
    assert_eq!(request_header(&msg, "x-b"), None);
}

#[test]
fn proxy_request_false_skips_httpsender_on_the_listener() {
    let host = Arc::new(ScriptHost::new());
    host.add_script(
        "stop",
        ScriptType::Proxy,
        "function proxyRequest(msg) { return false; } function proxyResponse(msg) { return true; }",
    )
    .unwrap();
    host.add_script(
        "sender",
        ScriptType::HttpSender,
        r#"
        function sendingRequest(msg, initiator, helper) {
            msg.setRequestHeader("X-Sender-Request", "should-not");
        }
        function responseReceived(msg, initiator, helper) {}
        "#,
    )
    .unwrap();
    let listener = ScriptProxyListener::new(Arc::clone(&host));
    let mut msg = message("http://example.test/drop");
    assert!(!listener.on_http_request_send(&mut msg));
    assert_eq!(request_header(&msg, "x-sender-request"), None);
}

#[test]
fn throwing_proxy_script_does_not_drop_the_request() {
    let host = ScriptHost::new();
    host.add_script(
        "boom",
        ScriptType::Proxy,
        "function proxyRequest(msg) { throw new Error('boom'); } function proxyResponse(msg) { return true; }",
    )
    .unwrap();
    host.add_script(
        "next",
        ScriptType::Proxy,
        r#"
        function proxyRequest(msg) {
            msg.setRequestHeader("X-Next", "yes");
            return true;
        }
        function proxyResponse(msg) { return true; }
        "#,
    )
    .unwrap();
    let mut msg = message("http://example.test/throw");
    assert!(host.proxy_request(&mut msg));
    assert_eq!(request_header(&msg, "x-next").as_deref(), Some("yes"));
}

#[test]
fn disabled_script_does_not_run() {
    let host = ScriptHost::new();
    host.add_script("rewrite", ScriptType::Proxy, SAMPLE_REWRITE_SCRIPT)
        .unwrap();
    host.set_enabled("rewrite", false);
    let mut msg = message("http://example.test/off");
    assert!(host.proxy_request(&mut msg));
    assert_eq!(request_header(&msg, "x-script-request"), None);
}

#[test]
fn set_response_skips_the_need_for_an_origin_body() {
    let host = ScriptHost::new();
    host.add_script(
        "override",
        ScriptType::Proxy,
        r#"
        function proxyRequest(msg) {
            msg.setResponse(201, "from-script");
            return true;
        }
        function proxyResponse(msg) { return true; }
        "#,
    )
    .unwrap();
    let mut msg = message("http://example.test/override");
    msg.response = None;
    assert!(host.proxy_request(&mut msg));
    let response = msg.response.expect("script set a response");
    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.body.as_ref(), b"from-script");
}

#[test]
fn docker_alert_script_fails_on_java_type() {
    assert!(DOCKER_HTTPSENDER_SCRIPT.contains("Java.type(\"java.lang.Integer\")"));
    assert!(DOCKER_HTTPSENDER_SCRIPT.contains("function sendingRequest"));
    assert!(DOCKER_HTTPSENDER_SCRIPT.contains("function responseReceived"));
    assert!(ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP.contains("Java.type"));
    assert!(ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP.contains("java.lang.Integer"));
    assert!(ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP.contains("java.util.regex.Pattern"));
    assert!(
        ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP.contains("org.parosproxy.paros.core.scanner.Alert")
    );
    let err =
        ScriptHost::check_source(DOCKER_HTTPSENDER_SCRIPT).expect_err("script should not run");
    let text = err.message().to_ascii_lowercase();
    assert!(
        text.contains("java"),
        "expected Java.type to fail, got {}",
        err.message()
    );
    let host = ScriptHost::new();
    let installed = host.add_script(
        "AlertOnHttpResponseCodeErrors.js",
        ScriptType::HttpSender,
        DOCKER_HTTPSENDER_SCRIPT,
    );
    assert!(installed.is_err());
}
