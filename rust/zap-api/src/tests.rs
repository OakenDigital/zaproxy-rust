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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::Value;
use zap_core::{HttpMessage, HttpResponse};
use zap_store::{Confidence, NewAlert, Risk, Session, UNKNOWN_CWE_ID, UNKNOWN_WASC_ID};

use crate::{ApiService, ROUTES};

const MESSAGE_KEYS: &[&str] = &[
    "cookieParams",
    "id",
    "note",
    "requestBody",
    "requestHeader",
    "responseBody",
    "responseHeader",
    "rtt",
    "tags",
    "timestamp",
    "type",
];

const ALERT_KEYS: &[&str] = &[
    "alert",
    "alertRef",
    "attack",
    "confidence",
    "cweid",
    "description",
    "evidence",
    "id",
    "inputVector",
    "messageId",
    "method",
    "name",
    "nodeName",
    "other",
    "param",
    "pluginId",
    "reference",
    "risk",
    "solution",
    "sourceMessageId",
    "sourceid",
    "tags",
    "url",
    "wascid",
];

fn temp_db(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-api-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path.join("session.sqlite")
}

fn service(session: Arc<Session>) -> (ApiService, Arc<AtomicBool>) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let api = ApiService::new(
        session,
        "0.1.0",
        Arc::new(move || flag.store(true, Ordering::SeqCst)),
    );
    (api, shutdown)
}

fn open() -> (ApiService, Arc<AtomicBool>, Arc<Session>) {
    let session = Arc::new(Session::open(temp_db("unit")).unwrap());
    let (api, flag) = service(Arc::clone(&session));
    (api, flag, session)
}

fn call(api: &ApiService, url: &str) -> (StatusCode, Value) {
    let mut message = HttpMessage {
        method: Method::GET,
        uri: url.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    };
    assert!(api.handle(&mut message), "host zap should be handled");
    let response = message.response.expect("api response");
    let content_type = response
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    assert_eq!(content_type, Some("application/json; charset=UTF-8"));
    let body = serde_json::from_slice(&response.body).expect("json body");
    (response.status, body)
}

fn exchange(session: &Session, url: &str, body: &'static [u8], content_type: &str) {
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap(),
    );
    session
        .record_exchange(&HttpMessage {
            method: Method::GET,
            uri: url.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: Some(HttpResponse {
                status: StatusCode::OK,
                headers: response_headers,
                body: Bytes::from_static(body),
            }),
        })
        .unwrap();
}

fn assert_keys(value: &Value, expected: &[&str]) {
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, expected);
}

#[test]
fn documented_routes_are_the_phase3_subset() {
    assert_eq!(
        ROUTES,
        &[
            "GET http://zap/JSON/core/view/version/",
            "GET http://zap/JSON/core/view/hosts/",
            "GET http://zap/JSON/core/view/messages/",
            "GET http://zap/JSON/core/action/shutdown/",
            "GET http://zap/JSON/alert/view/alerts/",
            "GET http://zap/JSON/alert/view/alert/?id=",
        ]
    );
}

#[test]
fn version_hosts_and_messages_use_zap_json_keys() {
    let (api, shutdown, session) = open();
    exchange(
        &session,
        "http://127.0.0.1:9/hello",
        b"hello-body",
        "text/plain",
    );
    exchange(
        &session,
        "https://example.test/a",
        b"example-body",
        "text/plain",
    );
    exchange(&session, "http://127.0.0.1:9/pic", b"png", "image/png");

    let (status, version) = call(&api, "http://zap/JSON/core/view/version/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(version, serde_json::json!({"version": "0.1.0"}));

    let (status, hosts) = call(&api, "http://ZAP/JSON/core/view/hosts/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hosts["hosts"].as_array().unwrap(),
        &vec![
            serde_json::json!("127.0.0.1"),
            serde_json::json!("example.test")
        ]
    );

    let (status, messages) = call(&api, "http://zap/JSON/core/view/messages/");
    assert_eq!(status, StatusCode::OK);
    let list = messages["messages"].as_array().unwrap();
    assert_eq!(list.len(), 2, "image responses are omitted");
    let first: Value = serde_json::from_str(list[0].as_str().unwrap()).unwrap();
    assert_keys(&first, MESSAGE_KEYS);
    assert_eq!(first["id"], "1");
    assert_eq!(first["type"], "1");
    assert_eq!(first["rtt"], "0");
    assert_eq!(first["requestBody"], "");
    assert_eq!(first["responseBody"], "hello-body");
    assert!(first["requestHeader"]
        .as_str()
        .unwrap()
        .contains("GET /hello"));
    assert!(first["responseHeader"]
        .as_str()
        .unwrap()
        .starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(first["tags"], serde_json::json!([]));
    assert!(first["timestamp"].as_str().unwrap().parse::<u64>().unwrap() > 0);

    let (status, page) = call(
        &api,
        "http://zap/JSON/core/view/messages/?baseurl=https://example.test&start=1&count=1",
    );
    assert_eq!(status, StatusCode::OK);
    let page = page["messages"].as_array().unwrap();
    assert_eq!(page.len(), 1);
    let only: Value = serde_json::from_str(page[0].as_str().unwrap()).unwrap();
    assert_eq!(only["responseBody"], "example-body");
    assert!(!shutdown.load(Ordering::SeqCst));
}

#[test]
fn alert_list_and_view_round_trip_zap_fields() {
    let (api, _, session) = open();
    session
        .insert_alert(&NewAlert {
            plugin_id: 40012,
            risk: Risk::Medium.code(),
            confidence: Confidence::High.code(),
            cwe_id: 79,
            wasc_id: 8,
            param: "q".to_string(),
            url: "http://example.test/search?q=1".to_string(),
        })
        .unwrap();
    session
        .insert_alert(&NewAlert {
            plugin_id: 0,
            risk: Risk::Informational.code(),
            confidence: Confidence::FalsePositive.code(),
            cwe_id: UNKNOWN_CWE_ID,
            wasc_id: UNKNOWN_WASC_ID,
            param: String::new(),
            url: "http://example.test/fp".to_string(),
        })
        .unwrap();
    session
        .insert_alert(&NewAlert {
            plugin_id: 40018,
            risk: Risk::High.code(),
            confidence: Confidence::UserConfirmed.code(),
            cwe_id: 89,
            wasc_id: 19,
            param: "id".to_string(),
            url: "https://other.test/item".to_string(),
        })
        .unwrap();

    let (status, list) = call(&api, "http://zap/JSON/alert/view/alerts/");
    assert_eq!(status, StatusCode::OK);
    let alerts = list["alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 2, "false positives are omitted by default");
    let first: Value = serde_json::from_str(alerts[0].as_str().unwrap()).unwrap();
    assert_keys(&first, ALERT_KEYS);
    assert_eq!(first["id"], "1");
    assert_eq!(first["pluginId"], "40012");
    assert_eq!(first["alertRef"], "40012");
    assert_eq!(first["risk"], "Medium");
    assert_eq!(first["confidence"], "High");
    assert_eq!(first["cweid"], "79");
    assert_eq!(first["wascid"], "8");
    assert_eq!(first["param"], "q");
    assert_eq!(first["url"], "http://example.test/search?q=1");
    assert_eq!(first["sourceid"], "0");
    assert_eq!(first["messageId"], "0");
    assert_eq!(first["sourceMessageId"], 0);
    assert_eq!(first["tags"], serde_json::json!({}));

    let (status, filtered) = call(
        &api,
        "http://zap/JSON/alert/view/alerts/?baseurl=https://other.test&riskId=3",
    );
    assert_eq!(status, StatusCode::OK);
    let filtered = filtered["alerts"].as_array().unwrap();
    assert_eq!(filtered.len(), 1);
    let high: Value = serde_json::from_str(filtered[0].as_str().unwrap()).unwrap();
    assert_eq!(high["pluginId"], "40018");
    assert_eq!(high["confidence"], "Confirmed");
    assert_eq!(high["cweid"], "89");
    assert_eq!(high["wascid"], "19");
    assert_eq!(high["param"], "id");
    assert_eq!(high["url"], "https://other.test/item");

    let (status, included) = call(
        &api,
        "http://zap/JSON/alert/view/alerts/?falsePositive=true",
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(included["alerts"].as_array().unwrap().len(), 3);

    let (status, one) = call(&api, "http://zap/JSON/alert/view/alert/?id=1");
    assert_eq!(status, StatusCode::OK);
    let inner: Value = serde_json::from_str(one["alert"].as_str().unwrap()).unwrap();
    assert_eq!(inner["pluginId"], "40012");
    assert_eq!(inner["risk"], "Medium");
    assert_eq!(inner["confidence"], "High");
    assert_eq!(inner["cweid"], "79");
    assert_eq!(inner["wascid"], "8");
    assert_eq!(inner["param"], "q");
    assert_eq!(inner["url"], "http://example.test/search?q=1");
    assert_keys(&inner, ALERT_KEYS);

    let (status, missing) = call(&api, "http://zap/JSON/alert/view/alert/");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing["code"], "missing_parameter");
    assert_eq!(missing["message"], "Missing Parameter");

    let (status, absent) = call(&api, "http://zap/JSON/alert/view/alert/?id=99");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(absent["code"], "does_not_exist");
    assert_eq!(absent["message"], "Does Not Exist");
}

#[test]
fn shutdown_invokes_the_hook_and_unknown_routes_are_errors() {
    let (api, shutdown, _) = open();
    let (status, body) = call(&api, "http://zap/JSON/core/action/shutdown/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"Result": "OK"}));
    assert!(shutdown.load(Ordering::SeqCst));

    let (status, body) = call(&api, "http://zap/JSON/core/view/nope/");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "bad_view");
    assert_eq!(body["message"], "Bad View");

    let (status, body) = call(&api, "http://zap/JSON/pscan/view/recordsToScan/");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "no_implementor");

    let (status, body) = call(&api, "http://zap/HTML/core/view/version/");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "bad_format");

    let (status, body) = call(&api, "http://zap/JSON/alert/view/alerts/?riskId=9");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "illegal_parameter");
}

#[test]
fn other_hosts_are_left_for_the_proxy() {
    let (api, shutdown, _) = open();
    let mut message = HttpMessage {
        method: Method::GET,
        uri: "http://example.test/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    };
    assert!(!api.handle(&mut message));
    assert!(message.response.is_none());
    assert!(!shutdown.load(Ordering::SeqCst));
}
