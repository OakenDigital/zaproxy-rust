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
            "GET http://zap/JSON/core/view/urls/",
            "GET http://zap/JSON/core/view/alerts/",
            "GET http://zap/JSON/core/view/message/?id=",
            "GET http://zap/JSON/core/view/numberOfMessages/",
            "GET http://zap/JSON/core/action/shutdown/",
            "GET http://zap/JSON/alert/view/alerts/",
            "GET http://zap/JSON/alert/view/alert/?id=",
            "GET http://zap/JSON/pscan/view/scanners/",
            "GET http://zap/JSON/pscan/view/recordsToScan/",
            "GET http://zap/JSON/pscan/action/disableAllTags/",
            "GET http://zap/JSON/pscan/action/setMaxAlertsPerRule/?maxAlerts=",
            "GET http://zap/JSON/ascan/view/scanners/",
            "GET http://zap/JSON/ascan/view/scanProgress/",
            "GET http://zap/JSON/ascan/action/enableAllScanners/",
            "GET http://zap/JSON/ascan/action/setScannerAlertThreshold/?id=&alertThreshold=",
            "GET http://zap/JSON/ascan/action/scanAsUser/",
            "GET http://zap/JSON/context/view/contextList/",
            "GET http://zap/JSON/context/action/importContext/?contextFile=",
            "GET http://zap/JSON/users/view/usersList/",
            "GET http://zap/JSON/script/view/listEngines/",
            "GET http://zap/JSON/script/action/load/",
            "GET http://zap/JSON/script/action/enable/",
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
            name: String::new(),
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
            name: String::new(),
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
            name: String::new(),
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

    let (status, body) = call(&api, "http://zap/JSON/ajaxSpider/view/status/");
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

#[test]
fn core_urls_are_plain_strings_and_core_alerts_are_objects() {
    let (api, _, session) = open();
    exchange(&session, "http://127.0.0.1:9/one", b"one", "text/html");
    exchange(&session, "http://127.0.0.1:9/two", b"two", "text/html");
    exchange(&session, "http://127.0.0.1:9/one", b"again", "text/html");
    session
        .insert_alert(&NewAlert {
            plugin_id: 10021,
            name: String::new(),
            risk: Risk::Low.code(),
            confidence: Confidence::Medium.code(),
            cwe_id: 693,
            wasc_id: 15,
            param: "x-content-type-options".to_string(),
            url: "http://127.0.0.1:9/one".to_string(),
        })
        .unwrap();

    let (status, urls) = call(&api, "http://zap/JSON/core/view/urls/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        urls["urls"],
        serde_json::json!(["http://127.0.0.1:9/one", "http://127.0.0.1:9/two"])
    );
    assert!(urls["urls"][0].is_string());

    let (status, objects) = call(&api, "http://zap/JSON/core/view/alerts/");
    assert_eq!(status, StatusCode::OK);
    let alerts = objects["alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].is_object());
    assert_eq!(alerts[0]["pluginId"], "10021");
    assert_eq!(alerts[0]["risk"], "Low");
    assert_eq!(alerts[0]["url"], "http://127.0.0.1:9/one");

    let (status, strings) = call(&api, "http://zap/JSON/alert/view/alerts/");
    assert_eq!(status, StatusCode::OK);
    assert!(strings["alerts"][0].is_string());
}

#[test]
fn core_message_and_number_of_messages_match_history() {
    let (api, _, session) = open();
    exchange(
        &session,
        "http://127.0.0.1:9/hello",
        b"hello-body",
        "text/plain",
    );
    exchange(&session, "http://127.0.0.1:9/pic", b"png", "image/png");
    exchange(
        &session,
        "https://example.test/a",
        b"example-body",
        "text/plain",
    );

    let (status, count) = call(&api, "http://zap/JSON/core/view/numberOfMessages/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count["numberOfMessages"], "2");
    assert!(count["numberOfMessages"].is_string());

    let (status, filtered) = call(
        &api,
        "http://zap/JSON/core/view/numberOfMessages/?baseurl=https://example.test",
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(filtered["numberOfMessages"], "1");

    let (status, message) = call(&api, "http://zap/JSON/core/view/message/?id=1");
    assert_eq!(status, StatusCode::OK);
    assert!(message["message"].is_object());
    assert_keys(&message["message"], MESSAGE_KEYS);
    assert_eq!(message["message"]["id"], "1");
    assert!(message["message"]["responseHeader"]
        .as_str()
        .unwrap()
        .contains("HTTP/1.1 200"));
    assert!(message["message"]["tags"].is_array());

    let (status, image) = call(&api, "http://zap/JSON/core/view/message/?id=2");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(image["message"]["id"], "2");

    let (status, missing) = call(&api, "http://zap/JSON/core/view/message/");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing["code"], "missing_parameter");

    let (status, absent) = call(&api, "http://zap/JSON/core/view/message/?id=99");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(absent["code"], "does_not_exist");
}

#[test]
fn pscan_routes_list_the_ported_rule_and_an_empty_queue() {
    let (api, _, _) = open();
    let (status, scanners) = call(&api, "http://zap/JSON/pscan/view/scanners/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(scanners["scanners"].as_array().unwrap().len(), 1);
    assert_eq!(
        scanners["scanners"][0],
        serde_json::json!({
            "alertThreshold": "DEFAULT",
            "enabled": "true",
            "id": "10021",
            "name": "X-Content-Type-Options Header Missing",
            "quality": "release",
            "status": "release",
        })
    );

    let (status, pending) = call(&api, "http://zap/JSON/pscan/view/recordsToScan/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pending["recordsToScan"], "0");

    let (status, tags) = call(&api, "http://zap/JSON/pscan/action/disableAllTags/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tags, serde_json::json!({"Result": "OK"}));

    let (status, limit) = call(
        &api,
        "http://zap/JSON/pscan/action/setMaxAlertsPerRule/?maxAlerts=10",
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(limit["Result"], "OK");

    let (status, missing) = call(&api, "http://zap/JSON/pscan/action/setMaxAlertsPerRule/");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing["code"], "missing_parameter");

    let (status, bad) = call(
        &api,
        "http://zap/JSON/pscan/action/setMaxAlertsPerRule/?maxAlerts=nope",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(bad["code"], "illegal_parameter");
}

#[test]
fn ascan_scanner_routes_cover_the_two_ported_rules() {
    let (api, _, session) = open();
    exchange(&session, "https://fixture.test/item", b"ok", "text/plain");

    let (status, scanners) = call(
        &api,
        "http://zap/JSON/ascan/view/scanners/?scanPolicyName=Default%20Policy",
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        scanners["scanners"],
        serde_json::json!([
            {
                "alertThreshold": "DEFAULT",
                "allDependenciesAvailable": "true",
                "attackStrength": "DEFAULT",
                "cweId": "113",
                "dependencies": [],
                "enabled": "true",
                "id": "40003",
                "name": "CRLF Injection",
                "policyId": "4",
                "quality": "release",
                "status": "release",
                "wascId": "25",
            },
            {
                "alertThreshold": "DEFAULT",
                "allDependenciesAvailable": "true",
                "attackStrength": "DEFAULT",
                "cweId": "643",
                "dependencies": [],
                "enabled": "true",
                "id": "90021",
                "name": "XPath Injection",
                "policyId": "4",
                "quality": "release",
                "status": "release",
                "wascId": "39",
            }
        ])
    );

    let (status, injection) = call(&api, "http://zap/JSON/ascan/view/scanners/?policyId=4");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(injection["scanners"].as_array().unwrap().len(), 2);

    let (status, other) = call(&api, "http://zap/JSON/ascan/view/scanners/?policyId=0");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(other["scanners"].as_array().unwrap().len(), 0);

    let (status, unknown_category) = call(&api, "http://zap/JSON/ascan/view/scanners/?policyId=9");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown_category["code"], "does_not_exist");

    let (status, missing_policy) = call(
        &api,
        "http://zap/JSON/ascan/view/scanners/?scanPolicyName=Other",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_policy["code"], "does_not_exist");

    let (status, off) = call(
        &api,
        "http://zap/JSON/ascan/action/setScannerAlertThreshold/?id=40003&alertThreshold=OFF",
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(off["Result"], "OK");
    let (_, after_off) = call(&api, "http://zap/JSON/ascan/view/scanners/");
    assert_eq!(after_off["scanners"][0]["alertThreshold"], "OFF");
    assert_eq!(after_off["scanners"][0]["enabled"], "false");
    assert_eq!(after_off["scanners"][1]["enabled"], "true");

    let (status, enabled) = call(&api, "http://zap/JSON/ascan/action/enableAllScanners/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(enabled["Result"], "OK");
    let (_, after_enable) = call(&api, "http://zap/JSON/ascan/view/scanners/");
    assert_eq!(after_enable["scanners"][0]["enabled"], "true");
    assert_eq!(after_enable["scanners"][0]["alertThreshold"], "OFF");

    let (status, _medium) = call(
        &api,
        "http://zap/JSON/ascan/action/setScannerAlertThreshold/?id=90021&alertThreshold=medium",
    );
    assert_eq!(status, StatusCode::OK);
    let (_, after_medium) = call(&api, "http://zap/JSON/ascan/view/scanners/");
    assert_eq!(after_medium["scanners"][1]["alertThreshold"], "MEDIUM");

    let (status, unknown_rule) = call(
        &api,
        "http://zap/JSON/ascan/action/setScannerAlertThreshold/?id=1&alertThreshold=LOW",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown_rule["code"], "does_not_exist");

    let (status, insane) = call(
        &api,
        "http://zap/JSON/ascan/action/setScannerAlertThreshold/?id=40003&alertThreshold=INSANE",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(insane["code"], "does_not_exist");

    let (status, progress) = call(&api, "http://zap/JSON/ascan/view/scanProgress/");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(progress["code"], "does_not_exist");
    let (status, progress_id) = call(&api, "http://zap/JSON/ascan/view/scanProgress/?scanId=1");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(progress_id["code"], "does_not_exist");

    let (status, not_in_context) = call(
        &api,
        "http://zap/JSON/ascan/action/scanAsUser/?contextId=1&userId=7&url=https://fixture.test/item",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(not_in_context["code"], "does_not_exist");

    let (status, missing_user) = call(
        &api,
        "http://zap/JSON/ascan/action/scanAsUser/?url=https://fixture.test/item",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_user["code"], "missing_parameter");
}

#[test]
fn context_import_lists_the_context_and_its_user() {
    let (api, _, session) = open();
    let path = std::env::temp_dir().join(format!(
        "zap-api-packaged-{}-{}.context",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(
        &path,
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<configuration>
    <context>
        <name>packaged</name>
        <incregexes>https://fixture\.test/.*</incregexes>
        <users>
            <user>7;true;YWxpY2U=;2;YWxpY2U=~c2VjcmV0~</user>
        </users>
    </context>
</configuration>
"#,
    )
    .unwrap();

    let (status, empty) = call(&api, "http://zap/JSON/context/view/contextList/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(empty["contextList"], serde_json::json!([]));

    let (status, imported) = call(
        &api,
        &format!(
            "http://zap/JSON/context/action/importContext/?contextFile={}",
            path.display()
        ),
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(imported, serde_json::json!({"contextId": "1"}));

    let (status, names) = call(&api, "http://zap/JSON/context/view/contextList/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names["contextList"], serde_json::json!(["packaged"]));
    assert!(names["contextList"][0].is_string());

    let (status, duplicate) = call(
        &api,
        &format!(
            "http://zap/JSON/context/action/importContext/?contextFile={}",
            path.display()
        ),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(duplicate["code"], "bad_external_data");

    let (status, missing_file) = call(
        &api,
        "http://zap/JSON/context/action/importContext/?contextFile=/no/such.context",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_file["code"], "does_not_exist");

    let (status, users) = call(&api, "http://zap/JSON/users/view/usersList/?contextId=1");
    assert_eq!(status, StatusCode::OK);
    let user = &users["usersList"][0];
    assert_eq!(user["name"], "alice");
    assert_eq!(user["id"], "7");
    assert_eq!(user["contextId"], "1");
    assert_eq!(user["enabled"], "true");
    let credentials: Value = serde_json::from_str(user["credentials"].as_str().unwrap()).unwrap();
    assert_eq!(
        credentials["type"],
        "UsernamePasswordAuthenticationCredentials"
    );
    assert_eq!(credentials["username"], "alice");
    assert_eq!(credentials["password"], "secret");

    let (status, all_users) = call(&api, "http://zap/JSON/users/view/usersList/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(all_users["usersList"].as_array().unwrap().len(), 1);

    let (status, unknown_context) = call(&api, "http://zap/JSON/users/view/usersList/?contextId=9");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown_context["code"], "does_not_exist");

    let (status, outside) = call(
        &api,
        "http://zap/JSON/ascan/action/scanAsUser/?contextId=1&userId=7&url=https://other.test/",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(outside["code"], "url_not_in_context");

    let (status, not_in_tree) = call(
        &api,
        "http://zap/JSON/ascan/action/scanAsUser/?contextId=1&userId=7&url=https://fixture.test/missing",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(not_in_tree["code"], "url_not_found");

    let (status, unknown_user) = call(
        &api,
        "http://zap/JSON/ascan/action/scanAsUser/?contextId=1&userId=8&url=https://fixture.test/missing",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown_user["code"], "user_not_found");

    exchange(&session, "https://fixture.test/item", b"ok", "text/plain");
    let (status, would_start) = call(
        &api,
        "http://zap/JSON/ascan/action/scanAsUser/?contextId=1&userId=7&url=https://fixture.test/item",
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(would_start["code"], "internal_error");
    assert!(would_start.get("scan").is_none());
    let _ = std::fs::remove_file(path);
}

#[test]
fn script_engine_list_load_and_enable() {
    let (api, _, _) = open();
    let (status, engines) = call(&api, "http://zap/JSON/script/view/listEngines/");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        engines["listEngines"],
        serde_json::json!(["ECMAScript : Boa"])
    );
    let listed = engines["listEngines"][0].as_str().unwrap();
    assert_eq!(listed.split(" : ").nth(1), Some("Boa"));

    let path = std::env::temp_dir().join(format!("zap-api-script-{}-hook.js", std::process::id()));
    std::fs::write(
        &path,
        "function sendingRequest(msg, initiator, helper) {}\n",
    )
    .unwrap();

    let load = format!(
        "http://zap/JSON/script/action/load/?scriptName=hook.js&scriptType=httpsender&scriptEngine=Boa&fileName={}",
        path.display()
    );
    let (status, loaded) = call(&api, &load);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(loaded["Result"], "OK");

    let (status, duplicate) = call(&api, &load);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(duplicate["code"], "already_exists");

    let (status, nashorn) = call(
        &api,
        &format!(
            "http://zap/JSON/script/action/load/?scriptName=other.js&scriptType=httpsender&scriptEngine=Oracle%20Nashorn&fileName={}",
            path.display()
        ),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(nashorn["code"], "does_not_exist");

    let (status, missing_file) = call(
        &api,
        "http://zap/JSON/script/action/load/?scriptName=gone.js&scriptType=httpsender&scriptEngine=Boa&fileName=/no/such.js",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_file["code"], "does_not_exist");

    let (status, bad_charset) = call(
        &api,
        &format!(
            "http://zap/JSON/script/action/load/?scriptName=charset.js&scriptType=httpsender&scriptEngine=ECMAScript%20:%20Boa&fileName={}&charset=not-a-charset",
            path.display()
        ),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_charset["code"], "illegal_parameter");

    let standalone = format!(
        "http://zap/JSON/script/action/load/?scriptName=once.js&scriptType=standalone&scriptEngine=Boa&fileName={}",
        path.display()
    );
    let (status, _) = call(&api, &standalone);
    assert_eq!(status, StatusCode::OK);
    let (status, not_enableable) = call(
        &api,
        "http://zap/JSON/script/action/enable/?scriptName=once.js",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(not_enableable["code"], "illegal_parameter");

    let (status, enabled) = call(
        &api,
        "http://zap/JSON/script/action/enable/?scriptName=hook.js",
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(enabled["Result"], "OK");

    let (status, unknown) = call(
        &api,
        "http://zap/JSON/script/action/enable/?scriptName=missing.js",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown["code"], "does_not_exist");

    let _ = std::fs::remove_file(path);
}
