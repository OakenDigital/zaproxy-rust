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

//! Unit tests for variants, both rules, strength, threshold, stop, and the API.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use zap_core::{HttpMessage, HttpResponse};
use zap_store::Session;

use crate::coding::{escape_java, form_encode, form_pairs};
use crate::context::{ActivePlugin, ScanContext};
use crate::policy::{AlertThreshold, AttackStrength, Policy};
use crate::variant::{variants_for, VariantKind};
use crate::{
    host_key, ActiveScanService, Engine, RaisedAlert, ScanOptions, ScanSender, CRLF_NAME,
    CRLF_PLUGIN_ID, XPATH_NAME, XPATH_PLUGIN_ID,
};

fn temp_session() -> (std::path::PathBuf, Arc<Session>) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-ascan-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let session = Arc::new(Session::open(path.join("session.sqlite")).unwrap());
    (path, session)
}

fn html(body: &[u8], headers: HeaderMap) -> HttpResponse {
    HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::copy_from_slice(body),
    }
}

fn empty_page() -> HttpResponse {
    html(b"<html><body></body></html>", HeaderMap::new())
}

fn message(method: Method, url: &str, headers: HeaderMap, body: &str) -> HttpMessage {
    HttpMessage {
        method,
        uri: url.parse().expect("url"),
        headers,
        body: Bytes::from(body.to_string()),
        response: Some(empty_page()),
    }
}

fn content_type(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static(value));
    headers
}

fn param_value(msg: &HttpMessage, name: &str) -> Option<String> {
    if let Some(query) = msg.uri.query() {
        if let Some((_, value)) = form_pairs(query).into_iter().find(|(key, _)| key == name) {
            return Some(value);
        }
    }
    let ctype = msg
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = String::from_utf8_lossy(&msg.body);
    if ctype.starts_with("application/x-www-form-urlencoded") {
        return form_pairs(&body)
            .into_iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value);
    }
    if ctype.starts_with("application/json") {
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        return parsed
            .get(name)
            .and_then(|value| value.as_str())
            .map(str::to_string);
    }
    None
}

fn crlf_header(value: &str) -> Option<(String, String)> {
    let mut parts = value.split("\r\n");
    let _first = parts.next()?;
    let line = parts.next()?;
    let (name, header_value) = line.split_once(':')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), header_value.trim().to_string()))
}

struct Fixture {
    crlf: bool,
}

impl ScanSender for Fixture {
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        if self.crlf {
            if let Some(value) = param_value(msg, "years") {
                if let Some((name, header_value)) = crlf_header(&value) {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                        HeaderValue::from_str(&header_value).unwrap(),
                    );
                    return Ok(html(b"<html><body></body></html>", headers));
                }
            }
            return Ok(empty_page());
        }
        let body: &[u8] = if param_value(msg, "query").as_deref() == Some("\"'") {
            b"<html><body>XPathException</body></html>"
        } else {
            b"<html><body></body></html>"
        };
        Ok(html(body, HeaderMap::new()))
    }
}

fn run(
    seed: HttpMessage,
    sender: Arc<dyn ScanSender>,
    options: ScanOptions,
) -> (Vec<RaisedAlert>, usize) {
    let (dir, session) = temp_session();
    let engine = Engine::new(session, sender);
    let id = engine.start(seed, options);
    assert!(engine.wait(id, Duration::from_secs(5)));
    let alerts = engine.alerts(id).unwrap();
    let requests = engine.request_count(id).unwrap();
    let _ = std::fs::remove_dir_all(dir);
    (alerts, requests)
}

fn assert_crlf(alert: &RaisedAlert, param: &str) {
    assert_eq!(alert.plugin_id, 40003);
    assert_eq!(alert.plugin_id, CRLF_PLUGIN_ID);
    assert_eq!(alert.name, "CRLF Injection");
    assert_eq!(alert.name, CRLF_NAME);
    assert_eq!(alert.risk, 2);
    assert_eq!(alert.confidence, 2);
    assert_eq!(alert.cwe_id, 113);
    assert_eq!(alert.wasc_id, 25);
    assert_eq!(alert.param, param);
    assert!(alert.attack.starts_with("any\r\nSet-cookie: Tamper="));
    assert!(alert
        .evidence
        .to_ascii_lowercase()
        .starts_with("\nset-cookie: tamper="));
    assert!(alert.url.contains("years=any%0D%0ASet-cookie%3A+Tamper%3D") || alert.param == param);
}

fn assert_xpath(alert: &RaisedAlert) {
    assert_eq!(alert.plugin_id, 90021);
    assert_eq!(alert.plugin_id, XPATH_PLUGIN_ID);
    assert_eq!(alert.name, "XPath Injection");
    assert_eq!(alert.name, XPATH_NAME);
    assert_eq!(alert.risk, 3);
    assert_eq!(alert.confidence, 3);
    assert_eq!(alert.cwe_id, 643);
    assert_eq!(alert.wasc_id, 39);
    assert_eq!(alert.param, "query");
    assert_eq!(alert.attack, "\"'");
    assert_eq!(alert.evidence, "XPathException");
}

#[test]
fn query_variant_encodes_like_java_url_encoder() {
    let seed = message(
        Method::GET,
        "http://fixture.test/a?years=1&other=ok",
        HeaderMap::new(),
        "",
    );
    let variants = variants_for(&seed);
    assert_eq!(variants.len(), 1);
    assert_eq!(variants[0].kind(), VariantKind::Query);
    assert_eq!(variants[0].params()[0].name, "years");
    let payload = "any\r\nSet-cookie: Tamper=abc";
    let attacked = variants[0].apply(&seed, 0, payload);
    assert_eq!(
        attacked.uri.query().unwrap(),
        "years=any%0D%0ASet-cookie%3A+Tamper%3Dabc&other=ok"
    );
    assert_eq!(form_encode(payload), "any%0D%0ASet-cookie%3A+Tamper%3Dabc");
    assert_eq!(form_encode("\"'"), "%22%27");
    assert_eq!(escape_java("\"'"), "\\\"'");
}

#[test]
fn form_and_json_variants_replace_one_value() {
    let form = message(
        Method::POST,
        "http://fixture.test/form",
        content_type("application/x-www-form-urlencoded"),
        "a=1&b=two words",
    );
    let form_variants = variants_for(&form);
    assert_eq!(form_variants[0].kind(), VariantKind::Form);
    let rewritten = form_variants[0].apply(&form, 1, "x y");
    assert_eq!(rewritten.body.as_ref(), b"a=1&b=x+y");

    let json = message(
        Method::POST,
        "http://fixture.test/json",
        content_type("application/json"),
        "{\"query\":\"xxx\"}",
    );
    let json_variants = variants_for(&json);
    assert_eq!(json_variants[0].kind(), VariantKind::Json);
    assert_eq!(json_variants[0].params()[0].name, "query");
    assert_eq!(json_variants[0].params()[0].value, "xxx");
    let injected = json_variants[0].apply(&json, 0, "\"'");
    assert_eq!(injected.body.as_ref(), b"{\"query\":\"\\\"'\"}");

    let numbers = message(
        Method::POST,
        "http://fixture.test/numbers",
        content_type("application/json"),
        "{ \"a\": 1, \"b\": -2, \"c\": 3.4e5, \"d\": -6E+7, \"e\": 8e-9 }",
    );
    let number_variant = &variants_for(&numbers)[0];
    assert_eq!(number_variant.params()[2].name, "c");
    assert_eq!(number_variant.params()[2].value, "3.4e5");
    let replaced = number_variant.apply(&numbers, 2, "injection");
    assert_eq!(
        replaced.body.as_ref(),
        b"{ \"a\": 1, \"b\": -2, \"c\": \"injection\", \"d\": -6E+7, \"e\": 8e-9 }"
    );

    let broken = message(
        Method::POST,
        "http://fixture.test/bad",
        content_type("application/json"),
        "{\"foo\":\"",
    );
    assert!(variants_for(&broken).is_empty());
}

#[test]
fn golden_query_crlf_matches_zap_plugin_fields() {
    let seed = message(
        Method::GET,
        "http://fixture.test/shouldFindCrLfInjection.php?years=1",
        HeaderMap::new(),
        "",
    );
    let (alerts, _) = run(
        seed,
        Arc::new(Fixture { crlf: true }),
        ScanOptions::default(),
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_crlf(&alerts[0], "years");
    assert!(alerts[0].url.contains(
        "http://fixture.test/shouldFindCrLfInjection.php?years=any%0D%0ASet-cookie%3A+Tamper%3D"
    ));
    assert_eq!(host_key_of(&alerts[0].url), "fixture.test");
}

#[test]
fn golden_query_xpath_matches_zap_plugin_fields() {
    let seed = message(
        Method::GET,
        "http://fixture.test/shouldRaiseAlertIfResponseContainsExpectedErrorForInjectedInput/?query=xxx",
        HeaderMap::new(),
        "",
    );
    let (alerts, _) = run(
        seed,
        Arc::new(Fixture { crlf: false }),
        ScanOptions::default(),
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_xpath(&alerts[0]);
    assert_eq!(
        alerts[0].url,
        "http://fixture.test/shouldRaiseAlertIfResponseContainsExpectedErrorForInjectedInput/?query=%22%27"
    );
}

#[test]
fn golden_form_and_json_raise_the_same_xpath_plugin() {
    let form = message(
        Method::POST,
        "http://fixture.test/xpath-form",
        content_type("application/x-www-form-urlencoded"),
        "query=xxx",
    );
    let (form_alerts, _) = run(
        form,
        Arc::new(Fixture { crlf: false }),
        ScanOptions::default(),
    );
    assert_eq!(form_alerts.len(), 1);
    assert_xpath(&form_alerts[0]);
    assert_eq!(form_alerts[0].url, "http://fixture.test/xpath-form");

    let json = message(
        Method::POST,
        "http://fixture.test/xpath-json",
        content_type("application/json"),
        "{\"query\":\"xxx\"}",
    );
    let (json_alerts, _) = run(
        json,
        Arc::new(Fixture { crlf: false }),
        ScanOptions::default(),
    );
    assert_eq!(json_alerts.len(), 1);
    assert_xpath(&json_alerts[0]);
    assert_eq!(json_alerts[0].url, "http://fixture.test/xpath-json");
}

#[test]
fn golden_form_and_json_raise_crlf_for_the_body_parameter() {
    let form = message(
        Method::POST,
        "http://fixture.test/shouldFindCrLfInjection.php",
        content_type("application/x-www-form-urlencoded"),
        "years=1",
    );
    let (form_alerts, _) = run(
        form,
        Arc::new(Fixture { crlf: true }),
        ScanOptions::default(),
    );
    assert_eq!(form_alerts.len(), 1);
    assert_crlf(&form_alerts[0], "years");
    assert_eq!(
        form_alerts[0].url,
        "http://fixture.test/shouldFindCrLfInjection.php"
    );

    let json = message(
        Method::POST,
        "http://fixture.test/shouldFindCrLfInjection.php",
        content_type("application/json"),
        "{\"years\":\"1\"}",
    );
    let (json_alerts, _) = run(
        json,
        Arc::new(Fixture { crlf: true }),
        ScanOptions::default(),
    );
    assert_eq!(json_alerts.len(), 1);
    assert_crlf(&json_alerts[0], "years");
}

#[test]
fn xpath_does_not_alert_when_the_original_body_already_has_the_error() {
    let mut seed = message(
        Method::GET,
        "http://fixture.test/xpath?query=xxx",
        HeaderMap::new(),
        "",
    );
    seed.response = Some(html(b"<html>XPathException</html>", HeaderMap::new()));
    let (alerts, _) = run(
        seed,
        Arc::new(Fixture { crlf: false }),
        ScanOptions::default(),
    );
    assert!(alerts
        .iter()
        .all(|alert| alert.plugin_id != XPATH_PLUGIN_ID));
}

#[test]
fn threshold_off_raises_nothing_and_sends_no_attacks() {
    let seed = message(
        Method::GET,
        "http://fixture.test/shouldFindCrLfInjection.php?years=1",
        HeaderMap::new(),
        "",
    );
    let options = ScanOptions {
        policy: Policy::new(AttackStrength::Medium, AlertThreshold::Off),
        ..ScanOptions::default()
    };
    let (alerts, requests) = run(seed, Arc::new(Fixture { crlf: true }), options);
    assert!(alerts.is_empty());
    assert_eq!(requests, 0);
}

#[test]
fn plugin_threshold_off_skips_only_that_rule() {
    let seed = message(
        Method::GET,
        "http://fixture.test/shouldRaiseAlertIfResponseContainsExpectedErrorForInjectedInput/?query=xxx",
        HeaderMap::new(),
        "",
    );
    let mut options = ScanOptions::default();
    options
        .policy
        .set_plugin_threshold(CRLF_PLUGIN_ID, AlertThreshold::Off);
    let (alerts, _) = run(seed, Arc::new(Fixture { crlf: false }), options);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, XPATH_PLUGIN_ID);
}

struct Probe {
    id: i32,
    name: &'static str,
    seen: Arc<Mutex<Vec<i32>>>,
    strength: Arc<Mutex<Vec<AttackStrength>>>,
    sends: usize,
}

impl ActivePlugin for Probe {
    fn plugin_id(&self) -> i32 {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        self.seen.lock().unwrap().push(self.id);
        self.strength.lock().unwrap().push(ctx.strength());
        for _ in 0..self.sends {
            if ctx.is_stopped() {
                return;
            }
            let mut msg = ctx.base().clone();
            if ctx.send(&mut msg).is_err() {
                return;
            }
        }
    }
}

#[test]
fn host_runs_plugins_in_order_at_the_configured_strength() {
    let (dir, session) = temp_session();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let strength = Arc::new(Mutex::new(Vec::new()));
    let plugins: Vec<Arc<dyn ActivePlugin>> = vec![
        Arc::new(Probe {
            id: 2,
            name: "second",
            seen: Arc::clone(&seen),
            strength: Arc::clone(&strength),
            sends: 0,
        }),
        Arc::new(Probe {
            id: 1,
            name: "first",
            seen: Arc::clone(&seen),
            strength: Arc::clone(&strength),
            sends: 0,
        }),
    ];
    let engine = Engine::with_plugins(session, Arc::new(Fixture { crlf: true }), plugins);
    let options = ScanOptions {
        policy: Policy::new(AttackStrength::High, AlertThreshold::Medium),
        ..ScanOptions::default()
    };
    let seed = message(
        Method::GET,
        "http://fixture.test/ordered?q=1",
        HeaderMap::new(),
        "",
    );
    let id = engine.start(seed, options);
    assert!(engine.wait(id, Duration::from_secs(5)));
    assert_eq!(engine.host(id).unwrap(), "fixture.test");
    assert_eq!(engine.strength(id), Some(AttackStrength::High));
    assert_eq!(*seen.lock().unwrap(), vec![2, 1]);
    assert_eq!(
        *strength.lock().unwrap(),
        vec![AttackStrength::High, AttackStrength::High]
    );
    let _ = std::fs::remove_dir_all(dir);
}

struct Gate {
    lock: Mutex<bool>,
    cv: Condvar,
    entered: AtomicUsize,
}

impl ScanSender for Gate {
    fn send(&self, _msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        let seen = self.entered.fetch_add(1, Ordering::SeqCst);
        if seen == 0 {
            let mut go = self.lock.lock().unwrap();
            while !*go {
                go = self.cv.wait(go).unwrap();
            }
        }
        Ok(empty_page())
    }
}

#[test]
fn stop_halts_further_requests() {
    let (dir, session) = temp_session();
    let gate = Arc::new(Gate {
        lock: Mutex::new(false),
        cv: Condvar::new(),
        entered: AtomicUsize::new(0),
    });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let strength = Arc::new(Mutex::new(Vec::new()));
    let plugins: Vec<Arc<dyn ActivePlugin>> = vec![Arc::new(Probe {
        id: 7,
        name: "many",
        seen,
        strength,
        sends: 5,
    })];
    let engine = Engine::with_plugins(
        Arc::clone(&session),
        Arc::clone(&gate) as Arc<dyn ScanSender>,
        plugins,
    );
    let seed = message(
        Method::GET,
        "http://fixture.test/stop?q=1",
        HeaderMap::new(),
        "",
    );
    let id = engine.start(seed, ScanOptions::default());
    wait_for_request(&engine, id);
    assert!(engine.stop(id));
    {
        let mut go = gate.lock.lock().unwrap();
        *go = true;
        gate.cv.notify_all();
    }
    assert!(engine.wait(id, Duration::from_secs(5)));
    assert_eq!(engine.request_count(id), Some(1));
    assert_eq!(engine.status(id), Some(100));
    assert!(engine.alerts(id).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

fn api_message(url: &str) -> HttpMessage {
    message(Method::GET, url, HeaderMap::new(), "")
}

fn body_json(msg: &HttpMessage) -> serde_json::Value {
    serde_json::from_slice(&msg.response.as_ref().unwrap().body).unwrap()
}

#[test]
fn api_scan_status_and_stop_use_zap_json_keys() {
    let (dir, session) = temp_session();
    let service = ActiveScanService::new(Arc::clone(&session), Arc::new(Fixture { crlf: true }));
    let mut missing = api_message("http://zap/JSON/ascan/action/scan/");
    assert!(service.handle(&mut missing));
    assert_eq!(
        missing.response.as_ref().unwrap().status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(body_json(&missing)["code"], "missing_parameter");

    let mut started = api_message(
        "http://zap/JSON/ascan/action/scan/?url=http://fixture.test/shouldFindCrLfInjection.php%3Fyears%3D1&recurse=false",
    );
    assert!(service.handle(&mut started));
    assert_eq!(body_json(&started)["scan"], "0");
    assert!(service.wait(0, Duration::from_secs(5)));
    assert_eq!(service.engine().recurse(0), Some(false));
    assert_eq!(service.engine().status(0), Some(100));

    let mut status = api_message("http://zap/JSON/ascan/view/status/?scanId=0");
    assert!(service.handle(&mut status));
    assert_eq!(body_json(&status)["status"], "100");
    let stored = session.alerts().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].plugin_id, 40003);
    assert_eq!(stored[0].risk, 2);
    assert!(stored[0]
        .url
        .contains("years=any%0D%0ASet-cookie%3A+Tamper%3D"));

    let mut unknown = api_message("http://zap/JSON/ascan/view/status/?scanId=99");
    assert!(service.handle(&mut unknown));
    assert_eq!(body_json(&unknown)["code"], "does_not_exist");

    let mut stopped = api_message("http://zap/JSON/ascan/action/stop/?scanId=0");
    assert!(service.handle(&mut stopped));
    assert_eq!(body_json(&stopped)["Result"], "OK");

    let mut other = api_message("http://zap/JSON/core/view/version/");
    assert!(!service.handle(&mut other));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn api_stop_halts_further_requests() {
    let (dir, session) = temp_session();
    let gate = Arc::new(Gate {
        lock: Mutex::new(false),
        cv: Condvar::new(),
        entered: AtomicUsize::new(0),
    });
    let service = ActiveScanService::new(session, Arc::clone(&gate) as Arc<dyn ScanSender>);
    let mut started = api_message(
        "http://zap/JSON/ascan/action/scan/?url=http://fixture.test/shouldFindCrLfInjection.php%3Fyears%3D1",
    );
    assert!(service.handle(&mut started));
    let id: i32 = body_json(&started)["scan"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let started_at = std::time::Instant::now();
    while service.engine().request_count(id).unwrap() == 0 {
        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "scan did not send"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut stopped = api_message(&format!("http://zap/JSON/ascan/action/stop/?scanId={id}"));
    assert!(service.handle(&mut stopped));
    assert_eq!(body_json(&stopped)["Result"], "OK");
    {
        let mut go = gate.lock.lock().unwrap();
        *go = true;
        gate.cv.notify_all();
    }
    assert!(service.wait(id, Duration::from_secs(5)));
    assert_eq!(service.engine().request_count(id), Some(1));
    let mut status = api_message(&format!("http://zap/JSON/ascan/view/status/?scanId={id}"));
    assert!(service.handle(&mut status));
    assert_eq!(body_json(&status)["status"], "100");
    let _ = std::fs::remove_dir_all(dir);
}

fn wait_for_request(engine: &Engine, id: i32) {
    let started_at = std::time::Instant::now();
    while engine.request_count(id).unwrap() == 0 {
        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "scan did not send"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn host_key_of(url: &str) -> String {
    let msg = message(Method::GET, url, HeaderMap::new(), "");
    host_key(&msg)
}
