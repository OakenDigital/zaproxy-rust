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

//! Unit tests for the queue, the X-Content-Type-Options rule, and threshold OFF.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use zap_core::{HttpMessage, HttpResponse, ProxyListener, HISTORY_LISTENER_ORDER};
use zap_store::{NewAlert, Session};

use crate::rules::x_content_type_options::{XContentTypeOptionsScanRule, HEADER_NAME, PLUGIN_ID};
use crate::scanner::PassiveScanner;
use crate::threshold::{AlertThreshold, ScannerState};
use crate::{PassiveScanListener, PassiveScanQueue, PASSIVE_SCAN_LISTENER_ORDER};

fn fixture(url: &str, status: StatusCode, headers: HeaderMap, body: &[u8]) -> HttpMessage {
    HttpMessage {
        method: Method::GET,
        uri: url.parse().expect("url"),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: Some(HttpResponse {
            status,
            headers,
            body: Bytes::copy_from_slice(body),
        }),
    }
}

fn temp_session() -> (std::path::PathBuf, Arc<Session>) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-pscan-unit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let session = Arc::new(Session::open(path.join("session.sqlite")).unwrap());
    (path, session)
}

struct Probe {
    state: ScannerState,
    plugin_id: i32,
    calls: AtomicUsize,
}

impl Probe {
    fn new(plugin_id: i32) -> Self {
        Self {
            state: ScannerState::new(AlertThreshold::Medium),
            plugin_id,
            calls: AtomicUsize::new(0),
        }
    }
}

impl PassiveScanner for Probe {
    fn plugin_id(&self) -> i32 {
        self.plugin_id
    }

    fn set_threshold(&self, threshold: AlertThreshold) {
        self.state.set_threshold(threshold);
    }

    fn is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    fn scan_http_response(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        vec![NewAlert {
            plugin_id: self.plugin_id,
            risk: 0,
            confidence: 0,
            cwe_id: -1,
            wasc_id: -1,
            param: String::new(),
            url: msg.url(),
        }]
    }
}

#[test]
fn listener_order_is_one_after_history() {
    assert_eq!(PASSIVE_SCAN_LISTENER_ORDER, HISTORY_LISTENER_ORDER + 1);
    assert_eq!(PASSIVE_SCAN_LISTENER_ORDER, 5001);
    let (_dir, session) = temp_session();
    let listener = PassiveScanListener::new(session);
    assert_eq!(listener.order(), 5001);
    let _ = std::fs::remove_dir_all(_dir);
}

#[test]
fn queue_runs_an_enabled_scanner_and_records_the_response() {
    let queue = PassiveScanQueue::new();
    let probe = Arc::new(Probe::new(7));
    queue.add_scanner(Arc::clone(&probe) as Arc<dyn PassiveScanner>);
    let url = "http://example.test/queued";
    let msg = fixture(url, StatusCode::OK, HeaderMap::new(), b"body");
    let alerts = queue.scan_response(&msg);
    assert_eq!(queue.queued_urls(), vec![url.to_string()]);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, 7);
    assert_eq!(alerts[0].url, url);
}

#[test]
fn queue_runs_scanners_in_registration_order() {
    let queue = PassiveScanQueue::new();
    queue.add_scanner(Arc::new(Probe::new(1)));
    queue.add_scanner(Arc::new(Probe::new(2)));
    let msg = fixture(
        "http://example.test/order",
        StatusCode::OK,
        HeaderMap::new(),
        b"body",
    );
    let alerts = queue.scan_response(&msg);
    let ids: Vec<i32> = alerts.iter().map(|alert| alert.plugin_id).collect();
    assert_eq!(ids, vec![1, 2]);
}

#[test]
fn queue_ignores_a_message_with_no_response() {
    let queue = PassiveScanQueue::new();
    let probe = Arc::new(Probe::new(7));
    queue.add_scanner(Arc::clone(&probe) as Arc<dyn PassiveScanner>);
    let msg = HttpMessage {
        method: Method::GET,
        uri: "http://example.test/none".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    };
    assert!(queue.scan_response(&msg).is_empty());
    assert!(queue.queued_urls().is_empty());
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn threshold_off_queues_the_response_and_raises_nothing() {
    let queue = PassiveScanQueue::new();
    let probe = Arc::new(Probe::new(7));
    queue.add_scanner(Arc::clone(&probe) as Arc<dyn PassiveScanner>);
    queue.set_threshold(7, AlertThreshold::Off);
    assert!(!probe.is_enabled());
    let msg = fixture(
        "http://example.test/off",
        StatusCode::OK,
        HeaderMap::new(),
        b"body",
    );
    let alerts = queue.scan_response(&msg);
    assert!(alerts.is_empty());
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        queue.queued_urls(),
        vec!["http://example.test/off".to_string()]
    );

    queue.set_threshold(7, AlertThreshold::Medium);
    assert!(probe.is_enabled());
    let again = queue.scan_response(&msg);
    assert_eq!(again.len(), 1);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn request_path_does_not_scan() {
    let (dir, session) = temp_session();
    let listener = PassiveScanListener::new(Arc::clone(&session));
    let mut msg = fixture(
        "http://example.test/req",
        StatusCode::OK,
        HeaderMap::new(),
        b"body",
    );
    assert!(listener.on_http_request_send(&mut msg));
    assert!(listener.queued_urls().is_empty());
    assert!(session.alerts().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn fixture_response_raises_one_alert_with_plugin_risk_and_url() {
    let (dir, session) = temp_session();
    let listener = PassiveScanListener::new(Arc::clone(&session));
    let url = "http://example.test/missing-nosniff";
    let mut msg = fixture(url, StatusCode::OK, HeaderMap::new(), b"<html></html>");
    assert!(listener.on_http_response_receive(&mut msg));
    let alerts = session.alerts().unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, 10021);
    assert_eq!(alerts[0].plugin_id, PLUGIN_ID);
    assert_eq!(alerts[0].risk, 1);
    assert_eq!(alerts[0].confidence, 2);
    assert_eq!(alerts[0].cwe_id, 693);
    assert_eq!(alerts[0].wasc_id, 15);
    assert_eq!(alerts[0].param, "x-content-type-options");
    assert_eq!(alerts[0].param, HEADER_NAME);
    assert_eq!(alerts[0].url, url);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn threshold_off_on_the_rule_raises_nothing() {
    let (dir, session) = temp_session();
    let listener = PassiveScanListener::new(Arc::clone(&session));
    listener.set_threshold(PLUGIN_ID, AlertThreshold::Off);
    let url = "http://example.test/off-rule";
    let mut msg = fixture(url, StatusCode::OK, HeaderMap::new(), b"body");
    assert!(listener.on_http_response_receive(&mut msg));
    assert!(session.alerts().unwrap().is_empty());
    assert_eq!(listener.queued_urls(), vec![url.to_string()]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn rule_alerts_once_per_value_that_lacks_nosniff() {
    let rule = XContentTypeOptionsScanRule::new();
    let url = "http://example.test/values";

    let mut nosniff = HeaderMap::new();
    nosniff.insert(HEADER_NAME, "NoSniff".parse().unwrap());
    assert!(rule
        .scan_http_response(&fixture(url, StatusCode::OK, nosniff, b"body"))
        .is_empty());

    let mut mixed = HeaderMap::new();
    mixed.append(HEADER_NAME, "nosniff".parse().unwrap());
    mixed.append(HEADER_NAME, "sniff".parse().unwrap());
    let alerts = rule.scan_http_response(&fixture(url, StatusCode::OK, mixed, b"body"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, 10021);
    assert_eq!(alerts[0].risk, 1);
    assert_eq!(alerts[0].url, url);

    let mut both_bad = HeaderMap::new();
    both_bad.append(HEADER_NAME, "sniff".parse().unwrap());
    both_bad.append(HEADER_NAME, "also-bad".parse().unwrap());
    assert_eq!(
        rule.scan_http_response(&fixture(url, StatusCode::OK, both_bad, b"body"))
            .len(),
        2
    );
}

#[test]
fn rule_ignores_an_empty_body() {
    let rule = XContentTypeOptionsScanRule::new();
    let msg = fixture(
        "http://example.test/empty",
        StatusCode::OK,
        HeaderMap::new(),
        b"",
    );
    assert!(rule.scan_http_response(&msg).is_empty());
    let low = XContentTypeOptionsScanRule::with_threshold(AlertThreshold::Low);
    assert!(low.scan_http_response(&msg).is_empty());
}

#[test]
fn default_medium_and_high_skip_error_and_redirect_bodies() {
    for threshold in [
        AlertThreshold::Default,
        AlertThreshold::Medium,
        AlertThreshold::High,
    ] {
        let rule = XContentTypeOptionsScanRule::with_threshold(threshold);
        for status in [
            StatusCode::FOUND,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let msg = fixture(
                "http://example.test/skip",
                status,
                HeaderMap::new(),
                b"body",
            );
            assert!(
                rule.scan_http_response(&msg).is_empty(),
                "{threshold:?} {status}"
            );
        }
        let ok = fixture(
            "http://example.test/ok",
            StatusCode::OK,
            HeaderMap::new(),
            b"body",
        );
        let alerts = rule.scan_http_response(&ok);
        assert_eq!(alerts.len(), 1, "{threshold:?}");
        assert_eq!(alerts[0].risk, 1);
        assert_eq!(alerts[0].url, "http://example.test/ok");
    }
}

#[test]
fn low_threshold_includes_error_and_redirect_bodies() {
    let rule = XContentTypeOptionsScanRule::with_threshold(AlertThreshold::Low);
    for status in [
        StatusCode::OK,
        StatusCode::FOUND,
        StatusCode::NOT_FOUND,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let msg = fixture("http://example.test/low", status, HeaderMap::new(), b"body");
        let alerts = rule.scan_http_response(&msg);
        assert_eq!(alerts.len(), 1, "{status}");
        assert_eq!(alerts[0].plugin_id, 10021);
        assert_eq!(alerts[0].url, "http://example.test/low");
    }
}
