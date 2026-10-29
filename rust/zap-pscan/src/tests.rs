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

//! Unit tests for the queue, the header rule, disclosure rules, and threshold OFF.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use zap_core::{HttpMessage, HttpResponse, ProxyListener, HISTORY_LISTENER_ORDER};
use zap_store::{NewAlert, Session};

use crate::rules::disclosure::{
    DebugErrorsScanRule, DirectoryBrowsingScanRule, InPageBannerScanRule,
    SuspiciousCommentsScanRule, XBackendServerScanRule, XChromeLoggerScanRule, XDebugTokenScanRule,
    BACKEND_SERVER_ID, BACKEND_SERVER_NAME, BANNER_ID, BANNER_NAME, CHROME_LOGGER_ID,
    CHROME_LOGGER_NAME, DEBUG_ERRORS_ID, DEBUG_ERRORS_NAME, DEBUG_TOKEN_ID, DEBUG_TOKEN_NAME,
    DIRECTORY_BROWSING_ID, DIRECTORY_BROWSING_NAME, SUSPICIOUS_COMMENTS_ID,
    SUSPICIOUS_COMMENTS_NAME,
};
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

    fn name(&self) -> &'static str {
        "probe"
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
            name: "probe".to_string(),
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

fn typed(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, value.parse().unwrap());
    headers
}

struct Expect {
    id: i32,
    name: &'static str,
    risk: i32,
    confidence: i32,
    cwe: i32,
    wasc: i32,
}

fn assert_disclosure(alert: &NewAlert, expect: Expect, url: &str) {
    assert_eq!(alert.plugin_id, expect.id);
    assert_eq!(alert.name, expect.name);
    assert_eq!(alert.risk, expect.risk);
    assert_eq!(alert.confidence, expect.confidence);
    assert_eq!(alert.cwe_id, expect.cwe);
    assert_eq!(alert.wasc_id, expect.wasc);
    assert_eq!(alert.param, "");
    assert_eq!(alert.url, url);
}

#[test]
fn directory_listing_bodies_raise_medium_directory_browsing() {
    let rule = DirectoryBrowsingScanRule::new();
    let url = "http://example.test/files/";
    let apache = b"<html><title>Index of /files/</title></html>";
    let alerts = rule.scan_http_response(&fixture(url, StatusCode::OK, HeaderMap::new(), apache));
    assert_eq!(alerts.len(), 1);
    assert_disclosure(
        &alerts[0],
        Expect {
            id: DIRECTORY_BROWSING_ID,
            name: DIRECTORY_BROWSING_NAME,
            risk: 2,
            confidence: 2,
            cwe: 548,
            wasc: 16,
        },
        url,
    );

    let iis = b"<pre><A HREF=\"/\">[To Parent Directory]</A><br><br>";
    let iis_alerts = rule.scan_http_response(&fixture(url, StatusCode::OK, HeaderMap::new(), iis));
    assert_eq!(iis_alerts.len(), 1);
    assert_eq!(iis_alerts[0].plugin_id, 10033);
    assert_eq!(iis_alerts[0].wasc_id, 16);

    let plain = b"<html><body><a href=\"/page\">page</a></body></html>";
    assert!(rule
        .scan_http_response(&fixture(url, StatusCode::OK, HeaderMap::new(), plain))
        .is_empty());
}

#[test]
fn debug_error_text_raises_low_and_skips_script_at_medium() {
    let rule = DebugErrorsScanRule::new();
    let url = "http://example.test/debug";
    let alerts = rule.scan_http_response(&fixture(
        url,
        StatusCode::OK,
        typed("text/html"),
        b"php warning: headers already sent",
    ));
    assert_eq!(alerts.len(), 1);
    assert_disclosure(
        &alerts[0],
        Expect {
            id: DEBUG_ERRORS_ID,
            name: DEBUG_ERRORS_NAME,
            risk: 1,
            confidence: 2,
            cwe: 1295,
            wasc: 13,
        },
        url,
    );

    assert!(rule
        .scan_http_response(&fixture(
            url,
            StatusCode::OK,
            HeaderMap::new(),
            b"PHP Warning: x",
        ))
        .is_empty());

    let script = fixture(
        url,
        StatusCode::OK,
        typed("application/javascript"),
        b"PHP Warning: x",
    );
    assert!(rule.scan_http_response(&script).is_empty());
    rule.set_threshold(AlertThreshold::Low);
    assert_eq!(rule.scan_http_response(&script).len(), 1);
}

#[test]
fn suspicious_comments_use_medium_for_html_and_low_for_script() {
    let rule = SuspiciousCommentsScanRule::new();
    let url = "http://example.test/comments";
    let html = rule.scan_http_response(&fixture(
        url,
        StatusCode::OK,
        typed("text/html"),
        b"<html><!-- TODO and FIXME --></html>",
    ));
    assert_eq!(html.len(), 2);
    for alert in &html {
        assert_disclosure(
            alert,
            Expect {
                id: SUSPICIOUS_COMMENTS_ID,
                name: SUSPICIOUS_COMMENTS_NAME,
                risk: 0,
                confidence: 2,
                cwe: 615,
                wasc: 13,
            },
            url,
        );
    }

    let script = rule.scan_http_response(&fixture(
        url,
        StatusCode::OK,
        typed("text/html"),
        b"<html><script>var x = 1; // FIXME</script></html>",
    ));
    assert_eq!(script.len(), 1);
    assert_eq!(script[0].plugin_id, 10027);
    assert_eq!(script[0].confidence, 1);
    assert_eq!(script[0].risk, 0);

    assert!(rule
        .scan_http_response(&fixture(
            url,
            StatusCode::OK,
            typed("text/html"),
            b"<p>TODO outside a comment</p>",
        ))
        .is_empty());
    assert!(rule
        .scan_http_response(&fixture(
            url,
            StatusCode::OK,
            typed("text/font"),
            b"<!-- TODO -->",
        ))
        .is_empty());
}

#[test]
fn in_page_banner_matches_error_pages_and_low_threshold_success() {
    let rule = InPageBannerScanRule::new();
    let url = "http://example.test/banner";
    let missing = fixture(
        url,
        StatusCode::NOT_FOUND,
        HeaderMap::new(),
        b"nginx/1.18.0",
    );
    let alerts = rule.scan_http_response(&missing);
    assert_eq!(alerts.len(), 1);
    assert_disclosure(
        &alerts[0],
        Expect {
            id: BANNER_ID,
            name: BANNER_NAME,
            risk: 1,
            confidence: 3,
            cwe: 497,
            wasc: 13,
        },
        url,
    );

    let ok = fixture(url, StatusCode::OK, typed("text/html"), b"Apache/2.4.41");
    assert!(rule.scan_http_response(&ok).is_empty());
    rule.set_threshold(AlertThreshold::Low);
    let low = rule.scan_http_response(&ok);
    assert_eq!(low.len(), 1);
    assert_eq!(low[0].plugin_id, 10009);
    assert_eq!(low[0].confidence, 3);
}

#[test]
fn backend_and_chrome_logger_alert_once_per_header_value() {
    let url = "http://example.test/headers";
    let mut backend = HeaderMap::new();
    backend.append("x-backend-server", "app-a".parse().unwrap());
    backend.append("x-backend-server", "app-b".parse().unwrap());
    let alerts = XBackendServerScanRule::new().scan_http_response(&fixture(
        url,
        StatusCode::OK,
        backend,
        b"ok",
    ));
    assert_eq!(alerts.len(), 2);
    for alert in &alerts {
        assert_disclosure(
            alert,
            Expect {
                id: BACKEND_SERVER_ID,
                name: BACKEND_SERVER_NAME,
                risk: 1,
                confidence: 2,
                cwe: 497,
                wasc: 13,
            },
            url,
        );
    }
    assert!(XBackendServerScanRule::new()
        .scan_http_response(&fixture(url, StatusCode::OK, HeaderMap::new(), b"ok"))
        .is_empty());

    let mut chrome = HeaderMap::new();
    chrome.insert("x-chromelogger-data", "eyJkYXRhIjoxfQ==".parse().unwrap());
    chrome.insert("x-chromephp-data", "eyJkYXRhIjoyfQ==".parse().unwrap());
    let chrome_alerts = XChromeLoggerScanRule::new().scan_http_response(&fixture(
        url,
        StatusCode::OK,
        chrome,
        b"ok",
    ));
    assert_eq!(chrome_alerts.len(), 2);
    for alert in &chrome_alerts {
        assert_disclosure(
            alert,
            Expect {
                id: CHROME_LOGGER_ID,
                name: CHROME_LOGGER_NAME,
                risk: 2,
                confidence: 3,
                cwe: 532,
                wasc: 13,
            },
            url,
        );
    }
}

#[test]
fn debug_token_raises_one_alert_when_either_header_is_present() {
    let rule = XDebugTokenScanRule::new();
    let url = "http://example.test/profiler";
    let mut link = HeaderMap::new();
    link.insert("x-debug-token-link", "/_profiler/abc".parse().unwrap());
    let alerts = rule.scan_http_response(&fixture(url, StatusCode::OK, link, b"ok"));
    assert_eq!(alerts.len(), 1);
    assert_disclosure(
        &alerts[0],
        Expect {
            id: DEBUG_TOKEN_ID,
            name: DEBUG_TOKEN_NAME,
            risk: 1,
            confidence: 3,
            cwe: 489,
            wasc: 13,
        },
        url,
    );

    let mut both = HeaderMap::new();
    both.insert("x-debug-token", "abc".parse().unwrap());
    both.insert("x-debug-token-link", "/_profiler/abc".parse().unwrap());
    assert_eq!(
        rule.scan_http_response(&fixture(url, StatusCode::OK, both, b"ok"))
            .len(),
        1
    );
    assert!(rule
        .scan_http_response(&fixture(url, StatusCode::OK, HeaderMap::new(), b"ok"))
        .is_empty());
}

#[test]
fn listener_adds_directory_browsing_without_matching_the_plain_fixture() {
    let (dir, session) = temp_session();
    let listener = PassiveScanListener::new(Arc::clone(&session));
    let url = "http://example.test/listing";
    let mut listing = fixture(
        url,
        StatusCode::OK,
        HeaderMap::new(),
        b"<title>Index of /listing/</title>",
    );
    assert!(listener.on_http_response_receive(&mut listing));
    let ids: Vec<i32> = session
        .alerts()
        .unwrap()
        .iter()
        .map(|alert| alert.plugin_id)
        .collect();
    assert_eq!(ids, vec![10021, 10033]);
    let listing_alert = session
        .alerts()
        .unwrap()
        .into_iter()
        .find(|alert| alert.plugin_id == 10033)
        .unwrap();
    assert_eq!(listing_alert.risk, 2);
    assert_eq!(listing_alert.confidence, 2);
    assert_eq!(listing_alert.cwe_id, 548);
    assert_eq!(listing_alert.wasc_id, 16);
    assert_eq!(listing_alert.param, "");
    assert_eq!(listing_alert.url, url);

    let (clean_dir, clean_session) = temp_session();
    let clean = PassiveScanListener::new(Arc::clone(&clean_session));
    let mut headers = typed("text/html");
    headers.insert(HEADER_NAME, "nosniff".parse().unwrap());
    let mut page = fixture(
        "http://example.test/clean",
        StatusCode::OK,
        headers,
        b"<html><body>ok</body></html>",
    );
    assert!(clean.on_http_response_receive(&mut page));
    assert!(clean_session.alerts().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(clean_dir);
}
