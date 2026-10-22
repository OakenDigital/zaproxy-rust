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
// This file is not an official OWASP ZAP build.

//! One fixture per ported rule: plugin id, name, risk, confidence, CWE, WASC, param, and URL.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use zap_addon::Registry;
use zap_ascan::{ActivePlugin, Engine, ScanOptions, ScanSender};
use zap_core::{HttpMessage, HttpResponse};
use zap_pscan::{AlertThreshold, PassiveScanner};
use zap_store::{Confidence, NewAlert, Risk, Session};

use crate::cookies::{attribute_value, cookie_name, has_attribute, is_expired};
use crate::{
    install, AntiClickjackingScanRule, ContentTypeMissingScanRule, CookieHttpOnlyScanRule,
    CookieSameSiteScanRule, CookieSecureFlagScanRule, FormatStringScanRule,
    ServerHeaderInfoLeakScanRule, ServerSideIncludeScanRule, XAspNetVersionScanRule,
    XPoweredByHeaderInfoLeakScanRule, CLICKJACK_ID, CONTENT_TYPE_ID, COOKIE_HTTPONLY_ID,
    COOKIE_SAMESITE_ID, COOKIE_SECURE_ID, FORMAT_NAME, FORMAT_PLUGIN_ID, SERVER_HEADER_ID,
    SSI_NAME, SSI_PLUGIN_ID, X_ASPNET_ID, X_POWERED_BY_ID,
};

fn page(url: &str, status: u16, headers: &[(&str, &str)], body: &str) -> HttpMessage {
    let mut response_headers = HeaderMap::new();
    for (name, value) in headers {
        response_headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    HttpMessage {
        method: Method::GET,
        uri: url.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: Some(HttpResponse {
            status: StatusCode::from_u16(status).unwrap(),
            headers: response_headers,
            body: Bytes::from(body.to_string()),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn expect(
    alert: &NewAlert,
    id: i32,
    name: &str,
    risk: i32,
    confidence: i32,
    cwe: i32,
    wasc: i32,
    param: &str,
) {
    assert_eq!(alert.plugin_id, id);
    assert_eq!(alert.name, name);
    assert_eq!(alert.risk, risk);
    assert_eq!(alert.confidence, confidence);
    assert_eq!(alert.cwe_id, cwe);
    assert_eq!(alert.wasc_id, wasc);
    assert_eq!(alert.param, param);
    assert_eq!(alert.url, "http://example.test/page");
}

#[test]
fn cookie_attribute_helpers_match_cookieutils() {
    assert!(has_attribute("id=1; HttpOnly", "httponly"));
    assert!(!has_attribute("HttpOnly=1", "httponly"));
    assert_eq!(
        attribute_value("id=1; SameSite=None", "samesite").as_deref(),
        Some("None")
    );
    assert_eq!(attribute_value("id=1; SameSite", "samesite"), None);
    assert_eq!(cookie_name("session=abc; Path=/"), "session");
    assert_eq!(cookie_name("noequals"), "");
    assert!(!is_expired("id=1; Path=/"));
    assert!(is_expired("id=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
    assert!(!is_expired("id=1; Expires=Thu, 01 Jan 2099 00:00:00 GMT"));
    assert!(is_expired("id=1; Expires=not-a-date"));
}

#[test]
fn cookie_without_httponly_uses_the_cookie_name() {
    let rule = CookieHttpOnlyScanRule::new();
    assert_eq!(rule.plugin_id(), COOKIE_HTTPONLY_ID);
    assert_eq!(rule.name(), CookieHttpOnlyScanRule::NAME);
    let msg = page(
        "http://example.test/page",
        200,
        &[
            ("Set-Cookie", "session=abc; Path=/"),
            ("Set-Cookie2", "other=1"),
        ],
        "ok",
    );
    let alerts = rule.scan_http_response(&msg);
    assert_eq!(alerts.len(), 2);
    expect(
        &alerts[0],
        COOKIE_HTTPONLY_ID,
        CookieHttpOnlyScanRule::NAME,
        Risk::Low.code(),
        Confidence::Medium.code(),
        1004,
        13,
        "session",
    );
    assert_eq!(alerts[1].param, "other");

    let safe = page(
        "http://example.test/page",
        200,
        &[("Set-Cookie", "session=abc; HttpOnly")],
        "ok",
    );
    assert!(rule.scan_http_response(&safe).is_empty());
    let expired = page(
        "http://example.test/page",
        200,
        &[(
            "Set-Cookie",
            "session=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        )],
        "ok",
    );
    assert!(rule.scan_http_response(&expired).is_empty());
    rule.set_threshold(AlertThreshold::Off);
    assert!(rule.scan_http_response(&msg).is_empty());
}

#[test]
fn secure_cookie_flag_is_https_only() {
    let rule = CookieSecureFlagScanRule::new();
    let http = page(
        "http://example.test/page",
        200,
        &[("Set-Cookie", "session=abc")],
        "ok",
    );
    assert!(rule.scan_http_response(&http).is_empty());
    let mut https = page(
        "https://example.test/page",
        200,
        &[("Set-Cookie", "session=abc; Path=/")],
        "ok",
    );
    let alerts = rule.scan_http_response(&https);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, COOKIE_SECURE_ID);
    assert_eq!(alerts[0].name, CookieSecureFlagScanRule::NAME);
    assert_eq!(alerts[0].risk, Risk::Low.code());
    assert_eq!(alerts[0].confidence, Confidence::Medium.code());
    assert_eq!(alerts[0].cwe_id, 614);
    assert_eq!(alerts[0].wasc_id, 13);
    assert_eq!(alerts[0].param, "session");
    assert_eq!(alerts[0].url, "https://example.test/page");
    https.response.as_mut().unwrap().headers.insert(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("session=abc; Secure"),
    );
    assert!(rule.scan_http_response(&https).is_empty());
}

#[test]
fn samesite_missing_none_and_illegal_values() {
    let rule = CookieSameSiteScanRule::new();
    let missing = page(
        "http://example.test/page",
        200,
        &[("Set-Cookie", "session=abc; Path=/")],
        "ok",
    );
    let alerts = rule.scan_http_response(&missing);
    expect(
        &alerts[0],
        COOKIE_SAMESITE_ID,
        CookieSameSiteScanRule::NAME,
        Risk::Low.code(),
        Confidence::Medium.code(),
        1275,
        13,
        "session",
    );
    let none = page(
        "http://example.test/page",
        200,
        &[("Set-Cookie", "session=abc; SameSite=none")],
        "ok",
    );
    assert_eq!(
        rule.scan_http_response(&none)[0].name,
        CookieSameSiteScanRule::NONE_NAME
    );
    rule.set_threshold(AlertThreshold::High);
    assert!(rule.scan_http_response(&none).is_empty());
    rule.set_threshold(AlertThreshold::Medium);
    let bad = page(
        "http://example.test/page",
        200,
        &[("Set-Cookie", "session=abc; SameSite=badVal")],
        "ok",
    );
    assert_eq!(
        rule.scan_http_response(&bad)[0].name,
        CookieSameSiteScanRule::BAD_NAME
    );
    for value in ["Lax", "Strict"] {
        let ok = page(
            "http://example.test/page",
            200,
            &[("Set-Cookie", &format!("session=abc; SameSite={value}"))],
            "ok",
        );
        assert!(rule.scan_http_response(&ok).is_empty(), "{value}");
    }
}

#[test]
fn content_type_missing_and_empty_are_informational() {
    let rule = ContentTypeMissingScanRule::new();
    let missing = page("http://example.test/page", 200, &[], "body");
    expect(
        &rule.scan_http_response(&missing)[0],
        CONTENT_TYPE_ID,
        ContentTypeMissingScanRule::NAME,
        Risk::Informational.code(),
        Confidence::Medium.code(),
        345,
        12,
        "content-type",
    );
    let empty = page(
        "http://example.test/page",
        200,
        &[("Content-Type", "")],
        "body",
    );
    assert_eq!(
        rule.scan_http_response(&empty)[0].name,
        ContentTypeMissingScanRule::EMPTY_NAME
    );
    let present = page(
        "http://example.test/page",
        200,
        &[("Content-Type", "text/html")],
        "body",
    );
    assert!(rule.scan_http_response(&present).is_empty());
    let nobody = page("http://example.test/page", 200, &[], "");
    assert!(rule.scan_http_response(&nobody).is_empty());
}

#[test]
fn anti_clickjacking_requires_html_and_names_each_case() {
    let rule = AntiClickjackingScanRule::new();
    assert_eq!(rule.name(), AntiClickjackingScanRule::NAME);
    let html = "<html><body>x</body></html>";
    let missing = page(
        "http://example.test/page",
        200,
        &[("Content-Type", "text/html")],
        html,
    );
    expect(
        &rule.scan_http_response(&missing)[0],
        CLICKJACK_ID,
        AntiClickjackingScanRule::MISSING_NAME,
        Risk::Medium.code(),
        Confidence::Medium.code(),
        1021,
        15,
        "x-frame-options",
    );
    let plain = page(
        "http://example.test/page",
        200,
        &[("Content-Type", "text/plain")],
        "not html",
    );
    assert!(rule.scan_http_response(&plain).is_empty());
    let deny = page(
        "http://example.test/page",
        200,
        &[("Content-Type", "text/html"), ("X-Frame-Options", "DENY")],
        html,
    );
    assert!(rule.scan_http_response(&deny).is_empty());
    let malformed = page(
        "http://example.test/page",
        200,
        &[
            ("Content-Type", "text/html"),
            ("X-Frame-Options", "ALLOW-FROM https://evil.test"),
        ],
        html,
    );
    assert_eq!(
        rule.scan_http_response(&malformed)[0].name,
        AntiClickjackingScanRule::MALFORMED_NAME
    );
    let mut multiple = HeaderMap::new();
    multiple.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/html"),
    );
    multiple.append(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    multiple.append(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    let mut both = page("http://example.test/page", 200, &[], html);
    both.response.as_mut().unwrap().headers = multiple;
    assert_eq!(
        rule.scan_http_response(&both)[0].name,
        AntiClickjackingScanRule::MULTIPLE_NAME
    );
    let meta = page(
        "http://example.test/page",
        200,
        &[("Content-Type", "text/html"), ("X-Frame-Options", "DENY")],
        "<html><meta http-equiv=\"X-Frame-Options\" content=\"deny\"></html>",
    );
    assert_eq!(
        rule.scan_http_response(&meta)[0].name,
        AntiClickjackingScanRule::META_NAME
    );
    let error = page(
        "http://example.test/page",
        404,
        &[("Content-Type", "text/html")],
        html,
    );
    assert!(rule.scan_http_response(&error).is_empty());
    let csp = page(
        "http://example.test/page",
        200,
        &[
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
        ],
        html,
    );
    assert!(rule.scan_http_response(&csp).is_empty());
    let untyped = page("http://example.test/page", 200, &[], html);
    assert!(rule.scan_http_response(&untyped).is_empty());
}

#[test]
fn server_header_version_is_low_and_bare_name_needs_low_threshold() {
    let rule = ServerHeaderInfoLeakScanRule::new();
    assert_eq!(rule.name(), ServerHeaderInfoLeakScanRule::NAME);
    let version = page(
        "http://example.test/page",
        200,
        &[("Server", "Apache/2.4.1")],
        "ok",
    );
    expect(
        &rule.scan_http_response(&version)[0],
        SERVER_HEADER_ID,
        ServerHeaderInfoLeakScanRule::VERSION_NAME,
        Risk::Low.code(),
        Confidence::High.code(),
        497,
        13,
        "",
    );
    let bare = page(
        "http://example.test/page",
        200,
        &[("Server", "Apache")],
        "ok",
    );
    assert!(rule.scan_http_response(&bare).is_empty());
    rule.set_threshold(AlertThreshold::Low);
    expect(
        &rule.scan_http_response(&bare)[0],
        SERVER_HEADER_ID,
        ServerHeaderInfoLeakScanRule::PRESENT_NAME,
        Risk::Informational.code(),
        Confidence::High.code(),
        497,
        13,
        "",
    );
}

#[test]
fn x_powered_by_and_aspnet_headers_leak_once_per_header() {
    let powered = XPoweredByHeaderInfoLeakScanRule::new();
    assert!(powered
        .scan_http_response(&page("http://example.test/page", 200, &[], "ok"))
        .is_empty());
    let leak = page(
        "http://example.test/page",
        200,
        &[("X-Powered-By", "PHP/5.4")],
        "ok",
    );
    expect(
        &powered.scan_http_response(&leak)[0],
        X_POWERED_BY_ID,
        XPoweredByHeaderInfoLeakScanRule::NAME,
        Risk::Low.code(),
        Confidence::Medium.code(),
        497,
        13,
        "",
    );
    let asp = XAspNetVersionScanRule::new();
    let mut headers = page("http://example.test/page", 200, &[], "ok");
    headers.response.as_mut().unwrap().headers.append(
        HeaderName::from_static("x-aspnet-version"),
        HeaderValue::from_static("4.0.30319"),
    );
    headers.response.as_mut().unwrap().headers.append(
        HeaderName::from_static("x-aspnetmvc-version"),
        HeaderValue::from_static("5.2"),
    );
    let alerts = asp.scan_http_response(&headers);
    assert_eq!(alerts.len(), 2);
    for alert in &alerts {
        expect(
            alert,
            X_ASPNET_ID,
            XAspNetVersionScanRule::NAME,
            Risk::Low.code(),
            Confidence::High.code(),
            933,
            14,
            "",
        );
    }
}

#[test]
fn bundled_addons_register_without_a_copied_manifest() {
    install();
    let dir = temp_dir("registry");
    let registry = Registry::load_with_bundled(&dir, crate::bundled_manifests()).unwrap();
    assert_eq!(
        registry.ids(),
        vec!["ascanrules".to_string(), "pscanrules".to_string()]
    );
    assert_eq!(registry.passive_rule_count(), 8);
    assert_eq!(registry.active_plugin_count(), 2);
    std::fs::write(
        dir.join("pscanrules.addon.json"),
        include_str!("../pscanrules.addon.json"),
    )
    .unwrap();
    let again = Registry::load_with_bundled(&dir, crate::bundled_manifests()).unwrap();
    assert_eq!(again.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zapd_sources_do_not_name_these_rules() {
    let names = [
        CookieHttpOnlyScanRule::NAME,
        CookieSecureFlagScanRule::NAME,
        CookieSameSiteScanRule::NAME,
        CookieSameSiteScanRule::NONE_NAME,
        CookieSameSiteScanRule::BAD_NAME,
        ContentTypeMissingScanRule::NAME,
        ContentTypeMissingScanRule::EMPTY_NAME,
        AntiClickjackingScanRule::NAME,
        AntiClickjackingScanRule::MISSING_NAME,
        AntiClickjackingScanRule::MULTIPLE_NAME,
        AntiClickjackingScanRule::META_NAME,
        AntiClickjackingScanRule::MALFORMED_NAME,
        ServerHeaderInfoLeakScanRule::NAME,
        ServerHeaderInfoLeakScanRule::VERSION_NAME,
        ServerHeaderInfoLeakScanRule::PRESENT_NAME,
        XPoweredByHeaderInfoLeakScanRule::NAME,
        XAspNetVersionScanRule::NAME,
        SSI_NAME,
        FORMAT_NAME,
    ];
    let ids = [
        "10010", "10011", "10019", "10020", "10036", "10037", "10054", "10061", "40009", "30002",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../zapd/src");
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for name in names {
            assert!(!text.contains(name), "{} in {}", name, path.display());
        }
        for id in ids {
            assert!(!text.contains(id), "{id} in {}", path.display());
        }
    }
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-scanrules-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn temp_session() -> Arc<Session> {
    let dir = temp_dir("session");
    Arc::new(Session::open(dir.join("session.sqlite")).unwrap())
}

struct Scripted<F> {
    respond: F,
}

impl<F> ScanSender for Scripted<F>
where
    F: Fn(&HttpMessage) -> HttpResponse + Send + Sync,
{
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        Ok((self.respond)(msg))
    }
}

fn response(status: StatusCode, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: HeaderMap::new(),
        body: Bytes::from(body.to_string()),
    }
}

fn seen(msg: &HttpMessage) -> String {
    format!(
        "{} {}",
        percent_decode(msg.uri.query().unwrap_or("")),
        percent_decode(&String::from_utf8_lossy(&msg.body))
    )
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (from_hex(bytes[index + 1]), from_hex(bytes[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
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

fn run_active(
    plugin: Arc<dyn ActivePlugin>,
    seed: HttpMessage,
    sender: Arc<dyn ScanSender>,
) -> Vec<zap_ascan::RaisedAlert> {
    let engine = Engine::with_plugins(temp_session(), sender, vec![plugin]);
    let id = engine.start(seed, ScanOptions::default());
    assert!(engine.wait(id, Duration::from_secs(5)));
    engine.alerts(id).unwrap()
}

fn seed(
    method: Method,
    url: &str,
    headers: HeaderMap,
    body: &str,
    response_body: &str,
) -> HttpMessage {
    HttpMessage {
        method,
        uri: url.parse().unwrap(),
        headers,
        body: Bytes::from(body.to_string()),
        response: Some(response(StatusCode::OK, response_body)),
    }
}

fn content_type(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static(value));
    headers
}

#[test]
fn server_side_include_matches_query_form_and_json() {
    let plugin = Arc::new(ServerSideIncludeScanRule);
    let sender = Arc::new(Scripted {
        respond: |msg: &HttpMessage| {
            let text = seen(msg);
            if text.contains("#EXEC") && text.contains("ls") {
                response(StatusCode::OK, "bin etc root home usr")
            } else if text.contains("#EXEC") && text.contains("dir") {
                response(StatusCode::OK, "program files WINDOWS")
            } else {
                response(StatusCode::OK, "ok")
            }
        },
    });
    let cases = [
        seed(
            Method::GET,
            "http://example.test/q?user=1",
            HeaderMap::new(),
            "",
            "ok",
        ),
        seed(
            Method::POST,
            "http://example.test/form",
            content_type("application/x-www-form-urlencoded"),
            "user=1",
            "ok",
        ),
        seed(
            Method::POST,
            "http://example.test/json",
            content_type("application/json"),
            "{\"user\":\"1\"}",
            "ok",
        ),
    ];
    for message in cases {
        let alerts = run_active(
            Arc::clone(&plugin) as Arc<dyn ActivePlugin>,
            message,
            Arc::clone(&sender) as Arc<dyn ScanSender>,
        );
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        let alert = &alerts[0];
        assert_eq!(alert.plugin_id, SSI_PLUGIN_ID);
        assert_eq!(alert.name, SSI_NAME);
        assert_eq!(alert.risk, Risk::High.code());
        assert_eq!(alert.confidence, Confidence::Medium.code());
        assert_eq!(alert.cwe_id, 97);
        assert_eq!(alert.wasc_id, 31);
        assert_eq!(alert.param, "user");
        assert!(alert.url.contains("example.test"));
        assert!(alert.evidence.to_ascii_lowercase().contains("root"));
        assert!(alert.evidence.to_ascii_lowercase().contains("usr"));
        assert!(alert.attack.contains("ls /"));
    }
    let clean = Arc::new(Scripted {
        respond: |_msg: &HttpMessage| response(StatusCode::OK, "no listing"),
    });
    let alerts = run_active(
        Arc::new(ServerSideIncludeScanRule),
        seed(
            Method::GET,
            "http://example.test/q?user=1",
            HeaderMap::new(),
            "",
            "ok",
        ),
        clean,
    );
    assert!(alerts.is_empty());
    let already = run_active(
        Arc::new(ServerSideIncludeScanRule),
        seed(
            Method::GET,
            "http://example.test/q?user=1",
            HeaderMap::new(),
            "",
            "root and usr and program files WINDOWS",
        ),
        Arc::new(Scripted {
            respond: |_msg: &HttpMessage| response(StatusCode::OK, "bin etc root home usr"),
        }),
    );
    assert!(already.is_empty());
}

#[test]
fn format_string_raises_on_gnu_and_microsoft_errors() {
    let gnu = Arc::new(Scripted {
        respond: |msg: &HttpMessage| {
            let text = seen(msg);
            if text.contains("%n%s") {
                response(StatusCode::INTERNAL_SERVER_ERROR, "err")
            } else if text.contains("%x") {
                response(StatusCode::OK, &"x".repeat(80))
            } else {
                response(StatusCode::OK, "short")
            }
        },
    });
    let alerts = run_active(
        Arc::new(FormatStringScanRule),
        seed(
            Method::GET,
            "http://example.test/q?name=1",
            HeaderMap::new(),
            "",
            "ok",
        ),
        gnu,
    );
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, FORMAT_PLUGIN_ID);
    assert_eq!(alerts[0].name, FORMAT_NAME);
    assert_eq!(alerts[0].risk, Risk::Medium.code());
    assert_eq!(alerts[0].confidence, Confidence::Medium.code());
    assert_eq!(alerts[0].cwe_id, 134);
    assert_eq!(alerts[0].wasc_id, 6);
    assert_eq!(alerts[0].param, "name");
    assert!(alerts[0].attack.contains("%x"));
    assert!(alerts[0].url.contains("example.test"));

    let microsoft = Arc::new(Scripted {
        respond: |msg: &HttpMessage| {
            let text = seen(msg);
            if text.contains("%1!s") {
                response(StatusCode::INTERNAL_SERVER_ERROR, "ms")
            } else {
                response(StatusCode::OK, "short")
            }
        },
    });
    let alerts = run_active(
        Arc::new(FormatStringScanRule),
        seed(
            Method::GET,
            "http://example.test/q?name=1",
            HeaderMap::new(),
            "",
            "ok",
        ),
        microsoft,
    );
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].attack.contains("%1!s"));
    assert!(alerts[0].attack.contains("%21!n"));

    let mut base_500 = seed(
        Method::GET,
        "http://example.test/q?name=1",
        HeaderMap::new(),
        "",
        "ok",
    );
    base_500.response.as_mut().unwrap().status = StatusCode::INTERNAL_SERVER_ERROR;
    let alerts = run_active(
        Arc::new(FormatStringScanRule),
        base_500,
        Arc::new(Scripted {
            respond: |_msg: &HttpMessage| response(StatusCode::INTERNAL_SERVER_ERROR, "no"),
        }),
    );
    assert!(alerts.is_empty());
}
