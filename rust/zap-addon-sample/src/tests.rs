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

//! The sample rule and API register from a copied manifest, not from zapd.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use zap_addon::{AddonPassiveListener, Registry};
use zap_core::{HttpMessage, HttpResponse, ProxyListener};
use zap_pscan::{AlertThreshold, PassiveScanner};
use zap_store::Session;

use crate::{
    install, manifest_file, SamplePassiveRule, API_PATH, HEADER_NAME, PLUGIN_ID, RULE_NAME,
};

fn temp_dir(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-addon-sample-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn response_with_header(present: bool) -> HttpMessage {
    let mut headers = HeaderMap::new();
    if present {
        headers.insert(HEADER_NAME, HeaderValue::from_static("ping"));
    }
    HttpMessage {
        method: Method::GET,
        uri: "http://example.test/page".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: Some(HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"ok"),
        }),
    }
}

#[test]
fn rule_alerts_only_for_its_header_and_threshold_off_skips_it() {
    let rule = SamplePassiveRule::new();
    assert_eq!(rule.name(), RULE_NAME);
    assert_eq!(rule.plugin_id(), PLUGIN_ID);
    assert!(rule
        .scan_http_response(&response_with_header(false))
        .is_empty());
    let alerts = rule.scan_http_response(&response_with_header(true));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, PLUGIN_ID);
    assert_eq!(alerts[0].param, HEADER_NAME);
    assert_eq!(alerts[0].risk, 0);
    rule.set_threshold(AlertThreshold::Off);
    assert!(!rule.is_enabled());
    assert!(rule
        .scan_http_response(&response_with_header(true))
        .is_empty());
}

#[test]
fn restart_after_copy_registers_the_rule_and_api() {
    install();
    let dir = temp_dir("restart");
    let before = Registry::load(&dir).unwrap();
    assert_eq!(before.passive_rule_count(), 0);
    assert_eq!(before.api_count(), 0);

    std::fs::copy(manifest_file(), dir.join("sample.addon.json")).unwrap();
    let after = Registry::load(&dir).unwrap();
    assert_eq!(after.ids(), vec!["sample".to_string()]);
    let rules = after.passive_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].plugin_id(), PLUGIN_ID);
    let alerts = rules[0].scan_http_response(&response_with_header(true));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].url, "http://example.test/page");

    let mut ping = HttpMessage {
        method: Method::GET,
        uri: format!("http://zap{API_PATH}").parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    };
    assert!(after.handle_api(&mut ping));
    let body = ping.response.unwrap().body;
    assert_eq!(body.as_ref(), br#"{"result":"pong"}"#);

    let mut other = HttpMessage {
        method: Method::GET,
        uri: "http://zap/JSON/core/view/version/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    };
    assert!(!after.handle_api(&mut other));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn listener_stores_the_sample_alert_without_the_daemon_naming_it() {
    install();
    let dir = temp_dir("listen");
    std::fs::copy(manifest_file(), dir.join("sample.addon.json")).unwrap();
    let registry = Arc::new(Registry::load(&dir).unwrap());
    let session_dir = temp_dir("session");
    let session = Arc::new(Session::open(session_dir.join("session.sqlite")).unwrap());
    let listener = AddonPassiveListener::new(Arc::clone(&registry), Arc::clone(&session));
    let mut msg = response_with_header(true);
    assert!(listener.on_http_response_receive(&mut msg));
    let rows = session.alerts().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].plugin_id, PLUGIN_ID);
    assert_eq!(rows[0].param, HEADER_NAME);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&session_dir);
}

#[test]
fn zapd_sources_do_not_name_the_sample_rule_or_api() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../zapd/src");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    assert!(!files.is_empty());
    let plugin = PLUGIN_ID.to_string();
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(RULE_NAME), "{}", path.display());
        assert!(!text.contains(&plugin), "{}", path.display());
        assert!(!text.contains(HEADER_NAME), "{}", path.display());
        assert!(!text.contains(API_PATH), "{}", path.display());
    }
}
