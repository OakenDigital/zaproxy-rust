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

//! Session views and break decisions without a running proxy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use zap_core::{HttpMessage, HttpResponse};
use zap_store::{NewAlert, Session};

use crate::breakpoint::{BreakListener, BreakSide, Breakpoint, BREAK_LISTENER_ORDER};
use crate::view::snapshot;
use zap_core::ProxyListener;

fn temp_session() -> (std::path::PathBuf, Session) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-desktop-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let session = Session::open(path.join("session.sqlite")).unwrap();
    (path, session)
}

fn message(url: &str, body: &'static [u8], response_body: &'static [u8]) -> HttpMessage {
    HttpMessage {
        method: Method::POST,
        uri: url.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::from_static(body),
        response: Some(HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(response_body),
        }),
    }
}

#[test]
fn snapshot_shows_sites_history_message_and_alerts() {
    let (dir, session) = temp_session();
    let msg = message(
        "http://fixture.test/item",
        b"request-body",
        b"response-body",
    );
    session.record_exchange(&msg).unwrap();
    session
        .insert_alert(&NewAlert {
            plugin_id: 10021,
            risk: 1,
            confidence: 2,
            cwe_id: 693,
            wasc_id: 15,
            param: "x-content-type-options".to_string(),
            url: msg.url(),
        })
        .unwrap();
    let shot = snapshot(&session, &Breakpoint::new(), None).unwrap();
    assert!(shot
        .sites
        .iter()
        .any(|line| line.segment.contains("fixture.test")));
    assert!(shot.sites.iter().any(|line| line.segment == "item"));
    assert_eq!(shot.history.len(), 1);
    assert_eq!(shot.history[0].method, "POST");
    assert_eq!(shot.history[0].status, 200);
    let text = shot.message.expect("message");
    assert!(text.request.contains("POST http://fixture.test/item"));
    assert!(text.request.contains("request-body"));
    assert!(text.response.contains("HTTP/1.1 200"));
    assert!(text.response.contains("response-body"));
    assert_eq!(shot.alerts.len(), 1);
    assert_eq!(shot.alerts[0].plugin_id, 10021);
    assert_eq!(shot.alerts[0].risk, 1);
    assert_eq!(shot.alerts[0].param, "x-content-type-options");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn break_order_is_before_history() {
    let listener = BreakListener::new(Arc::new(Breakpoint::new()));
    assert_eq!(listener.order(), BREAK_LISTENER_ORDER);
    assert!(listener.order() < zap_core::HISTORY_LISTENER_ORDER);
}

#[test]
fn forward_replaces_the_request_body_and_drop_skips_the_origin() {
    let breakpoint = Arc::new(Breakpoint::new());
    breakpoint.set_request_enabled(true);
    let listener = BreakListener::new(Arc::clone(&breakpoint));
    let handle = thread::spawn(move || {
        let waiting = wait_for(&breakpoint);
        assert_eq!(waiting.side, BreakSide::Request);
        assert!(waiting.text.contains("POST http://fixture.test/held"));
        assert!(breakpoint.forward(waiting.id, "edited".to_string()));
    });
    let mut msg = message("http://fixture.test/held", b"original", b"unused");
    msg.response = None;
    assert!(listener.on_http_request_send(&mut msg));
    assert_eq!(msg.body.as_ref(), b"edited");
    handle.join().unwrap();
}

#[test]
fn drop_on_request_returns_false_and_drop_on_response_clears_it() {
    let breakpoint = Arc::new(Breakpoint::new());
    breakpoint.set_request_enabled(true);
    let listener = BreakListener::new(Arc::clone(&breakpoint));
    let parked = Arc::clone(&breakpoint);
    let handle = thread::spawn(move || {
        let waiting = wait_for(&parked);
        assert!(parked.drop_message(waiting.id));
    });
    let mut msg = message("http://fixture.test/drop", b"original", b"secret");
    msg.response = None;
    assert!(!listener.on_http_request_send(&mut msg));
    assert!(msg.response.is_none());
    handle.join().unwrap();

    breakpoint.set_request_enabled(false);
    breakpoint.set_response_enabled(true);
    let listener = BreakListener::new(Arc::clone(&breakpoint));
    let parked = Arc::clone(&breakpoint);
    let handle = thread::spawn(move || {
        let waiting = wait_for(&parked);
        assert_eq!(waiting.side, BreakSide::Response);
        assert!(waiting.text.contains("secret"));
        assert!(parked.drop_message(waiting.id));
    });
    let mut msg = message("http://fixture.test/drop", b"original", b"secret");
    assert!(!listener.on_http_response_receive(&mut msg));
    assert!(msg.response.is_none());
    handle.join().unwrap();
}

#[test]
fn turning_break_off_releases_a_held_request() {
    let breakpoint = Arc::new(Breakpoint::new());
    breakpoint.set_request_enabled(true);
    let listener = BreakListener::new(Arc::clone(&breakpoint));
    let parked = Arc::clone(&breakpoint);
    let handle = thread::spawn(move || {
        let _ = wait_for(&parked);
        parked.set_request_enabled(false);
    });
    let mut msg = message("http://fixture.test/release", b"keep", b"nope");
    msg.response = None;
    assert!(listener.on_http_request_send(&mut msg));
    assert_eq!(msg.body.as_ref(), b"keep");
    handle.join().unwrap();
}

#[test]
fn zapd_does_not_depend_on_the_desktop_crate() {
    let manifest = include_str!("../../zapd/Cargo.toml");
    assert!(
        !manifest.contains("zap-desktop"),
        "zapd must keep running without the desktop"
    );
}

fn wait_for(breakpoint: &Breakpoint) -> crate::breakpoint::Waiting {
    let start = std::time::Instant::now();
    loop {
        if let Some(waiting) = breakpoint.waiting() {
            return waiting;
        }
        assert!(start.elapsed() < Duration::from_secs(2), "no breakpoint");
        thread::sleep(Duration::from_millis(5));
    }
}
