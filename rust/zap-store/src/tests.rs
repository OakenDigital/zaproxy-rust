// Copyright 2010-2024 The ZAP Development Team
// Copyright (C) 2003-2004 Chinotec Technologies Company
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
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use zap_core::{HttpMessage, HttpResponse};

use crate::{AlertRow, Confidence, NewAlert, Risk, Session, UNKNOWN_CWE_ID, UNKNOWN_WASC_ID};

fn temp_db(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-store-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path.join("session.sqlite")
}

fn message(with_response: bool) -> HttpMessage {
    let mut request_headers = HeaderMap::new();
    request_headers.insert("x-test", HeaderValue::from_static("one"));
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    HttpMessage {
        method: Method::POST,
        uri: "http://127.0.0.1:9/a/b?x=1".parse().unwrap(),
        headers: request_headers,
        body: Bytes::from(vec![0xff, 0x00, b'a']),
        response: with_response.then(|| HttpResponse {
            status: StatusCode::CREATED,
            headers: response_headers,
            body: Bytes::from_static(b"resp-body"),
        }),
    }
}

#[test]
fn schema_survives_reopen() {
    let path = temp_db("schema");
    let session = Session::open(&path).unwrap();
    assert_eq!(session.schema_version().unwrap(), 1);
    drop(session);
    let session = Session::open(&path).unwrap();
    assert_eq!(session.schema_version().unwrap(), 1);
    assert!(session.history_rows().unwrap().is_empty());
    assert!(session.alerts().unwrap().is_empty());
}

#[test]
fn history_and_site_nodes_round_trip() {
    let path = temp_db("history");
    let recorded_id;
    {
        let session = Session::open(&path).unwrap();
        assert!(session.record_exchange(&message(false)).unwrap().is_none());
        assert!(session.history_rows().unwrap().is_empty());
        recorded_id = session.record_exchange(&message(true)).unwrap().unwrap();
        assert_eq!(recorded_id, 1);
        let second = message(true);
        let mut deeper = second;
        deeper.uri = "http://127.0.0.1:9/a/c".parse().unwrap();
        deeper.method = Method::GET;
        assert_eq!(session.record_exchange(&deeper).unwrap().unwrap(), 2);
    }

    let session = Session::open(&path).unwrap();
    let rows = session.history_rows().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].id, 1);
    assert_eq!(rows[0].method, "POST");
    assert_eq!(rows[0].url, "http://127.0.0.1:9/a/b?x=1");
    assert_eq!(rows[0].status, 201);
    assert_eq!(
        rows[0].request_headers,
        vec![("x-test".into(), "one".into())]
    );
    assert_eq!(rows[0].request_body.as_ref(), &[0xff, 0x00, b'a']);
    assert_eq!(
        rows[0].response_headers,
        vec![("content-type".into(), "text/plain".into())]
    );
    assert_eq!(rows[0].response_body.as_ref(), b"resp-body");
    assert!(rows[0].recorded_at_ms > 0);
    assert_eq!(rows[1].method, "GET");
    assert_eq!(rows[1].url, "http://127.0.0.1:9/a/c");

    let nodes = session.site_nodes().unwrap();
    let host = nodes.iter().find(|node| node.parent_id.is_none()).unwrap();
    assert_eq!(host.segment, "http://127.0.0.1:9");
    assert!(host.method.is_none());
    assert!(host.history_id.is_none());
    let directory = nodes
        .iter()
        .find(|node| node.segment == "a")
        .expect("path segment a");
    assert_eq!(directory.parent_id, Some(host.id));
    assert!(directory.method.is_none());
    let leaf = nodes
        .iter()
        .find(|node| node.segment == "b")
        .expect("path segment b");
    assert_eq!(leaf.parent_id, Some(directory.id));
    assert_eq!(leaf.url, "http://127.0.0.1:9/a/b?x=1");
    assert_eq!(leaf.method.as_deref(), Some("POST"));
    assert_eq!(leaf.history_id, Some(recorded_id));
    let other = nodes
        .iter()
        .find(|node| node.segment == "c")
        .expect("path segment c");
    assert_eq!(other.parent_id, Some(directory.id));
    assert_eq!(other.method.as_deref(), Some("GET"));
    assert_eq!(other.history_id, Some(2));
}

#[test]
fn alert_row_round_trips_plugin_risk_confidence_cwe_wasc_param_and_url() {
    let path = temp_db("alert");
    let detailed = NewAlert {
        plugin_id: 40012,
        risk: Risk::Medium.code(),
        confidence: Confidence::High.code(),
        cwe_id: 79,
        wasc_id: 8,
        param: "q".to_string(),
        url: "http://example.test/search?q=1".to_string(),
    };
    let unknown = NewAlert {
        plugin_id: 0,
        risk: Risk::Informational.code(),
        confidence: Confidence::UserConfirmed.code(),
        cwe_id: UNKNOWN_CWE_ID,
        wasc_id: UNKNOWN_WASC_ID,
        param: String::new(),
        url: "https://example.test/empty".to_string(),
    };
    let raw = NewAlert {
        plugin_id: 7,
        risk: 99,
        confidence: 99,
        cwe_id: 89,
        wasc_id: 19,
        param: "id".to_string(),
        url: "https://example.test/items/1".to_string(),
    };
    {
        let session = Session::open(&path).unwrap();
        assert_eq!(session.insert_alert(&detailed).unwrap(), 1);
        assert_eq!(session.insert_alert(&unknown).unwrap(), 2);
        assert_eq!(session.insert_alert(&raw).unwrap(), 3);
    }

    let session = Session::open(&path).unwrap();
    let rows = session.alerts().unwrap();
    assert_eq!(
        rows,
        vec![
            AlertRow {
                id: 1,
                plugin_id: 40012,
                risk: 2,
                confidence: 3,
                cwe_id: 79,
                wasc_id: 8,
                param: "q".to_string(),
                url: "http://example.test/search?q=1".to_string(),
            },
            AlertRow {
                id: 2,
                plugin_id: 0,
                risk: 0,
                confidence: 4,
                cwe_id: -1,
                wasc_id: -1,
                param: String::new(),
                url: "https://example.test/empty".to_string(),
            },
            AlertRow {
                id: 3,
                plugin_id: 7,
                risk: 99,
                confidence: 99,
                cwe_id: 89,
                wasc_id: 19,
                param: "id".to_string(),
                url: "https://example.test/items/1".to_string(),
            },
        ]
    );
    assert_eq!(session.alert(1).unwrap().unwrap(), rows[0]);
    assert_eq!(rows[0].risk, Risk::Medium.code());
    assert_eq!(rows[0].confidence, Confidence::High.code());
    assert_eq!(rows[1].risk, Risk::Informational.code());
    assert_eq!(rows[1].confidence, Confidence::UserConfirmed.code());
    assert_eq!(rows[1].cwe_id, UNKNOWN_CWE_ID);
    assert_eq!(rows[1].wasc_id, UNKNOWN_WASC_ID);
}

#[test]
fn every_risk_and_confidence_code_round_trips() {
    let path = temp_db("codes");
    let risks = [Risk::Informational, Risk::Low, Risk::Medium, Risk::High];
    let confidences = [
        Confidence::FalsePositive,
        Confidence::Low,
        Confidence::Medium,
        Confidence::High,
        Confidence::UserConfirmed,
    ];
    {
        let session = Session::open(&path).unwrap();
        for risk in risks {
            for confidence in confidences {
                session
                    .insert_alert(&NewAlert {
                        plugin_id: 100,
                        risk: risk.code(),
                        confidence: confidence.code(),
                        cwe_id: UNKNOWN_CWE_ID,
                        wasc_id: UNKNOWN_WASC_ID,
                        param: format!("{risk:?}"),
                        url: format!("https://example.test/{confidence:?}"),
                    })
                    .unwrap();
            }
        }
    }
    let session = Session::open(&path).unwrap();
    let rows = session.alerts().unwrap();
    assert_eq!(rows.len(), risks.len() * confidences.len());
    let mut index = 0;
    for risk in risks {
        for confidence in confidences {
            assert_eq!(rows[index].plugin_id, 100);
            assert_eq!(rows[index].risk, risk.code());
            assert_eq!(rows[index].confidence, confidence.code());
            assert_eq!(rows[index].cwe_id, UNKNOWN_CWE_ID);
            assert_eq!(rows[index].wasc_id, UNKNOWN_WASC_ID);
            assert_eq!(rows[index].param, format!("{risk:?}"));
            assert_eq!(
                rows[index].url,
                format!("https://example.test/{confidence:?}")
            );
            index += 1;
        }
    }
}
