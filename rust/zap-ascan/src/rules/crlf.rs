// Copyright (C) 2003-2004 Chinotec Technologies Company
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
// This file is a Rust derivative of CrlfInjectionScanRule from ascanrules
// v78 (zaproxy/zap-extensions tag ascanrules-v78). It changes the language
// and the architecture (Apache License 2.0, section 4). It is not an
// official OWASP ZAP build. The Java add-on is not included. The original
// rule carries the Paros copyright.

//! CRLF Injection. Plugin id 40003.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use zap_core::HttpResponse;
use zap_store::{Confidence, Risk};

use crate::context::{ActivePlugin, RaisedAlert, ScanContext, SendError};
use crate::variant::variants_for;

pub const CRLF_PLUGIN_ID: i32 = 40003;
pub const CRLF_NAME: &str = "CRLF Injection";

const CWE_ID: i32 = 113;
const WASC_ID: i32 = 25;

/// Port of `CrlfInjectionScanRule` (ascanrules v78).
#[derive(Clone, Debug, Default)]
pub struct CrlfInjectionScanRule;

impl ActivePlugin for CrlfInjectionScanRule {
    fn plugin_id(&self) -> i32 {
        CRLF_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        CRLF_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        if ctx.is_stopped() {
            return;
        }
        let random = format!("Tamper={}", tamper_token());
        let payloads = payloads(&random);
        for variant in variants_for(ctx.base()) {
            if ctx.is_stopped() {
                return;
            }
            for (index, param) in variant.params().iter().enumerate() {
                if ctx.is_stopped() {
                    return;
                }
                for payload in &payloads {
                    if ctx.is_stopped() {
                        return;
                    }
                    let mut msg = variant.apply(ctx.base(), index, payload);
                    match ctx.send(&mut msg) {
                        Ok(response) => {
                            if let Some(evidence) = evidence(&response, &random) {
                                ctx.raise(RaisedAlert {
                                    plugin_id: CRLF_PLUGIN_ID,
                                    name: CRLF_NAME,
                                    risk: Risk::Medium.code(),
                                    confidence: Confidence::Medium.code(),
                                    cwe_id: CWE_ID,
                                    wasc_id: WASC_ID,
                                    param: param.name.clone(),
                                    url: msg.url(),
                                    evidence,
                                    attack: payload.clone(),
                                });
                                break;
                            }
                        }
                        Err(SendError::Stopped) => return,
                        Err(SendError::Failed(err)) => {
                            tracing::debug!(%err, "crlf injection send failed");
                        }
                    }
                }
            }
        }
    }
}

fn payloads(random: &str) -> Vec<String> {
    vec![
        format!("Set-cookie: {random}"),
        format!("any\r\nSet-cookie: {random}"),
        format!("any?\r\nSet-cookie: {random}"),
        format!("any\nSet-cookie: {random}"),
        format!("any?\nSet-cookie: {random}"),
        format!("any\r\nSet-cookie: {random}\r\n"),
        format!("any?\r\nSet-cookie: {random}\r\n"),
    ]
}

fn evidence(response: &HttpResponse, random: &str) -> Option<String> {
    let header = response_header_text(response);
    let needle = format!("\nset-cookie: {random}").to_ascii_lowercase();
    let lower = header.to_ascii_lowercase();
    let index = lower.find(&needle)?;
    Some(header[index..index + needle.len()].to_string())
}

fn response_header_text(response: &HttpResponse) -> String {
    let mut out = format!("HTTP/1.1 {}\r\n", response.status);
    let headers = response.headers.clone();
    append_headers(&mut out, &headers);
    out.push_str("\r\n");
    out
}

fn append_headers(out: &mut String, headers: &HeaderMap) {
    for (name, value) in headers.iter() {
        let value = String::from_utf8_lossy(value.as_bytes());
        out.push_str(&format!("{name}: {value}\r\n"));
    }
}

fn tamper_token() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(
        "{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}",
        (nanos & 0xffff_ffff) as u32,
        ((nanos >> 32) & 0xffff) as u16,
        (n & 0x0fff) as u16,
        ((n >> 12) & 0x0fff) as u16,
        (nanos as u64) & 0x0000_ffff_ffff_ffff
    )
}
