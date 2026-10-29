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
// This file is a Rust derivative of CrossSiteScriptingScanRule from
// ascanrules v78 (zaproxy/zap-extensions tag ascanrules-v78). It changes
// the language and the architecture (Apache License 2.0, section 4). It
// is not an official OWASP ZAP build. The Java add-on is not included.

//! Reflected cross-site scripting. Plugin id 40012.
//!
//! The eye-catcher, direct script payload, and header-split checks follow
//! the rule. Attribute, comment, and script-context breakouts that need
//! `HtmlContextAnalyser` are not included. There is no browser.

use http::Method;
use zap_store::{Confidence, Risk};

use crate::coding::form_encode;
use crate::context::{ActivePlugin, RaisedAlert, ScanContext, SendError};
use crate::variant::variants_for;

pub const XSS_PLUGIN_ID: i32 = 40012;
pub const XSS_NAME: &str = "Cross Site Scripting (Reflected)";

const CWE_ID: i32 = 79;
const WASC_ID: i32 = 8;
const EYE_CATCHER: &str = "0W45pz4p";
const SCRIPT_ALERT: &str = "<scrIpt>alert(1);</scRipt>";
const ONERROR_ALERT: &str = "<img src=x onerror=prompt()>";
const IMG_ONERROR_LOG: &str = "<img src=x onerror=console.log(1);>";
const MOUSE_ALERT: &str = "<b onMouseOver=alert(1);>test</b>";
const SVG_ALERT: &str = "<svg onload=alert(1)>";
const HEADER_SPLIT: &str = "\n\r\n\r";

/// Port of the reflected checks in `CrossSiteScriptingScanRule`.
#[derive(Clone, Debug, Default)]
pub struct CrossSiteScriptingScanRule;

impl ActivePlugin for CrossSiteScriptingScanRule {
    fn plugin_id(&self) -> i32 {
        XSS_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        XSS_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        if ctx.is_stopped() || ctx.base().method == Method::PUT {
            return;
        }
        let outside = outside_payloads();
        for variant in variants_for(ctx.base()) {
            if ctx.is_stopped() {
                return;
            }
            for (index, param) in variant.params().iter().enumerate() {
                if ctx.is_stopped() {
                    return;
                }
                let reflected = reflect_eye(ctx, &variant, index, &param.value);
                if ctx.is_stopped() {
                    return;
                }
                let mut raised = false;
                if reflected {
                    for payload in &outside {
                        match attack(ctx, &variant, index, &param.name, payload) {
                            Step::Raised => {
                                raised = true;
                                break;
                            }
                            Step::Stop => return,
                            Step::Next => {}
                        }
                    }
                } else {
                    for payload in [SCRIPT_ALERT, &null_script(), ONERROR_ALERT] {
                        let attack_value = format!("'\"{payload}");
                        match attack(ctx, &variant, index, &param.name, &attack_value) {
                            Step::Raised => {
                                raised = true;
                                break;
                            }
                            Step::Stop => return,
                            Step::Next => {}
                        }
                    }
                }
                if raised || ctx.is_stopped() {
                    return;
                }
                if header_reflects_eye(ctx, &variant, index, &param.value) {
                    let prefix = if reflected {
                        String::new()
                    } else {
                        param.value.clone()
                    };
                    for payload in [SCRIPT_ALERT, &null_script(), ONERROR_ALERT] {
                        let attack_value = format!("{prefix}{HEADER_SPLIT}{payload}");
                        match attack(ctx, &variant, index, &param.name, &attack_value) {
                            Step::Raised | Step::Stop => return,
                            Step::Next => {}
                        }
                    }
                }
            }
        }
    }
}

enum Step {
    Raised,
    Stop,
    Next,
}

fn outside_payloads() -> Vec<String> {
    vec![
        SCRIPT_ALERT.to_string(),
        null_script(),
        ONERROR_ALERT.to_string(),
        IMG_ONERROR_LOG.to_string(),
        MOUSE_ALERT.to_string(),
        SVG_ALERT.to_string(),
        form_encode(SCRIPT_ALERT),
    ]
}

fn null_script() -> String {
    format!("\0{SCRIPT_ALERT}")
}

fn reflect_eye(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    value: &str,
) -> bool {
    if send_contains(ctx, variant, index, EYE_CATCHER) {
        return true;
    }
    send_contains(ctx, variant, index, &format!("{value}{EYE_CATCHER}"))
}

fn header_reflects_eye(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    value: &str,
) -> bool {
    header_contains(ctx, variant, index, EYE_CATCHER)
        || header_contains(ctx, variant, index, &format!("{value}{EYE_CATCHER}"))
}

fn send_contains(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    payload: &str,
) -> bool {
    if ctx.is_stopped() {
        return false;
    }
    let mut msg = variant.apply(ctx.base(), index, payload);
    match ctx.send(&mut msg) {
        Ok(response) => {
            let body = String::from_utf8_lossy(&response.body);
            contains_token(&body, payload) || contains_token(&body, EYE_CATCHER)
        }
        Err(SendError::Stopped | SendError::Failed(_)) => false,
    }
}

fn header_contains(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    payload: &str,
) -> bool {
    if ctx.is_stopped() {
        return false;
    }
    let mut msg = variant.apply(ctx.base(), index, payload);
    match ctx.send(&mut msg) {
        Ok(response) => response.headers.iter().any(|(_, value)| {
            value
                .to_str()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(&payload.to_ascii_lowercase())
        }),
        Err(SendError::Stopped | SendError::Failed(_)) => false,
    }
}

fn attack(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    param: &str,
    payload: &str,
) -> Step {
    if ctx.is_stopped() {
        return Step::Stop;
    }
    if ctx.base_body().contains(payload) {
        return Step::Next;
    }
    let mut msg = variant.apply(ctx.base(), index, payload);
    match ctx.send(&mut msg) {
        Ok(response) => {
            let body = String::from_utf8_lossy(&response.body);
            if body.contains(payload) {
                ctx.raise(RaisedAlert {
                    plugin_id: XSS_PLUGIN_ID,
                    name: XSS_NAME,
                    risk: Risk::High.code(),
                    confidence: Confidence::Medium.code(),
                    cwe_id: CWE_ID,
                    wasc_id: WASC_ID,
                    param: param.to_string(),
                    url: msg.url(),
                    evidence: payload.to_string(),
                    attack: payload.to_string(),
                });
                Step::Raised
            } else {
                Step::Next
            }
        }
        Err(SendError::Stopped) => Step::Stop,
        Err(SendError::Failed(_)) => Step::Next,
    }
}

fn contains_token(body: &str, token: &str) -> bool {
    body.contains(token)
        || body
            .to_ascii_lowercase()
            .contains(&token.to_ascii_lowercase())
}
