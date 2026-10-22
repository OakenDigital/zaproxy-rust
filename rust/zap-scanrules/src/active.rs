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
// Server Side Include follows ascanrules v78 and carries the Paros
// copyright. Format String follows ascanrules v78. The Java add-on is not
// included. This is not an official OWASP ZAP build.
//
// Java limits Server Side Include to Linux, Mac, and Windows, and Format
// String to Tech.C. This port has no technology set, so both rules run on
// every query, form, and JSON parameter.

//! Active rules that inject into the existing parameter variants.

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use zap_core::HttpMessage;
use zap_store::{Confidence, Risk};

use zap_ascan::{variants_for, ActivePlugin, RaisedAlert, ScanContext, SendError, Variant};

pub const SSI_PLUGIN_ID: i32 = 40009;
pub const SSI_NAME: &str = "Server Side Include";
pub const FORMAT_PLUGIN_ID: i32 = 30002;
pub const FORMAT_NAME: &str = "Format String Error";

const SSI_UNIX: &str = "<!--#EXEC cmd=\"ls /\"-->";
const SSI_WIN: &str = "<!--#EXEC cmd=\"dir \\\"-->";

/// Port of `ServerSideIncludeScanRule` (ascanrules v78).
#[derive(Clone, Debug, Default)]
pub struct ServerSideIncludeScanRule;

impl ActivePlugin for ServerSideIncludeScanRule {
    fn plugin_id(&self) -> i32 {
        SSI_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        SSI_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        if ctx.is_stopped() {
            return;
        }
        let unix_known = evidence(ctx.base_body(), unix_pattern()).is_some();
        let win_known = evidence(ctx.base_body(), win_pattern()).is_some();
        for variant in variants_for(ctx.base()) {
            if ctx.is_stopped() {
                return;
            }
            for (index, param) in variant.params().iter().enumerate() {
                if ctx.is_stopped() {
                    return;
                }
                if !unix_known {
                    match ssi_payloads(
                        ctx,
                        &variant,
                        index,
                        &param.name,
                        &[SSI_UNIX, &unix_wrapped()],
                        unix_pattern(),
                    ) {
                        Step::NextParam => continue,
                        Step::Stop => return,
                        Step::NextPayload => {}
                    }
                }
                if !win_known
                    && ssi_payloads(
                        ctx,
                        &variant,
                        index,
                        &param.name,
                        &[SSI_WIN, &win_wrapped()],
                        win_pattern(),
                    ) == Step::Stop
                {
                    return;
                }
            }
        }
    }
}

/// Port of `FormatStringScanRule` (ascanrules v78).
#[derive(Clone, Debug, Default)]
pub struct FormatStringScanRule;

impl ActivePlugin for FormatStringScanRule {
    fn plugin_id(&self) -> i32 {
        FORMAT_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        FORMAT_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        if ctx.is_stopped() || is_status(ctx.base(), 500) {
            return;
        }
        for variant in variants_for(ctx.base()) {
            if ctx.is_stopped() {
                return;
            }
            for (index, param) in variant.params().iter().enumerate() {
                if ctx.is_stopped() {
                    return;
                }
                scan_format(ctx, &variant, index, &param.name);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    NextPayload,
    NextParam,
    Stop,
}

fn ssi_payloads(
    ctx: &ScanContext<'_>,
    variant: &Variant,
    index: usize,
    param: &str,
    payloads: &[&str],
    pattern: &Regex,
) -> Step {
    for payload in payloads {
        match try_ssi(ctx, variant, index, param, payload, pattern) {
            Step::NextPayload => {}
            other => return other,
        }
    }
    Step::NextPayload
}

fn try_ssi(
    ctx: &ScanContext<'_>,
    variant: &Variant,
    index: usize,
    param: &str,
    payload: &str,
    pattern: &Regex,
) -> Step {
    if ctx.is_stopped() {
        return Step::Stop;
    }
    let mut msg = variant.apply(ctx.base(), index, payload);
    match ctx.send(&mut msg) {
        Ok(response) => {
            let body = String::from_utf8_lossy(&response.body);
            if let Some(found) = evidence(&body, pattern) {
                ctx.raise(raised(
                    SSI_PLUGIN_ID,
                    SSI_NAME,
                    Risk::High.code(),
                    Confidence::Medium.code(),
                    97,
                    31,
                    param,
                    &msg.url(),
                    &found,
                    payload,
                ));
                Step::NextParam
            } else {
                Step::NextPayload
            }
        }
        Err(SendError::Stopped) => Step::Stop,
        Err(SendError::Failed(_)) => Step::NextParam,
    }
}

fn scan_format(ctx: &ScanContext<'_>, variant: &Variant, index: usize, param: &str) {
    let mut probe = variant.apply(ctx.base(), index, "ZAP");
    let initial = match ctx.send(&mut probe) {
        Ok(response) => response,
        Err(SendError::Stopped) => return,
        Err(SendError::Failed(_)) => return,
    };
    if initial.status.as_u16() == 500 {
        return;
    }
    let initial_len = initial.body.len();
    let gnu = gnu_payload();
    let mut gnu_msg = variant.apply(ctx.base(), index, &gnu);
    let gnu_response = match ctx.send(&mut gnu_msg) {
        Ok(response) => response,
        Err(SendError::Stopped) => return,
        Err(SendError::Failed(_)) => return,
    };
    if gnu_response.status.as_u16() == 500 {
        let verify = verify_payload();
        let mut verify_msg = variant.apply(ctx.base(), index, &verify);
        match ctx.send(&mut verify_msg) {
            Ok(response) => {
                let confirmed =
                    response.body.len() > initial_len + 20 && response.status.as_u16() == 200;
                let (attack, url) = if confirmed {
                    (verify, verify_msg.url())
                } else {
                    (gnu, gnu_msg.url())
                };
                raise_format(ctx, param, &attack, &url);
            }
            Err(SendError::Stopped | SendError::Failed(_)) => {}
        }
        return;
    }
    if ctx.is_stopped() {
        return;
    }
    let microsoft = microsoft_payload();
    let mut microsoft_msg = variant.apply(ctx.base(), index, &microsoft);
    match ctx.send(&mut microsoft_msg) {
        Ok(response) if response.status.as_u16() == 500 => {
            raise_format(ctx, param, &microsoft, &microsoft_msg.url());
        }
        Ok(_) => {}
        Err(SendError::Stopped | SendError::Failed(_)) => {}
    }
}

fn raise_format(ctx: &ScanContext<'_>, param: &str, attack: &str, url: &str) {
    ctx.raise(raised(
        FORMAT_PLUGIN_ID,
        FORMAT_NAME,
        Risk::Medium.code(),
        Confidence::Medium.code(),
        134,
        6,
        param,
        url,
        "",
        attack,
    ));
}

fn is_status(msg: &HttpMessage, status: u16) -> bool {
    msg.response
        .as_ref()
        .is_some_and(|response| response.status.as_u16() == status)
}

fn gnu_payload() -> String {
    let mut payload = String::from("ZAP");
    for _ in 0..20 {
        payload.push_str("%n%s");
    }
    payload.push('\n');
    payload
}

fn verify_payload() -> String {
    let mut payload = String::from("ZAP");
    for _ in 0..10 {
        payload.push_str("%x");
    }
    payload.push('\n');
    payload
}

fn microsoft_payload() -> String {
    let mut payload = String::from("ZAP ");
    for index in 1..=20 {
        payload.push_str(&format!("%{index}!s"));
    }
    for index in 21..=40 {
        payload.push_str(&format!("%{index}!n"));
    }
    payload.push('\n');
    payload
}

fn unix_wrapped() -> String {
    format!("\">{SSI_UNIX}<")
}

fn win_wrapped() -> String {
    format!("\">{SSI_WIN}<")
}

fn evidence(body: &str, pattern: &Regex) -> Option<String> {
    pattern.find(body).map(|found| found.as_str().to_string())
}

fn unix_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| pattern(r"\broot\b.*\busr\b"))
}

fn win_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| pattern(r"\bprogram files\b.*\b(WINDOWS|WINNT)\b"))
}

fn pattern(source: &str) -> Regex {
    RegexBuilder::new(source)
        .case_insensitive(true)
        .multi_line(true)
        .dot_matches_new_line(true)
        .build()
        .expect("scan pattern")
}

#[allow(clippy::too_many_arguments)]
fn raised(
    plugin_id: i32,
    name: &'static str,
    risk: i32,
    confidence: i32,
    cwe_id: i32,
    wasc_id: i32,
    param: &str,
    url: &str,
    evidence: &str,
    attack: &str,
) -> RaisedAlert {
    RaisedAlert {
        plugin_id,
        name,
        risk,
        confidence,
        cwe_id,
        wasc_id,
        param: param.to_string(),
        url: url.to_string(),
        evidence: evidence.to_string(),
        attack: attack.to_string(),
    }
}
