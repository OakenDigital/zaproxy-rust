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
// This file is a Rust derivative of DirectoryBrowsingScanRule from
// ascanrules v78 and carries the Paros copyright. It changes the language
// and the architecture (Apache License 2.0, section 4). It is not an
// official OWASP ZAP build. The Java add-on is not included.

//! Active directory browsing. Plugin id 0.
//!
//! One request is sent to the same path with the query removed and a
//! trailing slash. There is no technology filter, so IIS, Apache, and the
//! general patterns are all in scope.

use std::sync::OnceLock;

use http::Uri;
use regex::{Regex, RegexBuilder};
use zap_store::{Confidence, Risk};

use crate::context::{ActivePlugin, RaisedAlert, ScanContext, SendError};

pub const DIRECTORY_PLUGIN_ID: i32 = 0;
pub const DIRECTORY_NAME: &str = "Directory Browsing";

const CWE_ID: i32 = 548;
const WASC_ID: i32 = 48;

/// Port of active `DirectoryBrowsingScanRule` (ascanrules v78).
#[derive(Clone, Debug, Default)]
pub struct DirectoryBrowsingScanRule;

impl ActivePlugin for DirectoryBrowsingScanRule {
    fn plugin_id(&self) -> i32 {
        DIRECTORY_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        DIRECTORY_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        if ctx.is_stopped() {
            return;
        }
        let Some(target) = directory_target(&ctx.base().uri) else {
            return;
        };
        let mut msg = ctx.base().clone();
        msg.uri = target;
        let attack = msg.url();
        let response = match ctx.send(&mut msg) {
            Ok(response) => response,
            Err(SendError::Stopped | SendError::Failed(_)) => return,
        };
        if !response.status.is_success() {
            return;
        }
        let body = String::from_utf8_lossy(&response.body);
        let Some((confidence, evidence)) = listing(&body) else {
            return;
        };
        ctx.raise(RaisedAlert {
            plugin_id: DIRECTORY_PLUGIN_ID,
            name: DIRECTORY_NAME,
            risk: Risk::Medium.code(),
            confidence: confidence.code(),
            cwe_id: CWE_ID,
            wasc_id: WASC_ID,
            param: String::new(),
            url: attack.clone(),
            evidence,
            attack,
        });
    }
}

fn directory_target(uri: &Uri) -> Option<Uri> {
    let path = uri.path();
    let path = if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    };
    let mut url = String::new();
    url.push_str(uri.scheme_str()?);
    url.push_str("://");
    url.push_str(uri.authority()?.as_str());
    url.push_str(&path);
    url.parse().ok()
}

fn listing(body: &str) -> Option<(Confidence, String)> {
    if let Some(found) = iis_parent().find(body) {
        return Some((Confidence::Medium, found.as_str().to_string()));
    }
    if let Some(found) = apache_listing().find(body) {
        return Some((Confidence::Medium, found.as_str().to_string()));
    }
    if let Some(found) = general_parent().find(body) {
        return Some((Confidence::Low, found.as_str().to_string()));
    }
    if general_directory().is_match(body) && general_img().is_match(body) {
        let found = general_directory().find(body)?;
        return Some((Confidence::Low, found.as_str().to_string()));
    }
    None
}

fn iis_parent() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| build("Parent Directory"))
}

fn apache_listing() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| build(r"\bDirectory Listing\b.*(Tomcat|Apache)"))
}

fn general_parent() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| build("Parent directory"))
}

fn general_directory() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| build(r"\bDirectory\b"))
}

fn general_img() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| build(r"[\s<]+IMG\s*="))
}

fn build(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .multi_line(true)
        .build()
        .expect("directory browsing pattern")
}
