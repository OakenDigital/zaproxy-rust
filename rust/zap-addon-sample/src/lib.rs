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

//! Sample add-on. zapd links this crate and does not name the rule.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use zap_addon::{register_factory, Addon, ApiImplementor, Manifest};
use zap_core::{HttpMessage, HttpResponse};
use zap_pscan::{AlertThreshold, PassiveScanner};
use zap_store::{Confidence, NewAlert, Risk};

/// Add-on id. The manifest file uses the same id.
pub const ADDON_ID: &str = "sample";

/// Rule name. This string stays in this crate.
pub const RULE_NAME: &str = "Sample add-on passive rule";

/// Plugin id for [`SamplePassiveRule`]. Not a ZAP upstream id.
pub const PLUGIN_ID: i32 = 10901;

/// Response header that raises [`RULE_NAME`].
pub const HEADER_NAME: &str = "x-sample-addon";

/// API route answered by [`SampleApi`].
pub const API_PATH: &str = "/JSON/sample/view/ping/";

const MANIFEST_JSON: &str = include_str!("../sample.addon.json");

/// Path of the manifest a tester copies into the add-on directory.
pub fn manifest_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sample.addon.json")
}

/// Register this crate's factory. Safe to call more than once.
pub fn install() {
    register_factory(ADDON_ID, Arc::new(SampleAddon::create));
}

struct SampleAddon {
    manifest: Manifest,
    rule: Arc<SamplePassiveRule>,
    api: Arc<SampleApi>,
}

impl SampleAddon {
    fn create() -> Arc<dyn Addon> {
        let manifest = Manifest::parse(MANIFEST_JSON).expect("sample manifest");
        Arc::new(Self {
            manifest,
            rule: Arc::new(SamplePassiveRule::new()),
            api: Arc::new(SampleApi),
        })
    }
}

impl Addon for SampleAddon {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn passive_rules(&self) -> Vec<Arc<dyn PassiveScanner>> {
        vec![Arc::clone(&self.rule) as Arc<dyn PassiveScanner>]
    }

    fn api_implementor(&self) -> Option<Arc<dyn ApiImplementor>> {
        Some(Arc::clone(&self.api) as Arc<dyn ApiImplementor>)
    }
}

/// Passive rule shipped by the sample add-on.
pub struct SamplePassiveRule {
    threshold: AtomicU8,
}

impl SamplePassiveRule {
    pub fn new() -> Self {
        Self {
            threshold: AtomicU8::new(AlertThreshold::Default as u8),
        }
    }

    pub fn name(&self) -> &'static str {
        RULE_NAME
    }
}

impl Default for SamplePassiveRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveScanner for SamplePassiveRule {
    fn plugin_id(&self) -> i32 {
        PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        RULE_NAME
    }

    fn set_threshold(&self, threshold: AlertThreshold) {
        self.threshold.store(threshold as u8, Ordering::SeqCst);
    }

    fn is_enabled(&self) -> bool {
        self.threshold.load(Ordering::SeqCst) != AlertThreshold::Off as u8
    }

    fn scan_http_response(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        if !self.is_enabled() {
            return Vec::new();
        }
        let Some(response) = &msg.response else {
            return Vec::new();
        };
        let matched = response
            .headers
            .get(HEADER_NAME)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "ping");
        if !matched {
            return Vec::new();
        }
        vec![NewAlert {
            plugin_id: PLUGIN_ID,
            name: RULE_NAME.to_string(),
            risk: Risk::Informational.code(),
            confidence: Confidence::Medium.code(),
            cwe_id: -1,
            wasc_id: -1,
            param: HEADER_NAME.to_string(),
            url: msg.url(),
        }]
    }
}

/// `GET /JSON/sample/view/ping/` returns `{"result":"pong"}`.
pub struct SampleApi;

impl ApiImplementor for SampleApi {
    fn handle(&self, msg: &mut HttpMessage) -> bool {
        let host = msg.uri.host().unwrap_or("");
        if !host.eq_ignore_ascii_case("zap") {
            return false;
        }
        let path = msg.uri.path();
        if path != API_PATH && path != API_PATH.trim_end_matches('/') {
            return false;
        }
        let body = Bytes::from_static(br#"{"result":"pong"}"#);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        msg.response = Some(HttpResponse {
            status: StatusCode::OK,
            headers,
            body,
        });
        true
    }
}

#[cfg(test)]
mod tests;
