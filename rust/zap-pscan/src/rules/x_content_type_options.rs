// Copyright 2012 The ZAP Development Team
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
// This file is a Rust derivative of XContentTypeOptionsScanRule from
// pscanrules v70 (zaproxy/zap-extensions tag pscanrules-v70). It changes
// the language and the architecture (Apache License 2.0, section 4). It is
// not an official OWASP ZAP build. The Java add-on is not included.

//! X-Content-Type-Options passive rule. Plugin id 10021.
//!
//! A non-empty response body with no header value containing `nosniff`
//! raises one low-risk alert per such value. At medium, high, and the
//! default threshold, client errors, server errors, and redirects are
//! skipped. Low includes them. `Off` is applied by the queue, which does
//! not call this rule.

use zap_core::HttpMessage;
use zap_store::{Confidence, NewAlert, Risk};

use crate::scanner::PassiveScanner;
use crate::threshold::{AlertThreshold, ScannerState};

/// Plugin id from pscanrules v70 `XContentTypeOptionsScanRule`.
pub const PLUGIN_ID: i32 = 10021;

/// Alert name from pscanrules v70.
pub const RULE_NAME: &str = "X-Content-Type-Options Header Missing";

/// Header name and alert param. Matches `HttpHeader.X_CONTENT_TYPE_OPTIONS`.
pub const HEADER_NAME: &str = "x-content-type-options";

const CWE_ID: i32 = 693;
const WASC_ID: i32 = 15;

/// Port of `XContentTypeOptionsScanRule` (pscanrules v70).
pub struct XContentTypeOptionsScanRule {
    state: ScannerState,
}

impl XContentTypeOptionsScanRule {
    /// Default threshold, which resolves to medium.
    pub fn new() -> Self {
        Self::with_threshold(AlertThreshold::Default)
    }

    pub fn with_threshold(threshold: AlertThreshold) -> Self {
        Self {
            state: ScannerState::new(threshold),
        }
    }

    fn alert(&self, msg: &HttpMessage) -> NewAlert {
        NewAlert {
            plugin_id: PLUGIN_ID,
            name: RULE_NAME.to_string(),
            risk: Risk::Low.code(),
            confidence: Confidence::Medium.code(),
            cwe_id: CWE_ID,
            wasc_id: WASC_ID,
            param: HEADER_NAME.to_string(),
            url: msg.url(),
        }
    }
}

impl Default for XContentTypeOptionsScanRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveScanner for XContentTypeOptionsScanRule {
    fn plugin_id(&self) -> i32 {
        PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        RULE_NAME
    }

    fn set_threshold(&self, threshold: AlertThreshold) {
        self.state.set_threshold(threshold);
    }

    fn is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    fn scan_http_response(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = &msg.response else {
            return Vec::new();
        };
        if response.body.is_empty() {
            return Vec::new();
        }
        let include_error_redirect = self.state.resolved() == AlertThreshold::Low;
        let status = response.status.as_u16();
        if !include_error_redirect && is_error_or_redirect(status) {
            return Vec::new();
        }
        let values = header_values(&response.headers);
        if values.is_empty() {
            return vec![self.alert(msg)];
        }
        values
            .into_iter()
            .filter(|value| !value.to_ascii_lowercase().contains("nosniff"))
            .map(|_| self.alert(msg))
            .collect()
    }
}

/// Client error, server error, or redirect. Matches `HttpStatusCode` and the
/// passive-scan helper used by this rule when no custom pages are configured.
fn is_error_or_redirect(status: u16) -> bool {
    (300..400).contains(&status) || (400..500).contains(&status) || status >= 500
}

fn header_values(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all(HEADER_NAME)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect()
}
