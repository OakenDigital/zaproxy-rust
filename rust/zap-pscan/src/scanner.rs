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

//! Passive scanner invoked by the response queue.

use zap_core::HttpMessage;
use zap_store::NewAlert;

use crate::threshold::AlertThreshold;

/// One passive rule.
///
/// The queue calls [`PassiveScanner::scan_http_response`] only when
/// [`PassiveScanner::is_enabled`] is true. `Off` makes `is_enabled` false.
pub trait PassiveScanner: Send + Sync {
    fn plugin_id(&self) -> i32;

    fn set_threshold(&self, threshold: AlertThreshold);

    fn is_enabled(&self) -> bool;

    /// Alerts raised for this response. An empty body or a non-matching
    /// response returns an empty list. The rule does not write the session.
    fn scan_http_response(&self, msg: &HttpMessage) -> Vec<NewAlert>;
}
