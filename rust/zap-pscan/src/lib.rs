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

//! Passive-scan queue and one header rule.
//!
//! Not an official OWASP ZAP build. The queue runs on the proxy response
//! path. The shipped rule is X-Content-Type-Options, plugin id 10021, from
//! pscanrules v70. The Java add-on is not included. There is no authentication
//! and no active scan.

#![forbid(unsafe_code)]

mod listener;
mod queue;
mod rules;
mod scanner;
mod threshold;

pub use listener::PassiveScanListener;
pub use queue::{PassiveScanQueue, PASSIVE_SCAN_LISTENER_ORDER};
pub use rules::x_content_type_options::{
    XContentTypeOptionsScanRule, HEADER_NAME, PLUGIN_ID, RULE_NAME,
};
pub use scanner::PassiveScanner;
pub use threshold::{AlertThreshold, ScannerState};

#[cfg(test)]
mod tests;
