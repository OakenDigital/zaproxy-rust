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

//! Active scan engine.
//!
//! Not an official OWASP ZAP build. Variants cover URL query, form body,
//! and JSON. One host process runs the enabled rules with a strength, a
//! threshold, and a stop flag. The rules from ascanrules v78 are CRLF
//! Injection (40003), XPath Injection (90021), reflected XSS (40012), SQL
//! injection (40018), and directory browsing (0). The Java add-on is not
//! included. Scans use the caller-supplied sender; `zapd` passes the
//! default client. There is no forced user and no login.

#![forbid(unsafe_code)]

mod api;
mod coding;
mod context;
mod engine;
mod policy;
mod rules;
mod sender;
mod variant;

pub use api::ActiveScanService;
pub use context::{ActivePlugin, RaisedAlert, ScanContext, SendError};
pub use engine::{host_key, Engine, ScanOptions};
pub use policy::{AlertThreshold, AttackStrength, Policy};
pub use rules::{
    CrlfInjectionScanRule, CrossSiteScriptingScanRule, DirectoryBrowsingScanRule,
    SqlInjectionScanRule, XpathInjectionScanRule, CRLF_NAME, CRLF_PLUGIN_ID, DIRECTORY_NAME,
    DIRECTORY_PLUGIN_ID, SQLI_NAME, SQLI_PLUGIN_ID, XPATH_NAME, XPATH_PLUGIN_ID, XSS_NAME,
    XSS_PLUGIN_ID,
};
pub use sender::{DefaultSender, ScanSender};
pub use variant::{variants_for, Variant};

#[cfg(test)]
mod tests;
