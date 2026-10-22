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
// official OWASP ZAP build. The JSON shape follows the ZAP API at
// http://zap/JSON/.

//! `http://zap/JSON/` routes for `core`, `alert`, and the packaged-scan
//! subset (`pscan`, `ascan` scanners, `context`, `users`, `script`).
//!
//! Not an official OWASP ZAP build. This crate does not start a scan and
//! does not add scan rules. Active scan `scan`, `status`, and `stop`, and
//! the spider `scan` and `status` routes, stay in the daemon.

#![forbid(unsafe_code)]

mod meta;
mod service;

pub use service::ApiService;

/// Routes this build serves. Paths are absolute API URLs on the proxy.
pub const ROUTES: &[&str] = &[
    "GET http://zap/JSON/core/view/version/",
    "GET http://zap/JSON/core/view/hosts/",
    "GET http://zap/JSON/core/view/messages/",
    "GET http://zap/JSON/core/view/urls/",
    "GET http://zap/JSON/core/view/alerts/",
    "GET http://zap/JSON/core/view/message/?id=",
    "GET http://zap/JSON/core/view/numberOfMessages/",
    "GET http://zap/JSON/core/action/shutdown/",
    "GET http://zap/JSON/alert/view/alerts/",
    "GET http://zap/JSON/alert/view/alert/?id=",
    "GET http://zap/JSON/pscan/view/scanners/",
    "GET http://zap/JSON/pscan/view/recordsToScan/",
    "GET http://zap/JSON/pscan/action/disableAllTags/",
    "GET http://zap/JSON/pscan/action/setMaxAlertsPerRule/?maxAlerts=",
    "GET http://zap/JSON/ascan/view/scanners/",
    "GET http://zap/JSON/ascan/view/scanProgress/",
    "GET http://zap/JSON/ascan/action/enableAllScanners/",
    "GET http://zap/JSON/ascan/action/setScannerAlertThreshold/?id=&alertThreshold=",
    "GET http://zap/JSON/ascan/action/scanAsUser/",
    "GET http://zap/JSON/context/view/contextList/",
    "GET http://zap/JSON/context/action/importContext/?contextFile=",
    "GET http://zap/JSON/users/view/usersList/",
    "GET http://zap/JSON/script/view/listEngines/",
    "GET http://zap/JSON/script/action/load/",
    "GET http://zap/JSON/script/action/enable/",
];

#[cfg(test)]
mod tests;
