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
// This file is a Rust derivative of pscanrules v70 and ascanrules v78
// (zaproxy/zap-extensions). It changes the language and the architecture
// (Apache License 2.0, section 4). It is not an official OWASP ZAP build.
// The Java add-ons are not included.

//! Scan rules registered through the add-on registry.
//!
//! Not an official OWASP ZAP build. `pscanrules` 70.0.0 and `ascanrules`
//! 78.0.0 match the versions pinned in `zap/src/main/main-add-ons.yml`.
//! The daemon loads the manifests bundled here and does not name the rules.
//! Plugin 10021, 40003, and 90021 stay in their existing crates.

#![forbid(unsafe_code)]

mod active;
mod cookies;
mod msg;
mod passive;

use std::sync::Arc;

use zap_addon::{register_factory, Addon, ApiImplementor, Manifest};
use zap_ascan::ActivePlugin;
use zap_pscan::PassiveScanner;

pub use active::{
    FormatStringScanRule, ServerSideIncludeScanRule, FORMAT_NAME, FORMAT_PLUGIN_ID, SSI_NAME,
    SSI_PLUGIN_ID,
};
pub use passive::{
    AntiClickjackingScanRule, ContentTypeMissingScanRule, CookieHttpOnlyScanRule,
    CookieSameSiteScanRule, CookieSecureFlagScanRule, ServerHeaderInfoLeakScanRule,
    XAspNetVersionScanRule, XPoweredByHeaderInfoLeakScanRule, CLICKJACK_ID, CONTENT_TYPE_ID,
    COOKIE_HTTPONLY_ID, COOKIE_SAMESITE_ID, COOKIE_SECURE_ID, SERVER_HEADER_ID, X_ASPNET_ID,
    X_POWERED_BY_ID,
};

const PSCAN_MANIFEST: &str = include_str!("../pscanrules.addon.json");
const ASCAN_MANIFEST: &str = include_str!("../ascanrules.addon.json");

/// Register both add-on factories. Calling this again replaces them.
pub fn install() {
    register_factory("pscanrules", Arc::new(|| Arc::new(PscanAddon::new())));
    register_factory("ascanrules", Arc::new(|| Arc::new(AscanAddon::new())));
}

/// Manifests installed on every start when the directory does not already
/// contain that id.
pub fn bundled_manifests() -> Vec<Manifest> {
    vec![pscan_manifest(), ascan_manifest()]
}

fn pscan_manifest() -> Manifest {
    Manifest::parse(PSCAN_MANIFEST).expect("pscanrules manifest")
}

fn ascan_manifest() -> Manifest {
    Manifest::parse(ASCAN_MANIFEST).expect("ascanrules manifest")
}

struct PscanAddon {
    manifest: Manifest,
}

impl PscanAddon {
    fn new() -> Self {
        Self {
            manifest: pscan_manifest(),
        }
    }
}

impl Addon for PscanAddon {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn passive_rules(&self) -> Vec<Arc<dyn PassiveScanner>> {
        vec![
            Arc::new(CookieHttpOnlyScanRule::new()),
            Arc::new(CookieSecureFlagScanRule::new()),
            Arc::new(CookieSameSiteScanRule::new()),
            Arc::new(ContentTypeMissingScanRule::new()),
            Arc::new(AntiClickjackingScanRule::new()),
            Arc::new(ServerHeaderInfoLeakScanRule::new()),
            Arc::new(XPoweredByHeaderInfoLeakScanRule::new()),
            Arc::new(XAspNetVersionScanRule::new()),
        ]
    }

    fn api_implementor(&self) -> Option<Arc<dyn ApiImplementor>> {
        None
    }
}

struct AscanAddon {
    manifest: Manifest,
}

impl AscanAddon {
    fn new() -> Self {
        Self {
            manifest: ascan_manifest(),
        }
    }
}

impl Addon for AscanAddon {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn passive_rules(&self) -> Vec<Arc<dyn PassiveScanner>> {
        Vec::new()
    }

    fn active_plugins(&self) -> Vec<Arc<dyn ActivePlugin>> {
        vec![
            Arc::new(ServerSideIncludeScanRule),
            Arc::new(FormatStringScanRule),
        ]
    }

    fn api_implementor(&self) -> Option<Arc<dyn ApiImplementor>> {
        None
    }
}

#[cfg(test)]
mod tests;
