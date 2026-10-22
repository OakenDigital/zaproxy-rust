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

//! PHASE-8 add-on directory.
//!
//! Installing an add-on is copying its manifest into this directory and
//! starting the process again. This module does not name add-on rules.
//! Java `.zap` files are not loaded.

use std::path::Path;
use std::sync::Arc;

use zap_addon::{AddonPassiveListener, Registry};
use zap_addon_sample::install;
use zap_core::ProxyListener;
use zap_proxy::EarlyOverride;
use zap_scanrules::install as install_scanrules;
use zap_store::Session;

/// Read the add-on directory. Linked crates register before the read.
///
/// Bundled scan-rule manifests are installed when that id is not already
/// in the directory. This function does not name those rules.
pub fn load(dir: &Path) -> Result<Registry, String> {
    install();
    install_scanrules();
    Registry::load_with_bundled(dir, zap_scanrules::bundled_manifests())
        .map_err(|err| err.to_string())
}

/// Append the listener that runs passive rules from installed add-ons.
pub fn register(
    mut listeners: Vec<Arc<dyn ProxyListener>>,
    registry: Arc<Registry>,
    session: Arc<Session>,
) -> Vec<Arc<dyn ProxyListener>> {
    listeners.push(Arc::new(AddonPassiveListener::new(registry, session)));
    listeners
}

/// Answer add-on API routes, then the previous override.
pub fn chain(inner: EarlyOverride, registry: Arc<Registry>) -> EarlyOverride {
    Arc::new(move |message| {
        if registry.handle_api(message) {
            return true;
        }
        inner(message)
    })
}

/// Startup line. It counts installed add-ons and does not name their rules.
pub fn startup_line(registry: &Registry) -> String {
    format!("Add-ons: {} installed", registry.len())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::load;

    fn temp_dir() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zapd-phase8-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn copied_manifest_is_loaded_on_the_next_start() {
        let dir = temp_dir();
        let first = load(&dir).unwrap();
        assert!(first.ids().iter().any(|id| id == "pscanrules"));
        assert!(first.ids().iter().any(|id| id == "ascanrules"));
        assert_eq!(first.api_count(), 0);
        let passive = first.passive_rule_count();
        let active = first.active_plugin_count();
        assert!(passive > 0);
        assert!(active > 0);
        std::fs::copy(
            zap_addon_sample::manifest_file(),
            dir.join("installed.addon.json"),
        )
        .unwrap();
        let second = load(&dir).unwrap();
        assert_eq!(second.len(), first.len() + 1);
        assert_eq!(second.passive_rule_count(), passive + 1);
        assert_eq!(second.active_plugin_count(), active);
        assert_eq!(second.api_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
