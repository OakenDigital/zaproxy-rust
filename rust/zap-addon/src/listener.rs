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

//! Response listener for passive rules contributed by installed add-ons.

use std::sync::Arc;

use zap_core::{HttpMessage, ProxyListener};
use zap_store::Session;

use crate::registry::Registry;

/// One after the built-in passive scan listener (5001).
pub const ADDON_LISTENER_ORDER: i32 = 5_002;

/// Runs every installed add-on passive rule and stores its alerts.
pub struct AddonPassiveListener {
    registry: Arc<Registry>,
    session: Arc<Session>,
}

impl AddonPassiveListener {
    pub fn new(registry: Arc<Registry>, session: Arc<Session>) -> Self {
        Self { registry, session }
    }
}

impl ProxyListener for AddonPassiveListener {
    fn order(&self) -> i32 {
        ADDON_LISTENER_ORDER
    }

    fn on_http_request_send(&self, _msg: &mut HttpMessage) -> bool {
        true
    }

    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
        for rule in self.registry.passive_rules() {
            if !rule.is_enabled() {
                continue;
            }
            for alert in rule.scan_http_response(msg) {
                if let Err(err) = self.session.insert_alert(&alert) {
                    tracing::error!(%err, plugin_id = alert.plugin_id, "add-on passive alert write failed");
                }
            }
        }
        true
    }
}
