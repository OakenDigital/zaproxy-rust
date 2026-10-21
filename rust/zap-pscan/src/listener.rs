// Copyright 2010-2024 The ZAP Development Team
// Copyright (C) 2003-2004 Chinotec Technologies Company
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
// official OWASP ZAP build. Running on the response path follows the Paros
// `ProxyListener` contract carried in the ZAP core.

//! Proxy listener that submits each response to the passive-scan queue.

use std::sync::Arc;

use zap_core::{HttpMessage, ProxyListener};
use zap_store::Session;

use crate::queue::{PassiveScanQueue, PASSIVE_SCAN_LISTENER_ORDER};
use crate::rules::x_content_type_options::XContentTypeOptionsScanRule;
use crate::threshold::AlertThreshold;

/// Response-path passive scan. Order is history plus one, so the exchange
/// is already stored when a rule reads the message.
pub struct PassiveScanListener {
    queue: PassiveScanQueue,
    session: Arc<Session>,
}

impl PassiveScanListener {
    /// Queue with the X-Content-Type-Options rule at the default threshold.
    pub fn new(session: Arc<Session>) -> Self {
        let queue = PassiveScanQueue::new();
        queue.add_scanner(Arc::new(XContentTypeOptionsScanRule::new()));
        Self { queue, session }
    }

    pub fn set_threshold(&self, plugin_id: i32, threshold: AlertThreshold) {
        self.queue.set_threshold(plugin_id, threshold);
    }

    pub fn queued_urls(&self) -> Vec<String> {
        self.queue.queued_urls()
    }
}

impl ProxyListener for PassiveScanListener {
    fn order(&self) -> i32 {
        PASSIVE_SCAN_LISTENER_ORDER
    }

    fn on_http_request_send(&self, _msg: &mut HttpMessage) -> bool {
        true
    }

    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
        for alert in self.queue.scan_response(msg) {
            if let Err(err) = self.session.insert_alert(&alert) {
                tracing::error!(%err, url = %msg.url(), "passive scan alert write failed");
            } else {
                tracing::debug!(
                    plugin_id = alert.plugin_id,
                    url = %alert.url,
                    "passive scan alert"
                );
            }
        }
        true
    }
}
