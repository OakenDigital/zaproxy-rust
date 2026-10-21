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
// official OWASP ZAP build. Task submission follows
// `PassiveScanController`; skipping a disabled scanner follows
// `PassiveScanTask`.

//! In-process passive-scan queue.
//!
//! A response is recorded as a task, then the enabled scanners run before
//! the listener returns. Threshold `Off` still records the task and does
//! not run that scanner, so it raises nothing.

use std::sync::{Arc, Mutex};

use zap_core::{HttpMessage, HISTORY_LISTENER_ORDER};
use zap_store::NewAlert;

use crate::scanner::PassiveScanner;
use crate::threshold::AlertThreshold;

/// Listener order. ZAP uses the history listener order plus one.
pub const PASSIVE_SCAN_LISTENER_ORDER: i32 = HISTORY_LISTENER_ORDER + 1;

/// Scanners and the responses submitted to them.
pub struct PassiveScanQueue {
    scanners: Mutex<Vec<Arc<dyn PassiveScanner>>>,
    tasks: Mutex<Vec<String>>,
}

impl PassiveScanQueue {
    pub fn new() -> Self {
        Self {
            scanners: Mutex::new(Vec::new()),
            tasks: Mutex::new(Vec::new()),
        }
    }

    pub fn add_scanner(&self, scanner: Arc<dyn PassiveScanner>) {
        self.scanners.lock().expect("pscan scanners").push(scanner);
    }

    /// Set one scanner's threshold. `Off` disables it. Unknown ids are ignored.
    pub fn set_threshold(&self, plugin_id: i32, threshold: AlertThreshold) {
        let scanners = self.scanners.lock().expect("pscan scanners");
        for scanner in scanners.iter() {
            if scanner.plugin_id() == plugin_id {
                scanner.set_threshold(threshold);
            }
        }
    }

    /// Request URLs submitted so far, in submission order.
    pub fn queued_urls(&self) -> Vec<String> {
        self.tasks.lock().expect("pscan tasks").clone()
    }

    /// Queue `msg` when it has a response, then run enabled scanners.
    ///
    /// A message with no response is not a task. Disabled scanners are
    /// skipped. The returned alerts are what the listener persists.
    pub fn scan_response(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        if msg.response.is_none() {
            return Vec::new();
        }
        self.tasks.lock().expect("pscan tasks").push(msg.url());
        let scanners = self.scanners.lock().expect("pscan scanners").clone();
        let mut alerts = Vec::new();
        for scanner in scanners {
            if scanner.is_enabled() {
                alerts.extend(scanner.scan_http_response(msg));
            }
        }
        alerts
    }
}

impl Default for PassiveScanQueue {
    fn default() -> Self {
        Self::new()
    }
}
