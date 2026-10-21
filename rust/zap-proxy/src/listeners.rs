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
// official OWASP ZAP build.

//! Built-in listeners: a log line, and the in-memory history row.

use std::sync::Arc;

use zap_core::{HttpMessage, InMemoryHistory, ProxyListener, HISTORY_LISTENER_ORDER};

/// Logs the method, URL, and response status. Does not modify the message.
pub struct LoggingListener {
    order: i32,
}

impl LoggingListener {
    pub fn new(order: i32) -> Self {
        Self { order }
    }
}

impl Default for LoggingListener {
    fn default() -> Self {
        Self::new(0)
    }
}

impl ProxyListener for LoggingListener {
    fn order(&self) -> i32 {
        self.order
    }

    fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool {
        tracing::info!(method = %msg.method, url = %msg.url(), "proxy request");
        true
    }

    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
        let status = msg
            .response
            .as_ref()
            .map(|response| response.status.as_u16());
        tracing::info!(url = %msg.url(), ?status, "proxy response");
        true
    }
}

/// Records one history row when the response chain reaches this order.
pub struct HistoryListener {
    history: Arc<InMemoryHistory>,
}

impl HistoryListener {
    pub fn new(history: Arc<InMemoryHistory>) -> Self {
        Self { history }
    }
}

impl ProxyListener for HistoryListener {
    fn order(&self) -> i32 {
        HISTORY_LISTENER_ORDER
    }

    fn on_http_request_send(&self, _msg: &mut HttpMessage) -> bool {
        true
    }

    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
        self.history.record(msg);
        true
    }
}
