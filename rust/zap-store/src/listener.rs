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
// official OWASP ZAP build. Recording on the response path follows Paros
// `ProxyListenerLog`.

//! Proxy listener that writes each completed exchange to the session.

use std::sync::Arc;

use zap_core::{HttpMessage, ProxyListener, HISTORY_LISTENER_ORDER};

use crate::Session;

/// Persists the exchange when the response chain reaches history order.
///
/// A write error is logged and the chain continues, so the client still
/// receives the response. The in-memory history listener uses the same
/// order and is registered after this one by the proxy.
pub struct SessionHistoryListener {
    session: Arc<Session>,
}

impl SessionHistoryListener {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }
}

impl ProxyListener for SessionHistoryListener {
    fn order(&self) -> i32 {
        HISTORY_LISTENER_ORDER
    }

    fn on_http_request_send(&self, _msg: &mut HttpMessage) -> bool {
        true
    }

    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
        if let Err(err) = self.session.record_exchange(msg) {
            tracing::error!(%err, url = %msg.url(), "session history write failed");
        }
        true
    }
}
