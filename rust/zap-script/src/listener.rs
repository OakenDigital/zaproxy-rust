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
// official OWASP ZAP build. Listener order follows Paros `ProxyListener`
// as carried by ZAP `ProxyListenerScript`.

//! Proxy listener that runs `proxy` and `httpsender` scripts.
//!
//! On the way out: `proxyRequest`, then `sendingRequest`. On the way back:
//! `responseReceived`, then `proxyResponse`. That is the order a proxied
//! message sees in ZAP, where the sender hooks run inside the origin send
//! and the proxy hooks run in the listener chain. `proxyRequest` returning
//! false skips the sender hooks and the origin.

use std::sync::Arc;

use zap_core::{HttpMessage, ProxyListener, HISTORY_LISTENER_ORDER};

use crate::host::ScriptHost;

/// `HttpSender.PROXY_INITIATOR`.
pub const PROXY_INITIATOR: i32 = 1;

/// `ProxyListenerScript.PROXY_LISTENER_ORDER` (history order minus two).
pub const PROXY_SCRIPT_LISTENER_ORDER: i32 = HISTORY_LISTENER_ORDER - 2;

/// Registers the script hooks on the proxy listener chain.
pub struct ScriptProxyListener {
    host: Arc<ScriptHost>,
}

impl ScriptProxyListener {
    pub fn new(host: Arc<ScriptHost>) -> Self {
        Self { host }
    }

    pub fn host(&self) -> &Arc<ScriptHost> {
        &self.host
    }
}

impl ProxyListener for ScriptProxyListener {
    fn order(&self) -> i32 {
        PROXY_SCRIPT_LISTENER_ORDER
    }

    fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool {
        if !self.host.proxy_request(msg) {
            return false;
        }
        self.host.sending_request(msg, PROXY_INITIATOR);
        true
    }

    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
        self.host.response_received(msg, PROXY_INITIATOR);
        self.host.proxy_response(msg)
    }
}
