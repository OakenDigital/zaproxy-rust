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

//! PHASE-7 startup for the script host.
//!
//! Boa runs script types `proxy` and `httpsender`. The listener calls
//! `proxyRequest` then `sendingRequest` on the way out, and
//! `responseReceived` then `proxyResponse` on the way back.
//! `AlertOnHttpResponseCodeErrors.js` is not loaded: it needs `Java.type`.

use std::sync::Arc;

use zap_proxy::ProxyListener;
use zap_script::{ScriptHost, ScriptProxyListener, ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP};

/// Append the script proxy listener and return the host so a file can be loaded later.
pub fn register(
    mut listeners: Vec<Arc<dyn ProxyListener>>,
) -> (Vec<Arc<dyn ProxyListener>>, Arc<ScriptHost>) {
    let host = Arc::new(ScriptHost::new());
    listeners.push(Arc::new(ScriptProxyListener::new(Arc::clone(&host))));
    (listeners, host)
}

pub fn log_startup() {
    println!("Scripts: proxy and httpsender (boa). {ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP}");
}
