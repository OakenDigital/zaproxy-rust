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

//! JavaScript host for the `proxy` and `httpsender` script types.
//!
//! Not an official OWASP ZAP build. The engine is Boa. Hook names match
//! `ProxyScript` and `HttpSenderScript` in the ZAP core. The message object
//! is the narrow surface below, not the Java `HttpMessage` class.
//!
//! ```javascript
//! msg.url
//! msg.method
//! msg.requestHeader(name)
//! msg.setRequestHeader(name, value)
//! msg.responseHeader(name)
//! msg.setResponseHeader(name, value)
//! msg.responseStatus
//! msg.requestBody
//! msg.responseBody
//! msg.setResponse(status, body)
//! ```
//!
//! `proxyRequest` and `proxyResponse` return boolean. `false` stops later
//! proxy scripts and the rest of that side of the listener chain.
//! `sendingRequest` and `responseReceived` take `(msg, initiator, helper)`.
//! `helper` is an empty object. Initiator `1` is the proxy.

#![forbid(unsafe_code)]

mod engine;
mod host;
mod listener;

pub use host::{ScriptError, ScriptHost, ScriptType};
pub use listener::{ScriptProxyListener, PROXY_INITIATOR, PROXY_SCRIPT_LISTENER_ORDER};

/// Sample script that rewrites one request header and one response header.
///
/// Load it once as [`ScriptType::Proxy`] and once as [`ScriptType::HttpSender`].
pub const SAMPLE_REWRITE_SCRIPT: &str = include_str!("../scripts/rewrite-headers.js");

/// Why the Docker httpsender script `AlertOnHttpResponseCodeErrors.js` does not run.
///
/// The script is the community-scripts file packaged scans load. Boa is not a
/// JVM, so evaluation stops on Nashorn/Graal `Java.type` before either hook
/// is called. The calls that never run are `Java.type("java.lang.Integer")`,
/// `Java.type("java.util.regex.Pattern")`,
/// `Java.type("org.parosproxy.paros.core.scanner.Alert")`,
/// `Java.type("org.zaproxy.zap.extension.alert.ExtensionAlert")`, and
/// `Java.type("org.parosproxy.paros.model.HistoryReference")`, plus the ZAP
/// globals `control` and `model` and `extensionAlert.alertFound`.
pub const ALERT_ON_HTTP_RESPONSE_CODE_ERRORS_GAP: &str = "\
AlertOnHttpResponseCodeErrors.js does not run: Boa has no Nashorn/Graal \
Java.type host object. Evaluation fails on Java.type(\"java.lang.Integer\"), \
Java.type(\"java.util.regex.Pattern\"), \
Java.type(\"org.parosproxy.paros.core.scanner.Alert\"), \
Java.type(\"org.zaproxy.zap.extension.alert.ExtensionAlert\"), and \
Java.type(\"org.parosproxy.paros.model.HistoryReference\"). The script also \
reads the ZAP globals control and model and calls extensionAlert.alertFound. \
sendingRequest and responseReceived exist, and this script never reaches them.\
";

#[cfg(test)]
mod tests;
