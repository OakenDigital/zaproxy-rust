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

//! Enabled scripts of type `proxy` and `httpsender`.

use std::sync::Mutex;

use thiserror::Error;
use zap_core::HttpMessage;

use crate::engine;

/// Script type names from `ExtensionScript`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptType {
    /// `ProxyScript`: `proxyRequest` and `proxyResponse`.
    Proxy,
    /// `HttpSenderScript`: `sendingRequest` and `responseReceived`.
    HttpSender,
}

impl ScriptType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::HttpSender => "httpsender",
        }
    }
}

/// Failure while loading or running a script.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ScriptError {
    message: String,
}

impl ScriptError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone)]
struct Installed {
    name: String,
    kind: ScriptType,
    enabled: bool,
    source: String,
}

/// Scripts invoked by the proxy listener.
pub struct ScriptHost {
    scripts: Mutex<Vec<Installed>>,
}

impl ScriptHost {
    pub fn new() -> Self {
        Self {
            scripts: Mutex::new(Vec::new()),
        }
    }

    /// Compile `source` and keep it. A top-level throw, including `Java.type`, fails here.
    pub fn add_script(
        &self,
        name: impl Into<String>,
        kind: ScriptType,
        source: &str,
    ) -> Result<(), ScriptError> {
        engine::compile_check(source)?;
        self.scripts.lock().expect("scripts").push(Installed {
            name: name.into(),
            kind,
            enabled: true,
            source: source.to_string(),
        });
        Ok(())
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) {
        for script in self.scripts.lock().expect("scripts").iter_mut() {
            if script.name == name {
                script.enabled = enabled;
            }
        }
    }

    /// Evaluate `source` without installing it.
    pub fn check_source(source: &str) -> Result<(), ScriptError> {
        engine::compile_check(source)
    }

    pub fn proxy_request(&self, msg: &mut HttpMessage) -> bool {
        self.run(ScriptType::Proxy, "proxyRequest", msg, None)
    }

    pub fn proxy_response(&self, msg: &mut HttpMessage) -> bool {
        self.run(ScriptType::Proxy, "proxyResponse", msg, None)
    }

    pub fn sending_request(&self, msg: &mut HttpMessage, initiator: i32) {
        let _ = self.run(
            ScriptType::HttpSender,
            "sendingRequest",
            msg,
            Some(initiator),
        );
    }

    pub fn response_received(&self, msg: &mut HttpMessage, initiator: i32) {
        let _ = self.run(
            ScriptType::HttpSender,
            "responseReceived",
            msg,
            Some(initiator),
        );
    }

    fn run(
        &self,
        kind: ScriptType,
        hook: &str,
        msg: &mut HttpMessage,
        initiator: Option<i32>,
    ) -> bool {
        let scripts: Vec<Installed> = self
            .scripts
            .lock()
            .expect("scripts")
            .iter()
            .filter(|script| script.enabled && script.kind == kind)
            .cloned()
            .collect();
        for script in scripts {
            match engine::invoke(&script.source, hook, msg, initiator) {
                Ok(true) => {}
                Ok(false) => return false,
                Err(err) => {
                    tracing::error!(
                        script = %script.name,
                        hook,
                        %err,
                        "script hook failed"
                    );
                }
            }
        }
        true
    }
}

impl Default for ScriptHost {
    fn default() -> Self {
        Self::new()
    }
}
