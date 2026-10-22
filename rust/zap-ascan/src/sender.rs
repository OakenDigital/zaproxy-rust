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

//! HTTP sender used by an active scan.
//!
//! [`DefaultSender`] is the process client from `zap-http`. It does not
//! attach a user or run a login.

use zap_core::{HttpMessage, HttpResponse};
use zap_http::UpstreamClient;

/// Sends one attack or baseline request.
pub trait ScanSender: Send + Sync {
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String>;
}

/// Scan sender backed by the default upstream client.
pub struct DefaultSender {
    client: UpstreamClient,
    handle: tokio::runtime::Handle,
}

impl DefaultSender {
    /// Build the client on the runtime that is already running.
    pub fn from_current() -> Result<Self, String> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "active scan needs a running tokio runtime".to_string())?;
        let client = UpstreamClient::new(&[]).map_err(|err| err.to_string())?;
        Ok(Self { client, handle })
    }
}

impl ScanSender for DefaultSender {
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        self.handle
            .block_on(self.client.send(msg))
            .map_err(|err| err.to_string())
    }
}
