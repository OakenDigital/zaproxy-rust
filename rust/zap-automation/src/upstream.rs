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
// This file is a Rust derivative of the ZAP automation framework. It changes
// the language and the architecture (Apache License 2.0, section 4). It is
// not an official OWASP ZAP build. There is no JDK and no browser.

//! Request sender backed by the default upstream client.

use tokio::runtime::Handle;
use zap_core::{HttpMessage, HttpResponse};
use zap_http::UpstreamClient;

use crate::error::{self, Error};
use crate::RequestSender;

/// Sends plan requests with [`UpstreamClient`].
///
/// Build this on a running tokio runtime. Call [`RequestSender::send`] from
/// a worker thread: `Handle::block_on` must not run on the runtime thread.
pub struct UpstreamRequestSender {
    client: UpstreamClient,
    handle: Handle,
}

impl UpstreamRequestSender {
    /// Client for the runtime that is already running.
    pub fn from_current() -> Result<Self, Error> {
        let handle = Handle::try_current()
            .map_err(|_| error::plan("automation requestor needs a running tokio runtime"))?;
        let client = UpstreamClient::new(&[]).map_err(|err| Error::Engine(err.to_string()))?;
        Ok(Self { client, handle })
    }
}

impl RequestSender for UpstreamRequestSender {
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        self.handle
            .block_on(self.client.send(msg))
            .map_err(|err| err.to_string())
    }
}
