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
// This file is a Rust derivative of the ZAP core. It is not an official
// OWASP ZAP build. Fetches are plain HTTP GETs. A browser is not started.

//! HTTP fetch used by the AJAX spider.

use bytes::Bytes;
use http::{HeaderMap, Method};
use zap_core::{HttpMessage, HttpResponse};
use zap_http::UpstreamClient;

/// One response the parsers can read.
#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Sends one GET. Implementations must not start a browser.
pub trait AjaxSender: Send + Sync {
    fn fetch(&self, url: &str) -> Result<FetchResponse, String>;
}

/// Sender backed by the default upstream client.
pub struct DefaultSender {
    client: UpstreamClient,
    handle: tokio::runtime::Handle,
}

impl DefaultSender {
    /// Build the client on the runtime that is already running.
    pub fn from_current() -> Result<Self, String> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "ajax spider needs a running tokio runtime".to_string())?;
        let client = UpstreamClient::new(&[]).map_err(|err| err.to_string())?;
        Ok(Self { client, handle })
    }
}

impl AjaxSender for DefaultSender {
    fn fetch(&self, url: &str) -> Result<FetchResponse, String> {
        let uri = url
            .parse()
            .map_err(|err: http::uri::InvalidUri| err.to_string())?;
        let mut message = HttpMessage {
            method: Method::GET,
            uri,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: None,
        };
        let response = self
            .handle
            .block_on(self.client.send(&mut message))
            .map_err(|err| err.to_string())?;
        Ok(from_http(response))
    }
}

fn from_http(response: HttpResponse) -> FetchResponse {
    let headers = response
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    FetchResponse {
        status: response.status.as_u16(),
        headers,
        body: response.body.to_vec(),
    }
}
