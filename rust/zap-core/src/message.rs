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
// official OWASP ZAP build. The message shape follows the Paros HTTP model
// carried in the ZAP core.

//! One proxied exchange: request, optional response, bodies, and headers.

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};

/// Response bytes attached to an [`HttpMessage`].
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A request that may already carry a listener-supplied response.
///
/// When `response` is `Some` before the origin is contacted, the proxy skips
/// the origin. Listeners share this value and may mutate either side.
#[derive(Clone, Debug)]
pub struct HttpMessage {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub response: Option<HttpResponse>,
}

impl HttpMessage {
    /// Absolute URL string used for exclusions and history.
    pub fn url(&self) -> String {
        self.uri.to_string()
    }
}
