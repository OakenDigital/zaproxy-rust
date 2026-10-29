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
// This file is a Rust derivative of the OpenAPI import in zaproxy/zap-extensions
// at openapi-v48. It changes the language and the architecture (Apache License
// 2.0, section 4). It is not an official OWASP ZAP build. The Java add-on is
// not included. Definitions are read from a local JSON or YAML file. They are
// not downloaded. There is no browser.

//! Import an OpenAPI 2 or 3 document as seed requests.
//!
//! Not an official OWASP ZAP build. Each path operation becomes one request.
//! [`ApiRequest::url`] is a traditional spider seed. [`ApiRequest::active_scan_message`]
//! is an active-scan seed: method, URL, and body match the `ascan` `scan`
//! parameters `method`, `url`, and `postData`.

#![forbid(unsafe_code)]

mod error;
mod generate;
mod import;

pub use error::ImportError;

use std::path::Path;

/// One operation from an OpenAPI document.
///
/// The spider seed list takes [`Self::url`]. The active scanner takes
/// [`Self::active_scan_message`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiRequest {
    /// HTTP method, uppercase (`GET`, `POST`, and the other OpenAPI methods).
    pub method: String,
    /// Absolute `http` or `https` URL, including substituted path and query.
    pub url: String,
    /// Request body. Empty when the operation has none.
    pub body: String,
    /// `Content-Type` when `body` is not empty.
    pub content_type: Option<String>,
    /// Header parameters from the operation. Names are as written in the file.
    pub headers: Vec<(String, String)>,
}

impl ApiRequest {
    /// URL for the traditional spider seed list.
    #[must_use]
    pub fn spider_seed(&self) -> &str {
        &self.url
    }

    /// Message for the active-scan seed (`url`, `method`, `postData`).
    #[must_use]
    pub fn active_scan_message(&self) -> zap_core::HttpMessage {
        self.http_message()
    }
}

/// Read a JSON or YAML OpenAPI 2 or 3 document.
///
/// `target`, when set, replaces every server URL. The document is not
/// fetched. Remote `$ref` values are not followed.
///
/// # Errors
///
/// Returns [`ImportError`] when the text is empty, not JSON or YAML, not
/// OpenAPI 2 or 3, or an operation has no absolute `http` or `https` base.
pub fn import_str(document: &str, target: Option<&str>) -> Result<Vec<ApiRequest>, ImportError> {
    import::import_str(document, target)
}

/// Read one local OpenAPI file. The path is not used as a URL.
///
/// # Errors
///
/// Returns [`ImportError`] when the file cannot be read or the document
/// cannot be imported. See [`import_str`].
pub fn import_path(path: &Path, target: Option<&str>) -> Result<Vec<ApiRequest>, ImportError> {
    import::import_path(path, target)
}

/// Unique operation URLs, in document order, for the spider seed list.
#[must_use]
pub fn spider_seeds(requests: &[ApiRequest]) -> Vec<String> {
    let mut seeds = Vec::new();
    for request in requests {
        if !seeds.contains(&request.url) {
            seeds.push(request.url.clone());
        }
    }
    seeds
}

#[cfg(test)]
mod tests;
