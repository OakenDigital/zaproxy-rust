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
// This file is a Rust derivative of the ZAP OpenAPI add-on. It changes the
// language and the architecture (Apache License 2.0, section 4). It is not
// an official OWASP ZAP build.

//! Errors from reading one local OpenAPI document.

use thiserror::Error;

/// The definition could not be turned into requests.
#[derive(Debug, Error)]
pub enum ImportError {
    /// The file or string was empty.
    #[error("openapi definition is empty")]
    Empty,
    /// JSON and YAML parsing both failed.
    #[error("openapi definition is not valid JSON or YAML: {0}")]
    Syntax(String),
    /// The document is not OpenAPI 2 (`swagger: "2.0"`) or OpenAPI 3.
    #[error("openapi definition is not OpenAPI 2 or 3")]
    Unsupported,
    /// No absolute server URL and no target override.
    #[error("openapi definition has no server URL and no target")]
    NoServer,
    /// `-openapi-target` was not an http or https URL.
    #[error("openapi target URL is not http or https: {0}")]
    BadTarget(String),
    /// A generated operation URL was not http or https.
    #[error("openapi URL is not http or https: {0}")]
    BadUrl(String),
    /// The definition file could not be read.
    #[error("{0}")]
    Read(String),
}
