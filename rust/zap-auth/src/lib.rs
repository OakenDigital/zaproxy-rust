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

//! Context regexes, form and JSON authentication, and cookie sessions.
//!
//! Not an official OWASP ZAP build. Sending the authenticated request is
//! `zap_http::UpstreamClient::send_as_user`. There is no active scan and no
//! script host here.

#![forbid(unsafe_code)]

mod auth;
mod config;
mod context;
mod cookies;
mod user;

pub use auth::{LoginKind, PASSWORD_TOKEN, USERNAME_TOKEN};
pub use config::ContextConfig;
pub use context::Context;
pub use user::User;

/// Phase 5 surface printed by `zapd` at startup.
pub const PHASE5: &str =
    "context include/exclude regexes, form and JSON authentication, cookie sessions, send-as-user";

/// Failure loading a context or building a user.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid context regex `{pattern}`: {source}")]
    Regex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("context config: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests;
