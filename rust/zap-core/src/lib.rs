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

//! Message model, listener chain, URL exclusions, and in-memory history.
//!
//! Not an official OWASP ZAP build.

#![forbid(unsafe_code)]

mod exclude;
mod headers;
mod history;
mod listener;
mod message;

pub use exclude::{ExcludeError, ExcludeList};
pub use headers::{headers_for_forwarding, is_hop_by_hop, HOP_BY_HOP_HEADERS};
pub use history::{HistoryRow, InMemoryHistory};
pub use listener::{
    plan_after_request, run_request_listeners, run_response_listeners, ChainFlow, ExchangePlan,
    ProxyListener, HISTORY_LISTENER_ORDER,
};
pub use message::{HttpMessage, HttpResponse};

/// Crate version. The `zapd` binary prints the same workspace version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod version_tests {
    use super::VERSION;

    #[test]
    fn version_string_is_set() {
        assert_eq!(VERSION, "0.1.0");
    }
}
