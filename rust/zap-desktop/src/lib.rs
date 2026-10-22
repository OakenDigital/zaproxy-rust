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

//! Optional desktop over the proxy.
//!
//! Not an official OWASP ZAP build. The `zap-desktop` binary serves a local
//! page for sites, history, request and response text, alerts, and
//! intercept/break forward or drop. From that page a person can start a
//! traditional spider crawl and an active scan. Alerts from both show up
//! in the alerts list. The AJAX spider is not included. `zapd` does not
//! depend on this crate and still runs with the desktop disabled. Syntax
//! coloring is not included.
//!
//! Break was left out of the proxy milestone. It lives here as a listener
//! the desktop binary registers. A held request is not sent until Forward.
//! Drop skips the origin. A held response is not recorded until Forward.
//! Drop clears it so the client does not receive the origin bytes.

#![forbid(unsafe_code)]

mod breakpoint;
mod launch;
mod scans;
mod ui;
mod view;

#[cfg(test)]
mod tests;

pub use breakpoint::{BreakListener, BreakSide, Breakpoint, BREAK_LISTENER_ORDER};
pub use launch::{launch, DesktopConfig, RunningDesktop};
pub use view::{snapshot, MessageText, Snapshot};
