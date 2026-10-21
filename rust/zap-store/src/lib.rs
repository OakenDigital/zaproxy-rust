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
// official OWASP ZAP build. History, site, and alert persistence follow
// the Paros table model carried in the ZAP core.

//! SQLite session: history rows, site nodes, and alert rows.
//!
//! Not an official OWASP ZAP build. Nothing in this crate raises alerts or
//! serves the ZAP API.

#![forbid(unsafe_code)]

mod alert;
mod listener;
mod session;

pub use alert::{AlertRow, Confidence, NewAlert, Risk, UNKNOWN_CWE_ID, UNKNOWN_WASC_ID};
pub use listener::SessionHistoryListener;
pub use session::{Error, Result, Session, SiteNode};

#[cfg(test)]
mod tests;
