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

//! Add-on manifest and registry.
//!
//! Not an official OWASP ZAP build. A manifest records an id, a semver
//! version, and semver dependencies. Installing an add-on is copying its
//! manifest into a directory; the next process start reads that directory.
//! Java `.zap` files are rejected. Dynamic cdylib and Wasm loading are not
//! implemented. First-party crates register a factory; the daemon does not
//! name their rules.

#![forbid(unsafe_code)]

mod error;
mod listener;
mod manifest;
mod registry;

pub use error::{AddonError, ParseError};
pub use listener::{AddonPassiveListener, ADDON_LISTENER_ORDER};
pub use manifest::{Dependency, Manifest};
pub use registry::{register_factory, Addon, ApiImplementor, Factory, Registry};

#[cfg(test)]
mod tests;
