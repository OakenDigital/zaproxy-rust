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

//! Errors from reading a manifest or a directory.

use std::io;

/// A manifest file could not be parsed.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ParseError(pub String);

/// Loading an add-on directory failed.
#[derive(Debug, thiserror::Error)]
pub enum AddonError {
    #[error("cannot read add-on directory {path}: {source}")]
    Directory { path: String, source: io::Error },
    #[error("cannot read {path}: {source}")]
    File { path: String, source: io::Error },
    #[error("{path}: {source}")]
    Manifest { path: String, source: ParseError },
    #[error("Java .zap add-ons are not loaded ({name})")]
    JavaZap { name: String },
    #[error("duplicate add-on id {0}")]
    Duplicate(String),
    #[error("add-on {addon} requires {dependency} {requirement}, which is not installed")]
    MissingDependency {
        addon: String,
        dependency: String,
        requirement: String,
    },
    #[error("add-on {addon} requires {dependency} {requirement}, but {installed} is installed")]
    Incompatible {
        addon: String,
        dependency: String,
        requirement: String,
        installed: String,
    },
    #[error("add-on dependency cycle at {0}")]
    Cycle(String),
    #[error("no implementation registered for add-on {0}")]
    Unregistered(String),
    #[error("installed manifest for {id} does not match the linked add-on")]
    Mismatch { id: String },
}
