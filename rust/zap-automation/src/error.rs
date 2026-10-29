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
// This file is a Rust derivative of the ZAP automation framework. It changes
// the language and the architecture (Apache License 2.0, section 4). It is
// not an official OWASP ZAP build. There is no JDK and no browser.

//! Errors from reading a plan or running one of its jobs.

use std::path::PathBuf;

/// Failure while reading a plan or running a job.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The plan file could not be read.
    #[error("read {path}: {source}")]
    Read {
        /// Path that could not be read.
        path: String,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// The YAML is not a plan this runner can execute.
    #[error("plan: {0}")]
    Plan(String),
    /// One job failed.
    #[error("job {job}: {message}")]
    Job {
        /// Job type, such as `requestor`.
        job: String,
        /// What failed.
        message: String,
    },
    /// A report or summary file could not be written.
    #[error("write {path}: {source}")]
    Write {
        /// Path that could not be written.
        path: PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// An in-process engine returned an error.
    #[error("{0}")]
    Engine(String),
}

pub(crate) fn plan(message: impl Into<String>) -> Error {
    Error::Plan(message.into())
}

pub(crate) fn job(kind: &str, message: impl Into<String>) -> Error {
    Error::Job {
        job: kind.to_string(),
        message: message.into(),
    }
}
