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

//! Rules ported from ascanrules v78. The Java add-on is not vendored.

mod crlf;
mod xpath;

pub use crlf::{CrlfInjectionScanRule, CRLF_NAME, CRLF_PLUGIN_ID};
pub use xpath::{XpathInjectionScanRule, XPATH_NAME, XPATH_PLUGIN_ID};
