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

//! `zapd --version` prints a version and does not claim to be official ZAP.

#[test]
fn version_flag_prints_version_and_disclaimer() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zapd"))
        .arg("--version")
        .output()
        .expect("run zapd");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout was {stdout:?}"
    );
    assert!(
        stdout.contains("Not an official OWASP ZAP build."),
        "stdout was {stdout:?}"
    );
}

#[test]
fn single_dash_version_flag_works() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zapd"))
        .arg("-version")
        .output()
        .expect("run zapd");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("zapd "));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}
