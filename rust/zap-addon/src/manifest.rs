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
// official OWASP ZAP build. The fields follow ZAP's add-on id, version,
// and dependency list. The file format is JSON, not a Java `.zap` archive.

//! Id, semver version, and semver dependencies.

use semver::{Version, VersionReq};

use crate::error::ParseError;

/// One required add-on. `requirement` is a Cargo-style semver requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    pub id: String,
    pub requirement: VersionReq,
}

/// Manifest copied into the add-on directory to install an add-on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub id: String,
    pub version: Version,
    pub dependencies: Vec<Dependency>,
}

impl Manifest {
    /// Parse a JSON manifest. Unknown fields are ignored.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|err| ParseError(err.to_string()))?;
        let id = required_string(&value, "id")?;
        validate_id(id)?;
        let version = required_string(&value, "version")?;
        let version = Version::parse(version)
            .map_err(|err| ParseError(format!("version {version}: {err}")))?;
        let dependencies = match value.get("dependencies") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .map(parse_dependency)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(ParseError("dependencies must be an array".to_string())),
        };
        Ok(Self {
            id: id.to_string(),
            version,
            dependencies,
        })
    }
}

fn parse_dependency(value: &serde_json::Value) -> Result<Dependency, ParseError> {
    let id = required_string(value, "id")?;
    validate_id(id)?;
    let requirement = required_string(value, "version")?;
    let requirement = VersionReq::parse(requirement)
        .map_err(|err| ParseError(format!("dependency {id} version {requirement}: {err}")))?;
    Ok(Dependency {
        id: id.to_string(),
        requirement,
    })
}

fn required_string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, ParseError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| ParseError(format!("missing {key}")))
}

fn validate_id(id: &str) -> Result<(), ParseError> {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return Err(ParseError("missing id".to_string()));
    };
    if first.is_ascii_alphanumeric()
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        Ok(())
    } else {
        Err(ParseError(format!("invalid add-on id {id}")))
    }
}
