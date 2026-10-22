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

//! Manifest parsing, dependency resolution, and directory install.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use zap_core::HttpMessage;
use zap_pscan::{AlertThreshold, PassiveScanner};
use zap_store::NewAlert;

use crate::{register_factory, Addon, AddonError, ApiImplementor, Manifest, Registry};

struct Echo {
    manifest: Manifest,
    rules: usize,
    api: bool,
}

struct NopRule;

impl PassiveScanner for NopRule {
    fn plugin_id(&self) -> i32 {
        1
    }

    fn set_threshold(&self, _threshold: AlertThreshold) {}

    fn is_enabled(&self) -> bool {
        true
    }

    fn scan_http_response(&self, _msg: &HttpMessage) -> Vec<NewAlert> {
        Vec::new()
    }
}

struct NopApi;

impl ApiImplementor for NopApi {
    fn handle(&self, _msg: &mut HttpMessage) -> bool {
        false
    }
}

impl Addon for Echo {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn passive_rules(&self) -> Vec<Arc<dyn PassiveScanner>> {
        (0..self.rules)
            .map(|_| Arc::new(NopRule) as Arc<dyn PassiveScanner>)
            .collect()
    }

    fn api_implementor(&self) -> Option<Arc<dyn ApiImplementor>> {
        self.api
            .then(|| Arc::new(NopApi) as Arc<dyn ApiImplementor>)
    }
}

fn register_echo(json: &str) {
    let manifest = Manifest::parse(json).unwrap();
    let id = manifest.id.clone();
    register_factory(
        id,
        Arc::new(move || {
            Arc::new(Echo {
                manifest: manifest.clone(),
                rules: 1,
                api: true,
            })
        }),
    );
}

fn expect_err(result: Result<Registry, AddonError>) -> AddonError {
    match result {
        Ok(_) => panic!("expected an add-on error"),
        Err(err) => err,
    }
}

fn temp_dir() -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-addon-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn manifest_parses_id_version_and_semver_dependencies() {
    let manifest = Manifest::parse(
        r#"{"id":"child","version":"1.2.3","dependencies":[{"id":"parent","version":"^1.0.0"}]}"#,
    )
    .unwrap();
    assert_eq!(manifest.id, "child");
    assert_eq!(manifest.version.to_string(), "1.2.3");
    assert_eq!(manifest.dependencies.len(), 1);
    assert_eq!(manifest.dependencies[0].id, "parent");
    assert!(manifest.dependencies[0]
        .requirement
        .matches(&semver::Version::parse("1.4.0").unwrap()));
    assert!(!manifest.dependencies[0]
        .requirement
        .matches(&semver::Version::parse("2.0.0").unwrap()));
}

#[test]
fn manifest_rejects_bad_version_and_id() {
    assert!(Manifest::parse(r#"{"id":"ok","version":"nope"}"#).is_err());
    assert!(Manifest::parse(r#"{"id":"","version":"1.0.0"}"#).is_err());
    assert!(Manifest::parse(r#"{"id":"-bad","version":"1.0.0"}"#).is_err());
    assert!(Manifest::parse(r#"{"id":"ok","version":"1.0.0","dependencies":{}}"#).is_err());
}

#[test]
fn dependencies_install_in_order_when_versions_match() {
    let parent = r#"{"id":"phase8-parent","version":"1.2.0"}"#;
    let child = r#"{"id":"phase8-child","version":"0.1.0","dependencies":[{"id":"phase8-parent","version":"^1.0.0"}]}"#;
    register_echo(parent);
    register_echo(child);
    let registry = Registry::from_manifests(vec![
        Manifest::parse(child).unwrap(),
        Manifest::parse(parent).unwrap(),
    ])
    .unwrap();
    assert_eq!(
        registry.ids(),
        vec!["phase8-parent".to_string(), "phase8-child".to_string()]
    );
    assert_eq!(registry.passive_rule_count(), 2);
    assert_eq!(registry.api_count(), 2);
}

#[test]
fn missing_incompatible_cycle_and_duplicate_dependencies_fail() {
    let missing = Registry::from_manifests(vec![Manifest::parse(
        r#"{"id":"phase8-lonely","version":"1.0.0","dependencies":[{"id":"phase8-absent","version":"=1.0.0"}]}"#,
    )
    .unwrap()]);
    assert!(matches!(
        expect_err(missing),
        AddonError::MissingDependency { .. }
    ));

    register_echo(r#"{"id":"phase8-old","version":"1.0.0"}"#);
    let incompatible = Registry::from_manifests(vec![
        Manifest::parse(r#"{"id":"phase8-old","version":"1.0.0"}"#).unwrap(),
        Manifest::parse(
            r#"{"id":"phase8-needs-new","version":"1.0.0","dependencies":[{"id":"phase8-old","version":"^2.0.0"}]}"#,
        )
        .unwrap(),
    ]);
    assert!(matches!(
        expect_err(incompatible),
        AddonError::Incompatible { .. }
    ));

    let cycle = Registry::from_manifests(vec![
        Manifest::parse(
            r#"{"id":"phase8-a","version":"1.0.0","dependencies":[{"id":"phase8-b","version":"^1"}]}"#,
        )
        .unwrap(),
        Manifest::parse(
            r#"{"id":"phase8-b","version":"1.0.0","dependencies":[{"id":"phase8-a","version":"^1"}]}"#,
        )
        .unwrap(),
    ]);
    assert!(matches!(expect_err(cycle), AddonError::Cycle(_)));

    let duplicate = Registry::from_manifests(vec![
        Manifest::parse(r#"{"id":"phase8-dup","version":"1.0.0"}"#).unwrap(),
        Manifest::parse(r#"{"id":"phase8-dup","version":"1.0.1"}"#).unwrap(),
    ]);
    assert!(matches!(expect_err(duplicate), AddonError::Duplicate(_)));
}

#[test]
fn unregistered_id_and_manifest_mismatch_fail() {
    let missing = Registry::from_manifests(vec![Manifest::parse(
        r#"{"id":"phase8-nobody","version":"1.0.0"}"#,
    )
    .unwrap()]);
    assert!(matches!(expect_err(missing), AddonError::Unregistered(_)));

    register_factory(
        "phase8-mismatch",
        Arc::new(|| {
            Arc::new(Echo {
                manifest: Manifest::parse(r#"{"id":"phase8-mismatch","version":"1.0.0"}"#).unwrap(),
                rules: 0,
                api: false,
            })
        }),
    );
    let installed = Manifest::parse(r#"{"id":"phase8-mismatch","version":"2.0.0"}"#).unwrap();
    assert!(matches!(
        expect_err(Registry::from_manifests(vec![installed])),
        AddonError::Mismatch { .. }
    ));
}

#[test]
fn java_zap_file_is_rejected_and_other_files_are_ignored() {
    let dir = temp_dir();
    std::fs::write(dir.join("notes.txt"), "ignore").unwrap();
    std::fs::write(dir.join("legacy.zap"), "PK").unwrap();
    let err = expect_err(Registry::load(&dir));
    assert!(matches!(err, AddonError::JavaZap { .. }), "{err}");
    assert!(err.to_string().contains("Java .zap"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restart_picks_up_a_copied_manifest() {
    let json = r#"{"id":"phase8-copied","version":"1.0.0"}"#;
    register_echo(json);
    let dir = temp_dir();
    let before = Registry::load(&dir).unwrap();
    assert!(before.is_empty());
    std::fs::write(dir.join("phase8-copied.addon.json"), json).unwrap();
    let after = Registry::load(&dir).unwrap();
    assert_eq!(after.ids(), vec!["phase8-copied".to_string()]);
    assert_eq!(after.passive_rule_count(), 1);
    assert_eq!(after.api_count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
