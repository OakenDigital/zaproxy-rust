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

//! Directory registry. A copied manifest is visible on the next load.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use zap_ascan::ActivePlugin;
use zap_core::HttpMessage;
use zap_pscan::PassiveScanner;

use crate::error::AddonError;
use crate::manifest::Manifest;

/// Builds one linked add-on. Registered by the add-on crate, not by zapd.
pub type Factory = Arc<dyn Fn() -> Arc<dyn Addon> + Send + Sync>;

/// A first-party add-on. The daemon sees only this trait.
pub trait Addon: Send + Sync {
    fn manifest(&self) -> &Manifest;

    fn passive_rules(&self) -> Vec<Arc<dyn PassiveScanner>>;

    /// Active rules contributed by this add-on. The default is none.
    fn active_plugins(&self) -> Vec<Arc<dyn ActivePlugin>> {
        Vec::new()
    }

    fn api_implementor(&self) -> Option<Arc<dyn ApiImplementor>>;
}

/// JSON API implementor contributed by an add-on.
pub trait ApiImplementor: Send + Sync {
    /// Return true when this implementor answered `msg`.
    fn handle(&self, msg: &mut HttpMessage) -> bool;
}

fn factories() -> &'static Mutex<HashMap<String, Factory>> {
    static FACTORIES: OnceLock<Mutex<HashMap<String, Factory>>> = OnceLock::new();
    FACTORIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register the factory for `id`. A later registration replaces the earlier one.
pub fn register_factory(id: impl Into<String>, factory: Factory) {
    factories()
        .lock()
        .expect("addon factories")
        .insert(id.into(), factory);
}

/// Add-ons installed in one directory.
#[derive(Default)]
pub struct Registry {
    addons: Vec<Arc<dyn Addon>>,
}

impl Registry {
    /// Read `dir`, creating it when it is missing.
    ///
    /// `*.addon.json` files are manifests. A file whose name ends in `.zap`
    /// is an error. Any other file is ignored. Calling this again after a
    /// manifest is copied is the restart that picks the add-on up.
    pub fn load(dir: &Path) -> Result<Self, AddonError> {
        Self::load_with_bundled(dir, Vec::new())
    }

    /// Read `dir`, then add `bundled` manifests whose ids are not already there.
    ///
    /// A copied manifest with the same id wins, so a directory install is not
    /// registered twice.
    pub fn load_with_bundled(dir: &Path, bundled: Vec<Manifest>) -> Result<Self, AddonError> {
        let mut manifests = Self::read_manifests(dir)?;
        let present: HashSet<String> = manifests
            .iter()
            .map(|manifest| manifest.id.clone())
            .collect();
        for manifest in bundled {
            if !present.contains(&manifest.id) {
                manifests.push(manifest);
            }
        }
        Self::from_manifests(manifests)
    }

    pub fn active_plugins(&self) -> Vec<Arc<dyn ActivePlugin>> {
        self.addons
            .iter()
            .flat_map(|addon| addon.active_plugins())
            .collect()
    }

    pub fn active_plugin_count(&self) -> usize {
        self.active_plugins().len()
    }

    fn read_manifests(dir: &Path) -> Result<Vec<Manifest>, AddonError> {
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|source| AddonError::Directory {
                path: dir.display().to_string(),
                source,
            })?;
        }
        let entries = fs::read_dir(dir).map_err(|source| AddonError::Directory {
            path: dir.display().to_string(),
            source,
        })?;
        let mut manifests = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| AddonError::Directory {
                path: dir.display().to_string(),
                source,
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .to_string();
            if name.to_ascii_lowercase().ends_with(".zap") {
                return Err(AddonError::JavaZap { name });
            }
            if !name.ends_with(".addon.json") {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(|source| AddonError::File {
                path: path.display().to_string(),
                source,
            })?;
            let manifest = Manifest::parse(&text)
                .map_err(|source| AddonError::Manifest { path: name, source })?;
            manifests.push(manifest);
        }
        Ok(manifests)
    }

    /// Resolve `manifests` and instantiate registered factories.
    pub fn from_manifests(manifests: Vec<Manifest>) -> Result<Self, AddonError> {
        let ordered = resolve(&manifests)?;
        let map = factories().lock().expect("addon factories");
        let mut addons = Vec::with_capacity(ordered.len());
        for manifest in ordered {
            let factory = map
                .get(&manifest.id)
                .ok_or_else(|| AddonError::Unregistered(manifest.id.clone()))?;
            let addon = factory();
            if addon.manifest() != &manifest {
                return Err(AddonError::Mismatch {
                    id: manifest.id.clone(),
                });
            }
            addons.push(addon);
        }
        Ok(Self { addons })
    }

    pub fn len(&self) -> usize {
        self.addons.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addons.is_empty()
    }

    pub fn ids(&self) -> Vec<String> {
        self.addons
            .iter()
            .map(|addon| addon.manifest().id.clone())
            .collect()
    }

    pub fn passive_rules(&self) -> Vec<Arc<dyn PassiveScanner>> {
        self.addons
            .iter()
            .flat_map(|addon| addon.passive_rules())
            .collect()
    }

    pub fn passive_rule_count(&self) -> usize {
        self.passive_rules().len()
    }

    pub fn api_count(&self) -> usize {
        self.addons
            .iter()
            .filter(|addon| addon.api_implementor().is_some())
            .count()
    }

    /// Offer `msg` to each add-on API implementor.
    pub fn handle_api(&self, msg: &mut HttpMessage) -> bool {
        for addon in &self.addons {
            if let Some(api) = addon.api_implementor() {
                if api.handle(msg) {
                    return true;
                }
            }
        }
        false
    }
}

fn resolve(manifests: &[Manifest]) -> Result<Vec<Manifest>, AddonError> {
    let mut by_id = HashMap::new();
    for manifest in manifests {
        if by_id
            .insert(manifest.id.clone(), manifest.clone())
            .is_some()
        {
            return Err(AddonError::Duplicate(manifest.id.clone()));
        }
    }
    let mut ids: Vec<String> = by_id.keys().cloned().collect();
    ids.sort();
    let mut visiting = HashSet::new();
    let mut done = HashSet::new();
    let mut ordered = Vec::with_capacity(ids.len());
    for id in &ids {
        visit(id, &by_id, &mut visiting, &mut done, &mut ordered)?;
    }
    Ok(ordered)
}

fn visit(
    id: &str,
    by_id: &HashMap<String, Manifest>,
    visiting: &mut HashSet<String>,
    done: &mut HashSet<String>,
    ordered: &mut Vec<Manifest>,
) -> Result<(), AddonError> {
    if done.contains(id) {
        return Ok(());
    }
    if !visiting.insert(id.to_string()) {
        return Err(AddonError::Cycle(id.to_string()));
    }
    let manifest = by_id.get(id).expect("visit is only called for known ids");
    for dependency in &manifest.dependencies {
        let Some(installed) = by_id.get(&dependency.id) else {
            return Err(AddonError::MissingDependency {
                addon: id.to_string(),
                dependency: dependency.id.clone(),
                requirement: dependency.requirement.to_string(),
            });
        };
        if !dependency.requirement.matches(&installed.version) {
            return Err(AddonError::Incompatible {
                addon: id.to_string(),
                dependency: dependency.id.clone(),
                requirement: dependency.requirement.to_string(),
                installed: installed.version.to_string(),
            });
        }
        visit(&dependency.id, by_id, visiting, done, ordered)?;
    }
    visiting.remove(id);
    done.insert(id.to_string());
    ordered.push(manifest.clone());
    Ok(())
}
