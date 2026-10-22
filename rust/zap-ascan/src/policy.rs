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
// official OWASP ZAP build. The names match `Plugin.AlertThreshold` and
// `Plugin.AttackStrength`.

//! Strength and threshold for one active-scan policy.
//!
//! `Off` disables a rule. `Default` resolves to medium, which is the
//! scanner default. A per-plugin threshold overrides the policy threshold.

use std::collections::HashMap;

/// Alert threshold. `Off` means the rule is not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertThreshold {
    Off,
    Default,
    Low,
    Medium,
    High,
}

impl AlertThreshold {
    pub fn resolved(self) -> Self {
        match self {
            Self::Default => Self::Medium,
            other => other,
        }
    }

    pub fn enables_scanner(self) -> bool {
        self.resolved() != Self::Off
    }
}

/// Attack strength passed to each rule on the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackStrength {
    Default,
    Low,
    Medium,
    High,
    Insane,
}

impl AttackStrength {
    pub fn resolved(self) -> Self {
        match self {
            Self::Default => Self::Medium,
            other => other,
        }
    }
}

/// Default policy: medium strength, medium threshold, both rules enabled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub strength: AttackStrength,
    pub threshold: AlertThreshold,
    plugin_threshold: HashMap<i32, AlertThreshold>,
}

impl Policy {
    pub fn new(strength: AttackStrength, threshold: AlertThreshold) -> Self {
        Self {
            strength,
            threshold,
            plugin_threshold: HashMap::new(),
        }
    }

    pub fn set_plugin_threshold(&mut self, plugin_id: i32, threshold: AlertThreshold) {
        self.plugin_threshold.insert(plugin_id, threshold);
    }

    pub fn enables(&self, plugin_id: i32) -> bool {
        self.plugin_threshold
            .get(&plugin_id)
            .copied()
            .unwrap_or(self.threshold)
            .enables_scanner()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new(AttackStrength::Medium, AlertThreshold::Medium)
    }
}
