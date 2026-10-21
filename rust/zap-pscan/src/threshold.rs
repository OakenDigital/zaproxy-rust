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
// official OWASP ZAP build. The variants match
// `org.parosproxy.paros.core.scanner.Plugin.AlertThreshold`.

//! Alert threshold for a passive scanner.
//!
//! `Off` means the scanner is not used. `Default` resolves to medium, which
//! is the default on `PluginPassiveScanner`.

use std::sync::atomic::{AtomicU8, Ordering};

/// Threshold stored on a passive scanner.
///
/// Discriminant values are local. ZAP compares these by name, not by the
/// risk integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertThreshold {
    Off = 0,
    Default = 1,
    Low = 2,
    Medium = 3,
    High = 4,
}

impl AlertThreshold {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Off,
            1 => Self::Default,
            2 => Self::Low,
            3 => Self::Medium,
            4 => Self::High,
            _ => Self::Medium,
        }
    }

    /// `Default` is medium. Every other variant is itself.
    pub fn resolved(self) -> Self {
        match self {
            Self::Default => Self::Medium,
            other => other,
        }
    }
}

/// Threshold and the enabled bit derived from it.
///
/// Setting `Off` disables the scanner. Any other threshold enables it. That
/// is `ExtensionPassiveScan.setPluginPassiveScannerAlertThreshold`.
pub struct ScannerState {
    threshold: AtomicU8,
}

impl ScannerState {
    pub fn new(threshold: AlertThreshold) -> Self {
        Self {
            threshold: AtomicU8::new(threshold as u8),
        }
    }

    pub fn threshold(&self) -> AlertThreshold {
        AlertThreshold::from_u8(self.threshold.load(Ordering::SeqCst))
    }

    pub fn set_threshold(&self, threshold: AlertThreshold) {
        self.threshold.store(threshold as u8, Ordering::SeqCst);
    }

    pub fn resolved(&self) -> AlertThreshold {
        self.threshold().resolved()
    }

    pub fn is_enabled(&self) -> bool {
        self.threshold() != AlertThreshold::Off
    }
}
