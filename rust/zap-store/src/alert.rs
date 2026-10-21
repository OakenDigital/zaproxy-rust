// Copyright 2010-2024 The ZAP Development Team
// Copyright (C) 2003-2004 Chinotec Technologies Company
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
// official OWASP ZAP build. Risk and confidence codes match
// `org.parosproxy.paros.core.scanner.Alert`.

//! Alert row fields stored for a session.
//!
//! The integers match `org.parosproxy.paros.core.scanner.Alert`:
//! risk informational/low/medium/high are 0/1/2/3, and confidence
//! false positive/low/medium/high/user confirmed are 0/1/2/3/4.
//! CWE and WASC use `-1` when unknown. The row stores the raw integers
//! so a value outside those ranges still round-trips.

/// CWE id stored when the alert has none. Matches ZAP's unset CWE.
pub const UNKNOWN_CWE_ID: i32 = -1;

/// WASC id stored when the alert has none. Matches ZAP's unset WASC.
pub const UNKNOWN_WASC_ID: i32 = -1;

/// Risk score. Discriminants are the ZAP `RISK_*` constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Risk {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl Risk {
    pub const fn code(self) -> i32 {
        self as i32
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Informational),
            1 => Some(Self::Low),
            2 => Some(Self::Medium),
            3 => Some(Self::High),
            _ => None,
        }
    }
}

/// Confidence score. Discriminants are the ZAP `CONFIDENCE_*` constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Confidence {
    FalsePositive = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    UserConfirmed = 4,
}

impl Confidence {
    pub const fn code(self) -> i32 {
        self as i32
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::FalsePositive),
            1 => Some(Self::Low),
            2 => Some(Self::Medium),
            3 => Some(Self::High),
            4 => Some(Self::UserConfirmed),
            _ => None,
        }
    }
}

/// Fields written by [`crate::Session::insert_alert`].
///
/// `risk` and `confidence` are raw codes. Use [`Risk::code`] and
/// [`Confidence::code`] for the ZAP constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAlert {
    pub plugin_id: i32,
    pub risk: i32,
    pub confidence: i32,
    pub cwe_id: i32,
    pub wasc_id: i32,
    pub param: String,
    pub url: String,
}

/// One alert row, including the SQLite id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertRow {
    pub id: i64,
    pub plugin_id: i32,
    pub risk: i32,
    pub confidence: i32,
    pub cwe_id: i32,
    pub wasc_id: i32,
    pub param: String,
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_codes_match_zap_alert_constants() {
        assert_eq!(Risk::Informational.code(), 0);
        assert_eq!(Risk::Low.code(), 1);
        assert_eq!(Risk::Medium.code(), 2);
        assert_eq!(Risk::High.code(), 3);
        for code in 0..=3 {
            assert_eq!(Risk::from_code(code).unwrap().code(), code);
        }
        assert_eq!(Risk::from_code(-1), None);
        assert_eq!(Risk::from_code(4), None);
    }

    #[test]
    fn confidence_codes_match_zap_alert_constants() {
        assert_eq!(Confidence::FalsePositive.code(), 0);
        assert_eq!(Confidence::Low.code(), 1);
        assert_eq!(Confidence::Medium.code(), 2);
        assert_eq!(Confidence::High.code(), 3);
        assert_eq!(Confidence::UserConfirmed.code(), 4);
        for code in 0..=4 {
            assert_eq!(Confidence::from_code(code).unwrap().code(), code);
        }
        assert_eq!(Confidence::from_code(-1), None);
        assert_eq!(Confidence::from_code(5), None);
    }

    #[test]
    fn unknown_cwe_and_wasc_are_minus_one() {
        assert_eq!(UNKNOWN_CWE_ID, -1);
        assert_eq!(UNKNOWN_WASC_ID, -1);
    }
}
