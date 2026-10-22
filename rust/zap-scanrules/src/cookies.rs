// Copyright 2011 The ZAP Development Team
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
// This file follows CookieUtils from commonlib as used by pscanrules v70.
// The Java file is not included. It is not an official OWASP ZAP build.

//! Set-Cookie attribute helpers used by the cookie rules.
//!
//! The cookie ignore list is empty. There is no rule-config file in this port.

use std::time::{SystemTime, UNIX_EPOCH};

/// True when an attribute after the name/value pair matches `attribute` (case-insensitive).
pub fn has_attribute(header_value: &str, attribute: &str) -> bool {
    attribute_parts(header_value, attribute).is_some()
}

/// Trimmed attribute value, or `None` when the attribute is absent or has no `=`.
pub fn attribute_value(header_value: &str, attribute: &str) -> Option<String> {
    let parts = attribute_parts(header_value, attribute)?;
    if parts.len() < 2 {
        return None;
    }
    Some(parts[1].trim().to_string())
}

/// Cookie name, or `""` when the name/value pair has no `=` before the first `;`.
pub fn cookie_name(header_value: &str) -> String {
    if header_value.is_empty() {
        return String::new();
    }
    let equals = header_value.find('=');
    let semicolon = header_value.find(';');
    match equals {
        Some(equals) if semicolon.is_none_or(|semi| equals < semi) => {
            header_value[..equals].trim().to_string()
        }
        _ => String::new(),
    }
}

/// True when `Expires` is present and is in the past or not an HTTP date.
///
/// A missing `Expires` attribute is not expired. An unparseable value is expired,
/// matching `HttpDateUtils.parse` returning null.
pub fn is_expired(header_value: &str) -> bool {
    let Some(expiry) = attribute_value(header_value, "expires") else {
        return false;
    };
    match parse_http_date(&expiry) {
        Some(expires_at) => expires_at < now_unix(),
        None => true,
    }
}

fn attribute_parts<'a>(header_value: &'a str, attribute: &str) -> Option<Vec<&'a str>> {
    if header_value.is_empty() || attribute.is_empty() {
        return None;
    }
    let mut elements = header_value.split(';');
    elements.next()?;
    for element in elements {
        let mut parts = element.splitn(2, '=');
        let name = parts.next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case(attribute) {
            let mut collected = vec![name];
            if let Some(value) = parts.next() {
                collected.push(value);
            }
            return Some(collected);
        }
    }
    None
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// RFC 1123, RFC 850, and asctime dates. Two-digit years use the POSIX window.
fn parse_http_date(value: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let lower = value.to_ascii_lowercase();
    let (month, at) = MONTHS
        .iter()
        .enumerate()
        .find_map(|(index, name)| lower.find(name).map(|at| (index as u32 + 1, at)))?;
    let day = last_number(&lower[..at])?;
    let after = lower[at + 3..].trim_start();
    let mut tokens = after.split_whitespace();
    let year_token = tokens.next()?.trim_end_matches(',');
    let mut year: i32 = year_token.parse().ok()?;
    if year < 100 {
        year += if year >= 70 { 1900 } else { 2000 };
    }
    let time = tokens.next().unwrap_or("00:00:00");
    let mut clock = time.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let minute: u32 = clock.next()?.parse().ok()?;
    let second: u32 = clock.next().unwrap_or("0").parse().ok()?;
    civil_to_unix(year, month, day, hour, minute, second)
}

fn last_number(value: &str) -> Option<u32> {
    value
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .next_back()?
        .parse()
        .ok()
}

fn civil_to_unix(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let year = year as i64;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month_prime as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;
    Some(days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64)
}
