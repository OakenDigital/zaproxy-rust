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

//! Sites, history, message text, and alerts read from the session.

use zap_core::HistoryRow;
use zap_store::{Session, SiteNode};

use crate::breakpoint::{Breakpoint, Waiting};

/// Request and response text for one history row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageText {
    pub id: u64,
    pub request: String,
    pub response: String,
}

/// One rendered site-tree line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteLine {
    pub depth: usize,
    pub segment: String,
    pub url: String,
    pub history_id: Option<i64>,
}

/// One history row in the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryLine {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub status: u16,
}

/// One alert in the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertLine {
    pub id: i64,
    pub plugin_id: i32,
    pub risk: i32,
    pub confidence: i32,
    pub param: String,
    pub url: String,
}

/// Everything the page shows at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub request_break: bool,
    pub response_break: bool,
    pub sites: Vec<SiteLine>,
    pub history: Vec<HistoryLine>,
    pub alerts: Vec<AlertLine>,
    pub message: Option<MessageText>,
    pub breakpoint: Option<Waiting>,
}

/// Read the session and the current breakpoint.
///
/// `selected` picks a history row. When it is absent, the newest row is shown.
pub fn snapshot(
    session: &Session,
    breakpoint: &Breakpoint,
    selected: Option<u64>,
) -> Result<Snapshot, zap_store::Error> {
    let nodes = session.site_nodes()?;
    let rows = session.history_rows()?;
    let alerts = session.alerts()?;
    let history = rows
        .iter()
        .map(|row| HistoryLine {
            id: row.id,
            method: row.method.clone(),
            url: row.url.clone(),
            status: row.status,
        })
        .collect::<Vec<_>>();
    let chosen = selected.or_else(|| history.last().map(|row| row.id));
    let message = chosen.and_then(|id| rows.iter().find(|row| row.id == id).map(message_of));
    Ok(Snapshot {
        request_break: breakpoint.request_enabled(),
        response_break: breakpoint.response_enabled(),
        sites: site_lines(&nodes),
        history,
        alerts: alerts
            .into_iter()
            .map(|alert| AlertLine {
                id: alert.id,
                plugin_id: alert.plugin_id,
                risk: alert.risk,
                confidence: alert.confidence,
                param: alert.param,
                url: alert.url,
            })
            .collect(),
        message,
        breakpoint: breakpoint.waiting(),
    })
}

fn site_lines(nodes: &[SiteNode]) -> Vec<SiteLine> {
    let mut lines = Vec::new();
    walk(nodes, None, 0, &mut lines);
    lines
}

fn walk(nodes: &[SiteNode], parent: Option<i64>, depth: usize, out: &mut Vec<SiteLine>) {
    let mut children: Vec<&SiteNode> = nodes
        .iter()
        .filter(|node| node.parent_id == parent)
        .collect();
    children.sort_by_key(|node| node.id);
    for node in children {
        out.push(SiteLine {
            depth,
            segment: node.segment.clone(),
            url: node.url.clone(),
            history_id: node.history_id,
        });
        walk(nodes, Some(node.id), depth + 1, out);
    }
}

fn message_of(row: &HistoryRow) -> MessageText {
    MessageText {
        id: row.id,
        request: text_block(
            &format!("{} {}", row.method, row.url),
            &header_lines(&row.request_headers),
            &String::from_utf8_lossy(&row.request_body),
        ),
        response: text_block(
            &format!("HTTP/1.1 {}", row.status),
            &header_lines(&row.response_headers),
            &String::from_utf8_lossy(&row.response_body),
        ),
    }
}

fn header_lines(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn text_block(start: &str, headers: &str, body: &str) -> String {
    if headers.is_empty() {
        format!("{start}\n\n{body}")
    } else {
        format!("{start}\n{headers}\n\n{body}")
    }
}

/// Indent the site tree the way the page prints it.
pub fn sites_text(lines: &[SiteLine]) -> String {
    lines
        .iter()
        .map(|line| format!("{}{}", "  ".repeat(line.depth), line.segment))
        .collect::<Vec<_>>()
        .join("\n")
}
