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
// This file is a Rust derivative of the ZAP automation framework. It changes
// the language and the architecture (Apache License 2.0, section 4). It is
// not an official OWASP ZAP build. There is no JDK and no browser.

//! Report and output-summary files.
//!
//! Templates are the traditional HTML, JSON, XML, and Markdown reports the
//! packaged scans request. The bodies are the session alert rows, not the
//! Java traditional-report templates.

use std::fs;
use std::path::{Path, PathBuf};

use zap_store::AlertRow;

use crate::error::{self, Error};
use crate::plan::{Job, SummaryRule};

pub(crate) fn write_report(job: &Job, alerts: &[AlertRow], base: &Path) -> Result<String, Error> {
    let Job::Report {
        template,
        report_dir,
        report_file,
        title,
        description,
        risks,
        confidences,
    } = job
    else {
        return Err(error::job("report", "internal job mismatch"));
    };
    let extension = match template.as_str() {
        "traditional-html" => "html",
        "traditional-json" => "json",
        "traditional-xml" => "xml",
        "traditional-md" => "md",
        other => {
            return Err(error::job(
                "report",
                format!("report template `{other}` is not implemented"),
            ));
        }
    };
    let file_name = if report_file.is_empty() {
        format!("zap-report.{extension}")
    } else if Path::new(report_file).extension().is_some() {
        report_file.clone()
    } else {
        format!("{report_file}.{extension}")
    };
    let path = resolve(base, report_dir, &file_name);
    let selected: Vec<&AlertRow> = alerts
        .iter()
        .filter(|alert| {
            (risks.is_empty() || risks.contains(&alert.risk))
                && (confidences.is_empty() || confidences.contains(&alert.confidence))
        })
        .collect();
    let body = match extension {
        "html" => html(title, description, &selected),
        "json" => json(title, description, &selected)?,
        "xml" => xml(title, description, &selected),
        "md" => markdown(title, description, &selected),
        _ => unreachable!("extension is one of the four templates"),
    };
    write_text(&path, &body)?;
    Ok(format!(
        "wrote {} ({} alerts)",
        path.display(),
        selected.len()
    ))
}

pub(crate) fn write_summary(
    format: &str,
    summary_file: &str,
    rules: &[SummaryRule],
    alerts: &[AlertRow],
    base: &Path,
) -> Result<String, Error> {
    let path = resolve(base, "", summary_file);
    let mut lines = vec![
        format!("format: {format}"),
        format!("alerts: {}", alerts.len()),
    ];
    if rules.is_empty() {
        for alert in alerts {
            lines.push(format!(
                "plugin {} risk {} {}",
                alert.plugin_id, alert.risk, alert.url
            ));
        }
    } else {
        for rule in rules {
            let count = alerts
                .iter()
                .filter(|alert| alert.plugin_id == rule.id)
                .count();
            lines.push(format!("{} {}: {count}", rule.action, rule.id));
        }
    }
    lines.push(String::new());
    write_text(&path, &lines.join("\n"))?;
    Ok(format!("wrote {}", path.display()))
}

fn resolve(base: &Path, dir: &str, file: &str) -> PathBuf {
    let file_path = PathBuf::from(file);
    if file_path.is_absolute() {
        return file_path;
    }
    let directory = if dir.is_empty() {
        base.to_path_buf()
    } else {
        let directory = PathBuf::from(dir);
        if directory.is_absolute() {
            directory
        } else {
            base.join(directory)
        }
    };
    directory.join(file_path)
}

fn write_text(path: &Path, body: &str) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| Error::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    fs::write(path, body).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn json(title: &str, description: &str, alerts: &[&AlertRow]) -> Result<String, Error> {
    let alerts: Vec<_> = alerts
        .iter()
        .map(|alert| {
            serde_json::json!({
                "pluginId": alert.plugin_id,
                "risk": alert.risk,
                "confidence": alert.confidence,
                "cweId": alert.cwe_id,
                "wascId": alert.wasc_id,
                "param": alert.param,
                "url": alert.url,
            })
        })
        .collect();
    let value = serde_json::json!({
        "title": title,
        "description": description,
        "alerts": alerts,
    });
    serde_json::to_string_pretty(&value).map_err(|err| error::job("report", err.to_string()))
}

fn html(title: &str, description: &str, alerts: &[&AlertRow]) -> String {
    let mut rows = String::new();
    for alert in alerts {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            alert.plugin_id,
            alert.risk,
            alert.confidence,
            xml_escape(&alert.url),
            xml_escape(&alert.param),
        ));
    }
    format!(
        "<!DOCTYPE html>\n<html>\n<head><meta charset=\"utf-8\"><title>{}</title></head>\n<body>\n<h1>{}</h1>\n<p>{}</p>\n<table>\n<thead><tr><th>pluginId</th><th>risk</th><th>confidence</th><th>url</th><th>param</th></tr></thead>\n<tbody>\n{rows}</tbody>\n</table>\n</body>\n</html>\n",
        xml_escape(title),
        xml_escape(title),
        xml_escape(description),
    )
}

fn xml(title: &str, description: &str, alerts: &[&AlertRow]) -> String {
    let mut body = format!(
        "<report>\n<title>{}</title>\n<description>{}</description>\n",
        xml_escape(title),
        xml_escape(description),
    );
    for alert in alerts {
        body.push_str(&format!(
            "<alert><pluginId>{}</pluginId><risk>{}</risk><confidence>{}</confidence><cweId>{}</cweId><wascId>{}</wascId><param>{}</param><url>{}</url></alert>\n",
            alert.plugin_id,
            alert.risk,
            alert.confidence,
            alert.cwe_id,
            alert.wasc_id,
            xml_escape(&alert.param),
            xml_escape(&alert.url),
        ));
    }
    body.push_str("</report>\n");
    body
}

fn markdown(title: &str, description: &str, alerts: &[&AlertRow]) -> String {
    let mut body = format!("# {title}\n\n{description}\n\n| pluginId | risk | confidence | url | param |\n| --- | --- | --- | --- | --- |\n");
    for alert in alerts {
        body.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            alert.plugin_id,
            alert.risk,
            alert.confidence,
            cell(&alert.url),
            cell(&alert.param),
        ));
    }
    body
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
