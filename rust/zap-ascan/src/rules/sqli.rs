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
// This file is a Rust derivative of SqlInjectionScanRule from ascanrules
// v78 (zaproxy/zap-extensions tag ascanrules-v78). It changes the language
// and the architecture (Apache License 2.0, section 4). It is not an
// official OWASP ZAP build. The Java add-on is not included.

//! SQL injection. Plugin id 40018.
//!
//! Error-based checks (specific RDBMS messages and the HTTP 500 heuristic)
//! and expression-based checks follow the medium-strength, medium-threshold
//! settings. Boolean, union, and order-by checks are not included. There
//! is no time-based payload.

use http::StatusCode;
use zap_core::HttpResponse;
use zap_store::{Confidence, Risk};

use crate::context::{ActivePlugin, RaisedAlert, ScanContext};
use crate::policy::AttackStrength;
use crate::variant::variants_for;

pub const SQLI_PLUGIN_ID: i32 = 40018;
pub const SQLI_NAME: &str = "SQL Injection";

const CWE_ID: i32 = 89;
const WASC_ID: i32 = 19;
const SQL_CHECK_ERR: &[&str] = &["'", "\"", ";", "'(", ")", "(", "NULL", "'\""];
const SAFE_VALUE: &str = "S4feV4lu3";

/// `(display name, error fragment)`. Generic RDBMS fragments stay off at
/// medium threshold, matching `init` when the threshold is medium.
const SPECIFIC_ERRORS: &[(&str, &[&str])] = &[
    (
        "MySQL",
        &[
            "You have an error in your SQL syntax",
            "com.mysql.jdbc.exceptions",
            "org.gjt.mm.mysql",
            "ODBC driver does not support",
            "The used SELECT statements have a different number of columns",
        ],
    ),
    (
        "Microsoft SQL Server",
        &[
            "com.microsoft.sqlserver.jdbc",
            "com.microsoft.jdbc",
            "com.inet.tds",
            "com.ashna.jturbo",
            "weblogic.jdbc.mssqlserver",
            "[Microsoft]",
            "[SQLServer]",
            "[SQLServer 2000 Driver for JDBC]",
            "net.sourceforge.jtds.jdbc",
            "80040e14",
            "800a0bcd",
            "80040e57",
            "ODBC driver does not support",
            "All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists",
            "All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists",
        ],
    ),
    (
        "Oracle",
        &[
            "oracle.jdbc",
            "SQLSTATE[HY",
            "ORA-00933",
            "ORA-06512",
            "SQL command not properly ended",
            "ORA-00942",
            "ORA-29257",
            "ORA-00932",
            "query block has incorrect number of result columns",
            "ORA-01789",
        ],
    ),
    ("IBM DB2", &["com.ibm.db2.jcc", "COM.ibm.db2.jdbc"]),
    (
        "PostgreSQL",
        &[
            "org.postgresql.util.PSQLException",
            "org.postgresql",
            "each UNION query must have the same number of columns",
            "unterminated quoted string at or near",
            "syntax error at or near",
        ],
    ),
    (
        "Sybase",
        &["com.sybase.jdbc", "net.sourceforge.jtds.jdbc"],
    ),
    ("Informix", &["com.informix.jdbc"]),
    ("Firebird", &["org.firebirdsql.jdbc"]),
    ("IDS Server", &["ids.sql"]),
    (
        "InstantDB",
        &["org.enhydra.instantdb.jdbc", "jdbc.idb"],
    ),
    ("Interbase", &["interbase.interclient"]),
    (
        "Hypersonic SQL",
        &[
            "org.hsql",
            "hSql.",
            "Unexpected token , requires FROM in statement",
            "Unexpected end of command in statement",
            "Column count does not match in statement",
            "Table not found in statement",
            "Unexpected token:",
        ],
    ),
    ("Sybase SQL Anywhere", &["sybase.jdbc.sqlanywhere"]),
    ("Pointbase", &["com.pointbase.jdbc"]),
    (
        "Cloudscape",
        &["db2j.", "COM.cloudscape", "RmiJdbc.RJDriver"],
    ),
    ("Ingres", &["com.ingres.jdbc"]),
    (
        "SQLite",
        &[
            "SQLITE_ERROR",
            "SELECTs to the left and right of UNION do not have the same number of result columns",
        ],
    ),
];

/// Port of the error-based and expression-based checks.
#[derive(Clone, Debug, Default)]
pub struct SqlInjectionScanRule;

impl ActivePlugin for SqlInjectionScanRule {
    fn plugin_id(&self) -> i32 {
        SQLI_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        SQLI_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        if ctx.is_stopped() {
            return;
        }
        let limit = error_limit(ctx.strength());
        for variant in variants_for(ctx.base()) {
            if ctx.is_stopped() {
                return;
            }
            for (index, param) in variant.params().iter().enumerate() {
                if ctx.is_stopped() {
                    return;
                }
                if error_based(ctx, &variant, index, &param.name, &param.value, limit) {
                    return;
                }
                if ctx.is_stopped() {
                    return;
                }
                if expression_based(ctx, &variant, index, &param.name, &param.value) {
                    return;
                }
            }
        }
    }
}

fn error_limit(strength: AttackStrength) -> usize {
    match strength {
        AttackStrength::Low => 4,
        AttackStrength::Medium | AttackStrength::Default => 8,
        AttackStrength::High | AttackStrength::Insane => 16,
    }
}

fn error_based(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    param: &str,
    original: &str,
    limit: usize,
) -> bool {
    let base_status = ctx
        .base()
        .response
        .as_ref()
        .map(|response| response.status)
        .unwrap_or(StatusCode::OK);
    let base_body = ctx.base_body().to_ascii_lowercase();
    let mut sent = 0usize;
    for payload in SQL_CHECK_ERR {
        for prefix in ["", original] {
            if sent >= limit || ctx.is_stopped() {
                return false;
            }
            let attack = format!("{prefix}{payload}");
            let Some(response) = send(ctx, variant, index, &attack) else {
                if ctx.is_stopped() {
                    return true;
                }
                continue;
            };
            sent += 1;
            if response.status == StatusCode::INTERNAL_SERVER_ERROR
                && base_status != StatusCode::INTERNAL_SERVER_ERROR
            {
                if let Some(safe) = send(ctx, variant, index, SAFE_VALUE) {
                    if safe.status != StatusCode::INTERNAL_SERVER_ERROR {
                        raise(
                            ctx,
                            param,
                            &attack,
                            SQLI_NAME,
                            Confidence::Low,
                            status_line(&response),
                            &response_url(ctx, variant, index, &attack),
                        );
                        return true;
                    }
                } else if ctx.is_stopped() {
                    return true;
                }
            }
            let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
            if let Some((name, evidence)) = specific_error(&base_body, &body) {
                raise(
                    ctx,
                    param,
                    &attack,
                    rdbms_name(name),
                    Confidence::Medium,
                    evidence,
                    &response_url(ctx, variant, index, &attack),
                );
                return true;
            }
            if sqlite_error(&base_body, &body) {
                raise(
                    ctx,
                    param,
                    &attack,
                    "SQL Injection - SQLite",
                    Confidence::Medium,
                    "syntax error".to_string(),
                    &response_url(ctx, variant, index, &attack),
                );
                return true;
            }
        }
    }
    false
}

fn specific_error(base: &str, body: &str) -> Option<(&'static str, String)> {
    for (name, fragments) in SPECIFIC_ERRORS {
        for fragment in *fragments {
            let lower = fragment.to_ascii_lowercase();
            if body.contains(&lower) && !base.contains(&lower) {
                return Some((*name, (*fragment).to_string()));
            }
        }
    }
    None
}

fn sqlite_error(base: &str, body: &str) -> bool {
    fn near_error(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        let Some(start) = lower.find("near \"") else {
            return false;
        };
        lower[start..].contains("\": syntax error")
    }
    near_error(body) && !near_error(base)
}

fn expression_based(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    param: &str,
    original: &str,
) -> bool {
    let Ok(value) = original.parse::<i32>() else {
        return false;
    };
    let Some(normal) = send(ctx, variant, index, original) else {
        return ctx.is_stopped();
    };
    let Some(plus_two) = value.checked_add(2) else {
        return false;
    };
    let Some(plus_three) = value.checked_add(3) else {
        return false;
    };
    let same = format!("{plus_two}-2");
    let different = format!("{plus_three}-2");
    let pair = ExprPair {
        original,
        normal: &normal,
        same: &same,
        different: &different,
    };
    if expression_pair(ctx, variant, index, param, &pair) {
        return true;
    }
    let Some(times_two) = value.checked_mul(2) else {
        return false;
    };
    let Some(times_four) = value.checked_mul(4) else {
        return false;
    };
    let same = format!("{times_two}/2");
    let different = format!("{times_four}/2");
    let pair = ExprPair {
        original,
        normal: &normal,
        same: &same,
        different: &different,
    };
    expression_pair(ctx, variant, index, param, &pair)
}

struct ExprPair<'a> {
    original: &'a str,
    normal: &'a HttpResponse,
    same: &'a str,
    different: &'a str,
}

fn expression_pair(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    param: &str,
    pair: &ExprPair<'_>,
) -> bool {
    if ctx.is_stopped() {
        return false;
    }
    let Some(modified) = send(ctx, variant, index, pair.same) else {
        return ctx.is_stopped();
    };
    if !same_body(pair.normal, &modified, pair.original, pair.same) {
        return false;
    }
    let Some(confirm) = send(ctx, variant, index, pair.different) else {
        return ctx.is_stopped();
    };
    if same_body(pair.normal, &confirm, pair.original, pair.different) {
        return false;
    }
    raise(
        ctx,
        param,
        pair.same,
        SQLI_NAME,
        Confidence::Medium,
        String::new(),
        &response_url(ctx, variant, index, pair.same),
    );
    true
}

fn same_body(left: &HttpResponse, right: &HttpResponse, original: &str, attack: &str) -> bool {
    if left.status.is_redirection()
        && left.status == right.status
        && left.headers.get(http::header::LOCATION) != right.headers.get(http::header::LOCATION)
    {
        return false;
    }
    strip_body(&left.body, original, attack) == strip_body(&right.body, original, attack)
}

fn strip_body(body: &[u8], original: &str, attack: &str) -> String {
    let mut text = String::from_utf8_lossy(body).into_owned();
    for value in [original, attack] {
        if value.is_empty() {
            continue;
        }
        text = text.replace(value, "");
    }
    text
}

fn send(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    value: &str,
) -> Option<HttpResponse> {
    if ctx.is_stopped() {
        return None;
    }
    let mut msg = variant.apply(ctx.base(), index, value);
    ctx.send(&mut msg).ok()
}

fn response_url(
    ctx: &ScanContext<'_>,
    variant: &crate::variant::Variant,
    index: usize,
    value: &str,
) -> String {
    variant.apply(ctx.base(), index, value).url()
}

fn status_line(response: &HttpResponse) -> String {
    let reason = response.status.canonical_reason().unwrap_or("");
    format!("HTTP/1.1 {} {reason}", response.status.as_u16())
}

fn rdbms_name(name: &str) -> &'static str {
    match name {
        "MySQL" => "SQL Injection - MySQL",
        "Microsoft SQL Server" => "SQL Injection - Microsoft SQL Server",
        "Oracle" => "SQL Injection - Oracle",
        "IBM DB2" => "SQL Injection - IBM DB2",
        "PostgreSQL" => "SQL Injection - PostgreSQL",
        "Sybase" => "SQL Injection - Sybase",
        "Informix" => "SQL Injection - Informix",
        "Firebird" => "SQL Injection - Firebird",
        "IDS Server" => "SQL Injection - IDS Server",
        "InstantDB" => "SQL Injection - InstantDB",
        "Interbase" => "SQL Injection - Interbase",
        "Hypersonic SQL" => "SQL Injection - Hypersonic SQL",
        "Sybase SQL Anywhere" => "SQL Injection - Sybase SQL Anywhere",
        "Pointbase" => "SQL Injection - Pointbase",
        "Cloudscape" => "SQL Injection - Cloudscape",
        "Ingres" => "SQL Injection - Ingres",
        "SQLite" => "SQL Injection - SQLite",
        _ => SQLI_NAME,
    }
}

fn raise(
    ctx: &ScanContext<'_>,
    param: &str,
    attack: &str,
    name: &'static str,
    confidence: Confidence,
    evidence: String,
    url: &str,
) {
    ctx.raise(RaisedAlert {
        plugin_id: SQLI_PLUGIN_ID,
        name,
        risk: Risk::High.code(),
        confidence: confidence.code(),
        cwe_id: CWE_ID,
        wasc_id: WASC_ID,
        param: param.to_string(),
        url: url.to_string(),
        evidence,
        attack: attack.to_string(),
    });
}
