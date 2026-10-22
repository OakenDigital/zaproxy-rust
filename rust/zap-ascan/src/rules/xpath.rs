// Copyright 2013 The ZAP Development Team
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
// This file is a Rust derivative of XpathInjectionScanRule from ascanrules
// v78 (zaproxy/zap-extensions tag ascanrules-v78). It changes the language
// and the architecture (Apache License 2.0, section 4). It is not an
// official OWASP ZAP build. The Java add-on is not included.

//! XPath Injection. Plugin id 90021.

use zap_store::{Confidence, Risk};

use crate::context::{ActivePlugin, RaisedAlert, ScanContext, SendError};
use crate::variant::variants_for;

pub const XPATH_PLUGIN_ID: i32 = 90021;
pub const XPATH_NAME: &str = "XPath Injection";

const CWE_ID: i32 = 643;
const WASC_ID: i32 = 39;

const PAYLOADS: [&str; 3] = ["\"'", "<!--", "]]>"];

/// Error strings from ascanrules v78 `XpathInjectionScanRule.DEFAULT_ERRORS`.
const ERRORS: &[&str] = &[
    "XPathException",
    "MS.Internal.Xml.",
    "Unknown error in XPath",
    "org.apache.xpath.XPath",
    "A closing bracket expected in",
    "An operand in Union Expression does not produce a node-set",
    "Cannot convert expression to a number",
    "Document Axis does not allow any context Location Steps",
    "Empty Path Expression",
    "Empty Relative Location Path",
    "Empty Union Expression",
    "Expected ')' in",
    "Expected node test or name specification after axis operator",
    "Incompatible XPath key",
    "Incorrect Variable Binding",
    "libxml2 library function failed",
    "libxml2",
    "xmlsec library function",
    "xmlsec",
    "error '80004005'",
    "A document must contain exactly one root element.",
    "<font face=\"Arial\" size=2>Expression must evaluate to a node-set.",
    "Expected token '\\]'",
    "<p>msxml4.dll</font>",
    "<p>msxml3.dll</font>",
    "4005 Notes error: Query is not understandable",
    "SimpleXMLElement::xpath()",
    "xmlXPathEval: evaluation failed",
    "Expression must evaluate to a node-set.",
];

/// Port of `XpathInjectionScanRule` (ascanrules v78).
#[derive(Clone, Debug, Default)]
pub struct XpathInjectionScanRule;

impl ActivePlugin for XpathInjectionScanRule {
    fn plugin_id(&self) -> i32 {
        XPATH_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        XPATH_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) {
        let original = ctx.base_body();
        for variant in variants_for(ctx.base()) {
            if ctx.is_stopped() {
                return;
            }
            for (index, param) in variant.params().iter().enumerate() {
                if ctx.is_stopped() {
                    return;
                }
                for payload in PAYLOADS {
                    if ctx.is_stopped() {
                        return;
                    }
                    let mut msg = variant.apply(ctx.base(), index, payload);
                    match ctx.send(&mut msg) {
                        Ok(response) => {
                            let body = String::from_utf8_lossy(&response.body);
                            if let Some(error) = matching_error(&body, original) {
                                ctx.raise(RaisedAlert {
                                    plugin_id: XPATH_PLUGIN_ID,
                                    name: XPATH_NAME,
                                    risk: Risk::High.code(),
                                    confidence: Confidence::High.code(),
                                    cwe_id: CWE_ID,
                                    wasc_id: WASC_ID,
                                    param: param.name.clone(),
                                    url: msg.url(),
                                    evidence: error.to_string(),
                                    attack: payload.to_string(),
                                });
                                break;
                            }
                        }
                        Err(SendError::Stopped) => return,
                        Err(SendError::Failed(err)) => {
                            tracing::debug!(%err, "xpath injection send failed");
                        }
                    }
                }
            }
        }
    }
}

fn matching_error(body: &str, original: &str) -> Option<&'static str> {
    ERRORS
        .iter()
        .copied()
        .find(|error| body.contains(error) && !original.contains(error))
}
