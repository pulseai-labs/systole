//! Structured validation findings (ADR-0004): stable ids, severity, location
//! by stable id and path, evidence, suggested fixes as PlanRequests, and a
//! blocking flag.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::ir::format::format_value;
use crate::ir::RelPath;
use crate::op::PlanRequest;
use crate::revision::sha256_hex;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Where a finding points: the referenced stable id and/or IR file path.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Location {
    pub stable_id: Option<String>,
    pub path: Option<RelPath>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub finding_id: String,
    pub code: String,
    pub severity: Severity,
    pub location: Location,
    pub evidence: serde_json::Value,
    pub suggested_fixes: Vec<PlanRequest>,
    pub blocking: bool,
}

/// The single finding-id formula (ADR-0010): `finding_` plus the first 16 hex
/// digits of sha256 over the canonical bytes of `{code, location, evidence}`.
/// Deterministic, so `validate` and `plan --from-finding` agree on a finding's
/// id without persisting anything between them.
pub fn finding_id(code: &str, location: &Location, evidence: &Value) -> String {
    let basis = json!({
        "code": code,
        "location": serde_json::to_value(location).unwrap_or(Value::Null),
        "evidence": evidence,
    });
    format!("finding_{}", &sha256_hex(&format_value(&basis))[..16])
}
