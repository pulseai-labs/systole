//! Structured validation findings (ADR-0004): stable ids, severity, location
//! by stable id and path, evidence, suggested fixes as PlanRequests, and a
//! blocking flag.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ir::RelPath;
use crate::op::PlanRequest;

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
