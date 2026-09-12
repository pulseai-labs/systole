//! `project.systole.json` — the project manifest (ADR-0003, ADR-0006).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::RelPath;

pub const PROJECT_SCHEMA: u32 = 1;
pub const FIRST_REVISION: &str = "rev_00000";
pub const ENGINE_NAME: &str = "systole";

pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Engine {
    pub name: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ModuleEntry {
    pub version: String,
    pub schema: u32,
}

/// The head of the audit chain (ADR-0006): the id and hash of the last entry.
/// Null until the first commit.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AuditHead {
    pub id: String,
    pub hash: String,
}

/// The project manifest.
///
/// `files` is the per-file digest table (path → `sha256:<hex>` of the file's
/// canonical bytes) used for exact changed-file reporting at load time. It
/// covers every hash-domain file except the manifest itself, whose integrity
/// `project_hash` covers directly; both are updated together on every write.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Manifest {
    pub engine: Engine,
    pub project_schema: u32,
    pub modules: BTreeMap<String, ModuleEntry>,
    pub stable_id_counter: u64,
    pub project_revision: String,
    pub project_hash: String,
    pub audit_head: Option<AuditHead>,
    pub files: BTreeMap<RelPath, String>,
}
