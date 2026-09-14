//! The operation contracts (ADR-0004). Rounds 2 and 3 compile against these
//! signatures; they change only through a re-plan.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::finding::Finding;
use crate::ir::project::Project;
use crate::ir::RelPath;
use crate::tx::Transaction;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub enum Stability {
    Stable,
    Experimental,
    Internal,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub enum Mutability {
    Read,
    Write,
    Destructive,
}

/// The untrusted envelope a caller sends (ADR-0005): which op, which version,
/// the input payload, and the actor requesting it.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PlanRequest {
    pub op_id: String,
    pub op_version: u32,
    pub input: serde_json::Value,
    pub actor: String,
}

/// The engine-side plan: the op's materialized payload bound to the project
/// revision it was materialized against.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OperationPlan {
    pub plan_id: String,
    pub op_id: String,
    pub op_version: u32,
    pub base_project_revision: String,
    pub base_project_hash: String,
    pub engine_version: String,
    pub module_versions: BTreeMap<String, String>,
    pub payload: serde_json::Value,
}

/// One staged file state: `before = None` is a creation, `after = None` a
/// deletion.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FileChange {
    pub path: RelPath,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Diff {
    pub changes: Vec<FileChange>,
}

/// The catalog entry an op exposes: identity, schema, example, and when to
/// avoid it.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OperationDescription {
    pub id: String,
    pub version: u32,
    pub summary: String,
    pub input_schema: schemars::Schema,
    pub example: serde_json::Value,
    pub avoid_when: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OpError {
    #[error("unknown operation: {0}")]
    UnknownOp(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("materialize failed: {0}")]
    Materialize(String),
    #[error("diff failed: {0}")]
    Diff(String),
    #[error("apply failed: {0}")]
    Apply(String),
}

/// A write operation: request → plan → diff → findings → staged apply. The
/// engine lifecycle around these calls (revision binding, lock, two-phase
/// commit, audit append) is `r0.s1.w2`.
pub trait Operation: Send + Sync {
    type Request: DeserializeOwned + Serialize + JsonSchema;
    type Plan: DeserializeOwned + Serialize + JsonSchema;
    type Output: Serialize + JsonSchema;

    const ID: &'static str;
    const VERSION: u32;
    const CAPABILITY: Capability;
    const STABILITY: Stability;
    const MUTABILITY: Mutability;

    fn describe() -> OperationDescription;
    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError>;
    fn materialize(&self, project: &Project, req: Self::Request) -> Result<Self::Plan, OpError>;
    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError>;
    fn validate(&self, project: &Project, plan: &Self::Plan) -> Vec<Finding>;
    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError>;
}

/// A read operation: request → query, no plan, no writes.
pub trait ReadOperation: Send + Sync {
    type Request: DeserializeOwned + Serialize + JsonSchema;
    type Output: Serialize + JsonSchema;

    const ID: &'static str;
    const VERSION: u32;
    const CAPABILITY: Capability;

    fn describe() -> OperationDescription;
    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError>;
    fn query(&self, project: &Project, req: Self::Request) -> Result<Self::Output, OpError>;
}
