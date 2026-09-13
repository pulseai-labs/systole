//! The operation registry: type-erased entries keyed by `(id, version)`,
//! dispatched by envelope (ADR-0004). The lifecycle around the dispatch
//! methods — revision binding, lock, two-phase commit, audit append — is
//! `r0.s1.w2`.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use crate::capability::Capability;
use crate::finding::Finding;
use crate::ir::format::format_value;
use crate::ir::project::Project;
use crate::op::{
    Diff, Mutability, Operation, OperationDescription, OperationPlan, OpError, PlanRequest,
    ReadOperation,
};
use crate::revision::sha256_hex;
use crate::tx::Transaction;

/// The catalog row `op list` renders: the description plus the capability and
/// mutability constants declared on the op itself (ADR-0005). Kept separate
/// from `OperationDescription` so the w1 contract type stays untouched.
#[derive(Clone, PartialEq, Debug)]
pub struct OpMeta {
    pub id: String,
    pub version: u32,
    pub capability: Capability,
    pub mutability: Mutability,
    pub summary: String,
}

pub struct Registry {
    ops: BTreeMap<(String, u32), Box<dyn ErasedOperation>>,
    reads: BTreeMap<(String, u32), Box<dyn ErasedReadOperation>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            ops: BTreeMap::new(),
            reads: BTreeMap::new(),
        }
    }

    pub fn register<O: Operation + Default + 'static>(&mut self) {
        let entry: Box<dyn ErasedOperation> = Box::new(OpEntry::<O>::default());
        self.ops.insert((O::ID.to_string(), O::VERSION), entry);
    }

    pub fn register_read<R: ReadOperation + Default + 'static>(&mut self) {
        let entry: Box<dyn ErasedReadOperation> = Box::new(ReadEntry::<R>::default());
        self.reads.insert((R::ID.to_string(), R::VERSION), entry);
    }

    /// Every registered operation and read operation, sorted by id then
    /// version.
    pub fn list(&self) -> Vec<OperationDescription> {
        let mut out: Vec<OperationDescription> =
            self.ops.values().map(|e| e.describe()).collect();
        out.extend(self.reads.values().map(|e| e.describe()));
        out
    }

    /// The description of an operation's latest registered version.
    pub fn describe(&self, id: &str) -> Option<OperationDescription> {
        self.ops
            .range((id.to_string(), u32::MIN)..(id.to_string(), u32::MAX))
            .next_back()
            .map(|(_, e)| e.describe())
            .or_else(|| {
                self.reads
                    .range((id.to_string(), u32::MIN)..(id.to_string(), u32::MAX))
                    .next_back()
                    .map(|(_, e)| e.describe())
            })
    }

    /// The version of an op's latest registered entry, whichever side of the
    /// registry hosts it.
    pub fn latest_version(&self, id: &str) -> Option<u32> {
        self.describe(id).map(|d| d.version)
    }

    /// The capability declared by a specific `(id, version)` entry, whether
    /// write op or read op. The engine's policy check is this one lookup.
    pub fn capability_of(&self, id: &str, version: u32) -> Option<Capability> {
        self.ops
            .get(&(id.to_string(), version))
            .map(|e| e.capability())
            .or_else(|| {
                self.reads
                    .get(&(id.to_string(), version))
                    .map(|e| e.capability())
            })
    }

    /// Every registered op and read op as catalog rows (id, version,
    /// capability, mutability, summary), sorted by id then version.
    pub fn list_meta(&self) -> Vec<OpMeta> {
        let mut out: Vec<OpMeta> = self
            .ops
            .iter()
            .map(|((id, version), e)| OpMeta {
                id: id.clone(),
                version: *version,
                capability: e.capability(),
                mutability: e.mutability(),
                summary: e.describe().summary,
            })
            .collect();
        out.extend(self.reads.iter().map(|((id, version), e)| OpMeta {
            id: id.clone(),
            version: *version,
            capability: e.capability(),
            mutability: Mutability::Read,
            summary: e.describe().summary,
        }));
        out
    }

    pub fn materialize(
        &self,
        project: &Project,
        req: &PlanRequest,
    ) -> Result<OperationPlan, OpError> {
        let entry = self
            .ops
            .get(&(req.op_id.clone(), req.op_version))
            .ok_or_else(|| OpError::UnknownOp(format!("{} v{}", req.op_id, req.op_version)))?;
        entry.materialize(project, req)
    }

    pub fn diff(&self, project: &Project, plan: &OperationPlan) -> Result<Diff, OpError> {
        let entry = self
            .ops
            .get(&(plan.op_id.clone(), plan.op_version))
            .ok_or_else(|| OpError::UnknownOp(format!("{} v{}", plan.op_id, plan.op_version)))?;
        entry.diff(project, plan)
    }

    pub fn validate(&self, project: &Project, plan: &OperationPlan) -> Vec<Finding> {
        self.ops
            .get(&(plan.op_id.clone(), plan.op_version))
            .map(|e| e.validate(project, plan))
            .unwrap_or_default()
    }

    pub fn apply(&self, tx: &mut Transaction, plan: OperationPlan) -> Result<serde_json::Value, OpError> {
        let entry = self
            .ops
            .get(&(plan.op_id.clone(), plan.op_version))
            .ok_or_else(|| OpError::UnknownOp(format!("{} v{}", plan.op_id, plan.op_version)))?;
        entry.apply(tx, &plan)
    }

    pub fn query(&self, project: &Project, req: &PlanRequest) -> Result<serde_json::Value, OpError> {
        let entry = self
            .reads
            .get(&(req.op_id.clone(), req.op_version))
            .ok_or_else(|| {
                OpError::UnknownOp(format!("{} v{}", req.op_id, req.op_version))
            })?;
        entry.query(project, req)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Registry::new()
    }
}

/// A deterministic plan id: nothing random names a plan (ADR-0010). Derived
/// from the envelope, the base revision, the materialized payload, and the
/// engine/module versions — the same request against the same project yields
/// the same plan id, and a hand-edited payload in a saved plan file can no
/// longer match it.
fn plan_id(
    req: &PlanRequest,
    base_revision: &str,
    payload: &serde_json::Value,
    engine_version: &str,
    module_versions: &BTreeMap<String, String>,
) -> String {
    let mut domain = serde_json::to_vec(req).expect("envelope serializes");
    domain.extend_from_slice(base_revision.as_bytes());
    domain.extend_from_slice(&format_value(payload));
    domain.extend_from_slice(engine_version.as_bytes());
    domain.extend_from_slice(&format_value(
        &serde_json::to_value(module_versions).expect("module versions serialize"),
    ));
    format!("plan_{}", &sha256_hex(&domain)[..16])
}

/// The plan id a given request would receive for the given plan contents —
/// the same deterministic derivation `materialize` uses, exposed so the
/// engine can verify a stored plan file still matches its request envelope,
/// payload, and version stamps.
pub fn expected_plan_id(req: &PlanRequest, plan: &OperationPlan) -> String {
    plan_id(
        req,
        &plan.base_project_revision,
        &plan.payload,
        &plan.engine_version,
        &plan.module_versions,
    )
}

trait ErasedOperation: Send + Sync {
    fn describe(&self) -> OperationDescription;
    fn capability(&self) -> Capability;
    fn mutability(&self) -> Mutability;
    fn materialize(&self, project: &Project, req: &PlanRequest) -> Result<OperationPlan, OpError>;
    fn diff(&self, project: &Project, plan: &OperationPlan) -> Result<Diff, OpError>;
    fn validate(&self, project: &Project, plan: &OperationPlan) -> Vec<Finding>;
    fn apply(&self, tx: &mut Transaction, plan: &OperationPlan) -> Result<serde_json::Value, OpError>;
}

struct OpEntry<O: Operation> {
    op: O,
    _marker: PhantomData<fn()>,
}

impl<O: Operation + Default> Default for OpEntry<O> {
    fn default() -> Self {
        OpEntry {
            op: O::default(),
            _marker: PhantomData,
        }
    }
}

impl<O: Operation + 'static> ErasedOperation for OpEntry<O> {
    fn describe(&self) -> OperationDescription {
        O::describe()
    }

    fn capability(&self) -> Capability {
        O::CAPABILITY
    }

    fn mutability(&self) -> Mutability {
        O::MUTABILITY
    }

    fn materialize(&self, project: &Project, req: &PlanRequest) -> Result<OperationPlan, OpError> {
        let request: O::Request = serde_json::from_value(req.input.clone())
            .map_err(|e| OpError::InvalidRequest(e.to_string()))?;
        self.op.validate_request(&request)?;
        let plan = self.op.materialize(project, request)?;
        let payload =
            serde_json::to_value(&plan).map_err(|e| OpError::Materialize(e.to_string()))?;
        let engine_version = project.manifest.engine.version.clone();
        let module_versions: BTreeMap<String, String> = project
            .manifest
            .modules
            .iter()
            .map(|(id, entry)| (id.clone(), entry.version.clone()))
            .collect();
        Ok(OperationPlan {
            plan_id: plan_id(
                req,
                &project.manifest.project_revision,
                &payload,
                &engine_version,
                &module_versions,
            ),
            op_id: req.op_id.clone(),
            op_version: req.op_version,
            base_project_revision: project.manifest.project_revision.clone(),
            base_project_hash: project.manifest.project_hash.clone(),
            engine_version,
            module_versions,
            payload,
        })
    }

    fn diff(&self, project: &Project, plan: &OperationPlan) -> Result<Diff, OpError> {
        let plan: O::Plan = serde_json::from_value(plan.payload.clone())
            .map_err(|e| OpError::Diff(e.to_string()))?;
        self.op.diff(project, &plan)
    }

    fn validate(&self, project: &Project, plan: &OperationPlan) -> Vec<Finding> {
        match serde_json::from_value::<O::Plan>(plan.payload.clone()) {
            Ok(plan) => self.op.validate(project, &plan),
            Err(_) => Vec::new(),
        }
    }

    fn apply(&self, tx: &mut Transaction, plan: &OperationPlan) -> Result<serde_json::Value, OpError> {
        let plan: O::Plan = serde_json::from_value(plan.payload.clone())
            .map_err(|e| OpError::Apply(e.to_string()))?;
        let output = self.op.apply(tx, plan)?;
        serde_json::to_value(&output).map_err(|e| OpError::Apply(e.to_string()))
    }
}

trait ErasedReadOperation: Send + Sync {
    fn describe(&self) -> OperationDescription;
    fn capability(&self) -> Capability;
    fn query(&self, project: &Project, req: &PlanRequest) -> Result<serde_json::Value, OpError>;
}

struct ReadEntry<R: ReadOperation> {
    op: R,
    _marker: PhantomData<fn()>,
}

impl<R: ReadOperation + Default> Default for ReadEntry<R> {
    fn default() -> Self {
        ReadEntry {
            op: R::default(),
            _marker: PhantomData,
        }
    }
}

impl<R: ReadOperation + 'static> ErasedReadOperation for ReadEntry<R> {
    fn describe(&self) -> OperationDescription {
        R::describe()
    }

    fn capability(&self) -> Capability {
        R::CAPABILITY
    }

    fn query(&self, project: &Project, req: &PlanRequest) -> Result<serde_json::Value, OpError> {
        let request: R::Request = serde_json::from_value(req.input.clone())
            .map_err(|e| OpError::InvalidRequest(e.to_string()))?;
        self.op.validate_request(&request)?;
        let output = self.op.query(project, request)?;
        serde_json::to_value(&output).map_err(|e| OpError::Apply(e.to_string()))
    }
}
