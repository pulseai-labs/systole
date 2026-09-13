//! The engine facade (ADR-0007): load → resolve capability → materialize →
//! diff → validate → commit → audit, with `preview` as the side-effect-free
//! half and `commit`/`rollback`/`query` the explicit verbs.
//!
//! Ordering inside `commit`, per the spec: request↔plan agreement, capability
//! re-check (the plan may have been made under another actor), stale-plan
//! refusal, preview re-run for blocking findings, write lock, apply into a
//! fresh `Transaction`, two-phase commit, release, reload.

use std::path::{Path, PathBuf};

use crate::audit::{self, AuditEntry, ChainBreak};
use crate::capability::{Capability, Decision, Policy};
use crate::finding::Finding;
use crate::ir::project::{Project, ProjectError};
use crate::ir::RelPath;
use crate::lock::{LockError, WriteLock};
use crate::op::{Diff, FileChange, OpError, OperationPlan, PlanRequest};
use crate::registry::{expected_plan_id, Registry};
use crate::tx::commit::{self, CommitMeta};
use crate::tx::Transaction;

/// `SYSTOLE_READ_ONLY=1` refuses every engine write path.
pub fn is_read_only() -> bool {
    std::env::var("SYSTOLE_READ_ONLY").as_deref() == Ok("1")
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error(transparent)]
    Op(#[from] OpError),
    #[error(transparent)]
    Chain(#[from] ChainBreak),
    #[error("{0}")]
    Commit(#[from] commit::CommitError),
    #[error("{0}")]
    Io(String),
    #[error("refused: SYSTOLE_READ_ONLY=1")]
    ReadOnly,
    #[error("capability denied: {op_id} requires {capability} (actor {actor})")]
    CapabilityDenied {
        op_id: String,
        capability: String,
        actor: String,
    },
    #[error(
        "approval required: {op_id} requires {capability} — \
         interactive approval is not available in Release 0"
    )]
    ApprovalRequired {
        op_id: String,
        capability: String,
        stable_id: Option<String>,
    },
    #[error("stale plan: based on {base}, current is {current}; {hint}")]
    StalePlan {
        base: String,
        current: String,
        hint: String,
    },
    #[error("request does not match plan: {0}")]
    InvalidRequest(String),
    #[error("plan blocked by findings")]
    Blocked(Vec<Finding>),
    #[error("project is locked by pid {pid}")]
    Locked { pid: u32 },
    #[error("not head: requested {requested}, head is {}", head.as_deref().unwrap_or("<none>"))]
    NotHead {
        requested: String,
        head: Option<String>,
    },
    #[error("audit entry {audit_id} is not reversible ({reason})")]
    NotReversible { audit_id: String, reason: String },
    #[error(
        "{count} pending transaction marker(s) under audit/pending — \
         run `systole project doctor` to resolve them
    ")]
    PendingTransactions { count: usize },
}

pub struct Engine {
    root: PathBuf,
    project: Project,
    registry: Registry,
}

/// The result of `preview`: the diff plus every finding. Read-only — nothing
/// is staged, written, or audited.
pub struct Preview {
    pub diff: Diff,
    pub findings: Vec<Finding>,
    pub blocking: bool,
}

impl Engine {
    /// Load + verify the project and bind a registry. Any integrity or audit
    /// refusal surfaces here — callers (the CLI) map it to exit 2.
    pub fn open(root: &Path, registry: Registry) -> Result<Engine, EngineError> {
        let project = Project::load(root)?;
        // A leftover crash marker means a transaction died mid-commit: every
        // operation refuses until `doctor` resolves it. Checked before the
        // chain because the marker state explains a torn log better than a
        // bare chain break.
        let pending = commit::pending_marker_files(root)?;
        if !pending.is_empty() {
            return Err(EngineError::PendingTransactions {
                count: pending.len(),
            });
        }
        // The audit log lives outside the project hash: an edited or
        // truncated audit.jsonl is refused here rather than silently
        // re-extended. `doctor` is the only unverified path
        // (Project::load_unverified).
        audit::verify_chain(root, project.manifest.audit_head.as_ref())?;
        Ok(Engine {
            root: root.to_path_buf(),
            project,
            registry,
        })
    }

    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    fn acquire_lock(&self) -> Result<WriteLock, EngineError> {
        WriteLock::acquire(&self.root).map_err(|e| match e {
            LockError::Held { pid } => EngineError::Locked { pid },
            LockError::Io(e) => EngineError::Io(e.to_string()),
        })
    }

    /// The capability gate shared by materialize, commit and query (ADR-0005):
    /// one lookup against the static policy table. Deny and prompt both refuse;
    /// interactive approval does not exist in Release 0.
    fn check_policy(
        &self,
        op_id: &str,
        op_version: u32,
        actor: &str,
    ) -> Result<Capability, EngineError> {
        let capability = self
            .registry
            .capability_of(op_id, op_version)
            .ok_or_else(|| OpError::UnknownOp(format!("{op_id} v{op_version}")))?;
        match Policy::resolve(actor, capability) {
            Decision::Allow => Ok(capability),
            Decision::Deny => Err(EngineError::CapabilityDenied {
                op_id: op_id.to_string(),
                capability: capability.as_str().to_string(),
                actor: actor.to_string(),
            }),
            Decision::Prompt => Err(EngineError::ApprovalRequired {
                op_id: op_id.to_string(),
                capability: capability.as_str().to_string(),
                stable_id: None,
            }),
        }
    }

    /// Request → plan, under the capability policy. Deterministic and pure.
    pub fn materialize(&self, req: &PlanRequest) -> Result<OperationPlan, EngineError> {
        self.check_policy(&req.op_id, req.op_version, &req.actor)?;
        Ok(self.registry.materialize(&self.project, req)?)
    }

    /// plan → diff → validate. Never stages, writes, or audits.
    pub fn preview(&self, plan: &OperationPlan) -> Result<Preview, EngineError> {
        let diff = self.registry.diff(&self.project, plan)?;
        let findings = self.registry.validate(&self.project, plan);
        let blocking = findings.iter().any(|f| f.blocking);
        Ok(Preview {
            diff,
            findings,
            blocking,
        })
    }

    /// plan → audit. The only way the project changes.
    pub fn commit(
        &mut self,
        req: &PlanRequest,
        plan: OperationPlan,
    ) -> Result<AuditEntry, EngineError> {
        if is_read_only() {
            return Err(EngineError::ReadOnly);
        }

        // The plan must name this request (W2-A1: actor is envelope-only).
        if req.op_id != plan.op_id || req.op_version != plan.op_version {
            return Err(EngineError::InvalidRequest(format!(
                "request {} v{} vs plan {} v{}",
                req.op_id, req.op_version, plan.op_id, plan.op_version
            )));
        }
        if expected_plan_id(req, &plan) != plan.plan_id {
            return Err(EngineError::InvalidRequest(
                "plan_id does not match this request, payload, and version stamps"
                    .into(),
            ));
        }

        // Capability re-check at commit — a plan may have been materialized
        // under a different actor or before a policy change.
        let capability = self.check_policy(&plan.op_id, plan.op_version, &req.actor)?;

        // The write lock comes before every read of mutable state: a
        // concurrent commit must not land between the staleness check and the
        // rename phase. Reload under the lock and validate against that
        // snapshot, not the open-time one.
        let _lock = self.acquire_lock()?;
        self.project = Project::load(&self.root)?;

        // A marker could have been left between open and this commit — the
        // locked snapshot is where mutable state is read, so the refusal
        // lives here too (commit::run re-checks as the funnel).
        let pending = commit::pending_marker_files(&self.root)?;
        if !pending.is_empty() {
            return Err(EngineError::PendingTransactions {
                count: pending.len(),
            });
        }

        // Stale-plan refusal: the plan is bound to the exact revision+hash it
        // was materialized against.
        let manifest = &self.project.manifest;
        if plan.base_project_revision != manifest.project_revision
            || plan.base_project_hash != manifest.project_hash
        {
            return Err(EngineError::StalePlan {
                base: format!(
                    "{} ({})",
                    plan.base_project_revision, plan.base_project_hash
                ),
                current: format!(
                    "{} ({})",
                    manifest.project_revision, manifest.project_hash
                ),
                hint: "re-run systole plan against the current revision".into(),
            });
        }

        // Version stamps: a plan materialized by another engine build or
        // module set must not apply under this one.
        let running_engine = crate::ir::manifest::engine_version();
        if plan.engine_version != running_engine {
            return Err(EngineError::InvalidRequest(format!(
                "plan was materialized by engine {0}; running engine is {1}",
                plan.engine_version, running_engine
            )));
        }
        let current_modules: std::collections::BTreeMap<String, String> = self
            .project
            .manifest
            .modules
            .iter()
            .map(|(id, entry)| (id.clone(), entry.version.clone()))
            .collect();
        if plan.module_versions != current_modules {
            return Err(EngineError::InvalidRequest(
                "plan module versions do not match the project's module set".into(),
            ));
        }

        // The staleness check above proved the project is still in the
        // plan's base state, so re-materializing the recorded request must
        // reproduce the payload exactly — a hand-edited payload in a saved
        // plan refuses here rather than applying unvalidated.
        let rematerialized = self.registry.materialize(&self.project, req)?;
        if rematerialized.payload != plan.payload {
            return Err(EngineError::InvalidRequest(
                "plan payload does not match the recorded request".into(),
            ));
        }

        // Preview again: blocking findings refuse before anything is staged.
        let preview = self.preview(&plan)?;
        if preview.blocking {
            return Err(EngineError::Blocked(preview.findings));
        }

        let mut tx = Transaction::new(&self.project);
        let output = self.registry.apply(&mut tx, plan.clone())?;
        let entry = commit::run(
            &self.root,
            &self.project,
            tx.staged(),
            tx.staged(),
            tx.stable_id_counter(),
            CommitMeta {
                actor: req.actor.clone(),
                op_id: plan.op_id.clone(),
                op_version: plan.op_version,
                input: req.input.clone(),
                plan_id: Some(plan.plan_id.clone()),
                capability: capability.as_str().to_string(),
                approval: "allow".into(),
                rollback_of: None,
                output,
            },
        )?;

        self.project = Project::load(&self.root)?;
        Ok(entry)
    }

    /// Compensating-transaction rollback (ADR-0007): head-only, restores every
    /// `before` image from the head entry's diff, and appends a new entry with
    /// `rollback_of` — never removes history.
    pub fn rollback(&mut self, audit_id: &str) -> Result<AuditEntry, EngineError> {
        if is_read_only() {
            return Err(EngineError::ReadOnly);
        }

        // The lock precedes the head-only check: a newer transaction must not
        // commit between this check and the compensating one.
        let _lock = self.acquire_lock()?;
        self.project = Project::load(&self.root)?;

        let head = self
            .project
            .manifest
            .audit_head
            .as_ref()
            .map(|h| h.id.clone());
        if head.as_deref() != Some(audit_id) {
            return Err(EngineError::NotHead {
                requested: audit_id.to_string(),
                head,
            });
        }

        // Re-read the head entry from the log.
        let lines = audit::read_lines(&self.root).map_err(|e| EngineError::Io(e.to_string()))?;
        let last_line = lines
            .last()
            .ok_or_else(|| EngineError::Io("audit log is empty".into()))?;
        let target: AuditEntry = serde_json::from_slice(last_line)
            .map_err(|e| EngineError::Io(format!("cannot parse head entry: {e}")))?;
        if target.audit_id != audit_id {
            return Err(EngineError::Io(format!(
                "head entry is {}, not {audit_id}",
                target.audit_id
            )));
        }
        if target.op_id == "core.external_edit" {
            return Err(EngineError::NotReversible {
                audit_id: audit_id.to_string(),
                reason: "external_edit".into(),
            });
        }

        // Inverse diff: each change's before becomes its after.
        let inverse: Vec<FileChange> = target
            .changes
            .iter()
            .map(|c| FileChange {
                path: RelPath::new(c.path.as_str()),
                before: c.after.clone(),
                after: c.before.clone(),
            })
            .collect();

        let entry = commit::run(
            &self.root,
            &self.project,
            &inverse,
            &inverse,
            self.project.manifest.stable_id_counter,
            CommitMeta {
                actor: "cli_local".into(),
                op_id: "core.rollback".into(),
                op_version: 1,
                input: serde_json::json!({ "audit_id": audit_id }),
                plan_id: None,
                capability: "project.write".into(),
                approval: "allow".into(),
                rollback_of: Some(audit_id.to_string()),
                output: serde_json::Value::Null,
            },
        )?;

        self.project = Project::load(&self.root)?;
        Ok(entry)
    }

    /// Read-side dispatch for read operations.
    pub fn query(&self, req: &PlanRequest) -> Result<serde_json::Value, EngineError> {
        self.check_policy(&req.op_id, req.op_version, &req.actor)?;
        Ok(self.registry.query(&self.project, req)?)
    }
}
