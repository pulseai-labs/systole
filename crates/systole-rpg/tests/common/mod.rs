//! Shared test helpers: an in-memory `Project` (nothing touches disk) and a
//! runner that drives one envelope through the registry's full dispatch path.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;
use systole_core::finding::Finding;
use systole_core::ir::lock::Lock;
use systole_core::ir::manifest::{Engine, Manifest, ModuleEntry};
use systole_core::ir::project::Project;
use systole_core::ir::RelPath;
use systole_core::module::{CoreModule, Module};
use systole_core::op::{FileChange, OpError, PlanRequest};
use systole_core::registry::Registry;
use systole_core::tx::Transaction;
use systole_rpg::RpgModule;

/// The composition root's view: `CoreModule` + `RpgModule`.
pub fn registry() -> Registry {
    let mut registry = Registry::new();
    CoreModule.register(&mut registry);
    RpgModule.register(&mut registry);
    registry
}

/// A project in the post-init state at `rev_00000` with no files.
pub fn project() -> Project {
    let engine = Engine {
        name: "systole".into(),
        version: "0.1.0".into(),
    };
    let mut modules = BTreeMap::new();
    modules.insert(
        "systole.rpg".to_string(),
        ModuleEntry {
            version: "0.1.0".into(),
            schema: 1,
        },
    );
    let mut lock_modules = BTreeMap::new();
    lock_modules.insert("systole.rpg".to_string(), "0.1.0".to_string());
    Project {
        root: PathBuf::new(),
        manifest: Manifest {
            engine: engine.clone(),
            project_schema: 1,
            modules,
            stable_id_counter: 0,
            project_revision: "rev_00000".into(),
            project_hash: "sha256:test".into(),
            audit_head: None,
            files: BTreeMap::new(),
        },
        lock: Lock {
            engine,
            modules: lock_modules,
        },
        files: BTreeMap::new(),
    }
}

#[allow(dead_code)]
pub struct StepOutcome {
    pub output: Value,
    pub findings: Vec<Finding>,
    pub staged: Vec<FileChange>,
    pub inverse: Value,
}

/// Drive one request through `validate_request` → `materialize` → `diff` →
/// `validate` → `apply` (the read op goes through `query` instead) and merge
/// the staged writes into the project — the in-memory stand-in for w2's
/// commit. A blocking finding stops the step before apply, as the lifecycle
/// will.
pub fn run(project: &mut Project, op_id: &str, input: Value) -> Result<StepOutcome, OpError> {
    let registry = registry();
    let req = PlanRequest {
        op_id: op_id.to_string(),
        op_version: 1,
        input,
        actor: "test".into(),
    };
    let plan = match registry.materialize(project, &req) {
        Ok(plan) => plan,
        Err(OpError::UnknownOp(_)) => {
            let output = registry.query(project, &req)?;
            return Ok(StepOutcome {
                output,
                findings: Vec::new(),
                staged: Vec::new(),
                inverse: Value::Null,
            });
        }
        Err(e) => return Err(e),
    };
    registry.diff(project, &plan)?;
    let findings = registry.validate(project, &plan);
    if findings.iter().any(|f| f.blocking) {
        return Ok(StepOutcome {
            output: Value::Null,
            findings,
            staged: Vec::new(),
            inverse: Value::Null,
        });
    }
    let mut tx = Transaction::new(project);
    let output = registry.apply(&mut tx, plan)?;
    let staged = tx.staged().to_vec();
    let inverse = tx.inverse().clone();
    merge(project, &staged);
    bump_counter(project);
    Ok(StepOutcome {
        output,
        findings,
        staged,
        inverse,
    })
}

fn merge(project: &mut Project, staged: &[FileChange]) {
    for change in staged {
        match &change.after {
            Some(value) => {
                project.files.insert(change.path.clone(), value.clone());
            }
            None => {
                project.files.remove(&change.path);
            }
        }
    }
}

/// Advance the manifest's shared counter past every stable id in the files —
/// what a commit will persist in w2.
fn bump_counter(project: &mut Project) {
    let mut max = project.manifest.stable_id_counter;
    for value in project.files.values() {
        collect_stable_ids(value, &mut max);
    }
    project.manifest.stable_id_counter = max;
}

fn collect_stable_ids(value: &Value, max: &mut u64) {
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                if key == "stable_id" || key == "region_stable_id" {
                    if let Some(n) = v.as_str().and_then(suffix_number) {
                        *max = (*max).max(n);
                    }
                }
                collect_stable_ids(v, max);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_stable_ids(item, max);
            }
        }
        _ => {}
    }
}

fn suffix_number(s: &str) -> Option<u64> {
    s.rsplit_once('_')?.1.parse().ok()
}

/// Replay a transaction's inverse data over `files`: each staged path returns
/// to its before-image (removed when that image is null).
#[allow(dead_code)]
pub fn restore_inverse(
    files: &BTreeMap<RelPath, Value>,
    staged: &[FileChange],
    inverse: &Value,
) -> BTreeMap<RelPath, Value> {
    let mut out = files.clone();
    for change in staged {
        match inverse.get(change.path.as_str()) {
            Some(Value::Null) => {
                out.remove(&change.path);
            }
            Some(v) => {
                out.insert(change.path.clone(), v.clone());
            }
            None => {}
        }
    }
    out
}
