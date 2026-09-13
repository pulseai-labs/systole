//! CLI command implementations and the composition root (ADR-0002): the
//! binary links core and rpg, and modules register at startup.

pub mod apply;
pub mod check;
pub mod doctor;
pub mod format;
pub mod init;
pub mod op;
pub mod plan;
pub mod preview;
pub mod query;
pub mod rollback;
pub mod validate;

use std::path::Path;

use systole_core::engine::{Engine, EngineError};
use systole_core::finding::Finding;
use systole_core::ir::format::format_value;
use systole_core::ir::project::ProjectError;
use systole_core::module::{CoreModule, Module, ModuleManifest};
use systole_core::op::{Diff, Mutability, OperationPlan, OpError, PlanRequest};
use systole_core::registry::Registry;

/// Build the registry from `systole.core` and `systole.rpg`, and collect the
/// module manifests a new project records. The engine itself is not a project
/// module; only genre modules go into `project.systole.json`.
pub fn compose() -> (Registry, Vec<ModuleManifest>) {
    let mut registry = Registry::new();
    let core = CoreModule;
    let rpg = systole_rpg::RpgModule;
    core.register(&mut registry);
    rpg.register(&mut registry);
    #[cfg(feature = "fixture-ops")]
    {
        registry.register::<systole_core::fixture::PutNote>();
        registry.register::<systole_core::fixture::Forbidden>();
        registry.register_read::<systole_core::fixture::GetNote>();
    }
    (registry, vec![rpg.manifest()])
}

/// Every registered module validator, in registration order — `validate`
/// and `plan --from-finding` run them, and doctor runs them after an absorb.
pub fn module_validators() -> Vec<Box<dyn systole_core::module::Validator>> {
    let mut out = CoreModule.validators();
    out.extend(systole_rpg::RpgModule.validators());
    out
}

/// The verified engine every command path uses: project load, pending-marker
/// and audit-chain checks, plus the module validators attached so preview and
/// commit gate on blocking findings.
pub fn open_engine(
    root: &Path,
) -> Result<systole_core::engine::Engine, systole_core::engine::EngineError> {
    let (registry, _) = compose();
    Engine::open(root, registry).map(|e| e.with_validators(module_validators()))
}

/// The kill switch (risk gate `ir-integrity`): `SYSTOLE_READ_ONLY=1` refuses
/// every write path without a rebuild. One definition, in the engine — the
/// CLI re-exports it so the predicate cannot drift between crates.
pub use systole_core::engine::is_read_only;

/// Resolve a project root in ADR-0001 order: `--project`, `$SYSTOLE_PROJECT`,
/// the current directory.
pub fn project_root(explicit: Option<&Path>) -> std::path::PathBuf {
    if let Some(p) = explicit {
        return absolutize(p);
    }
    if let Some(env) = std::env::var_os("SYSTOLE_PROJECT") {
        return absolutize(Path::new(&env));
    }
    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

pub fn absolutize(path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(path)
    }
}

/// Print a project error to stderr and return its exit code. Integrity
/// refusals render the fixed multi-line refusal text (ADR-0006): the reason,
/// one line per changed file, the recorded revision, and the repair hint
/// (`doctor` itself is w2; the hint text is fixed now).
pub fn report_project_error(root: &Path, err: &ProjectError) -> i32 {
    match err {
        ProjectError::Integrity(integrity) => {
            eprintln!("refused: project files changed outside a transaction");
            for path in &integrity.changed {
                eprintln!("  changed: {path}");
            }
            let revision = recorded_revision(root);
            eprintln!("recorded revision {revision}");
            eprintln!("systole project doctor --absorb");
        }
        other => eprintln!("{other}"),
    }
    2
}

/// Best-effort read of the manifest's recorded revision for refusal text.
fn recorded_revision(root: &Path) -> String {
    std::fs::read(root.join(systole_core::ir::MANIFEST_FILE))
        .ok()
        .and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| {
                    v.get("project_revision")
                        .and_then(|r| r.as_str())
                        .map(str::to_string)
                })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

// --- transaction verbs ------------------------------------------------------

/// The durable plan artifact (`plans/<plan_id>.json` or `--out`): the request
/// envelope plus the engine plan. The plan id is derived from the envelope, so
/// a saved plan must carry it for `apply` to re-verify agreement.
pub struct PlanFile {
    pub request: PlanRequest,
    pub plan: OperationPlan,
}

impl PlanFile {
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "request": serde_json::to_value(&self.request).expect("a request serializes"),
            "plan": serde_json::to_value(&self.plan).expect("a plan serializes"),
        })
    }

    pub fn from_value(value: &serde_json::Value) -> Result<PlanFile, String> {
        let request = serde_json::from_value::<PlanRequest>(
            value.get("request").cloned().unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| format!("plan file has no valid request: {e}"))?;
        let plan = serde_json::from_value::<OperationPlan>(
            value.get("plan").cloned().unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| format!("plan file has no valid plan: {e}"))?;
        Ok(PlanFile { request, plan })
    }
}

/// The fixed actor the CLI adapter sends on every request (ADR-0005).
pub const CLI_ACTOR: &str = "cli_local";

/// Parse an `--input` argument: `@file` reads JSON from a file, `-` reads
/// stdin, anything else is the JSON literal.
pub fn read_input(raw: &str) -> Result<serde_json::Value, String> {
    use std::io::Read;
    let text = if let Some(path) = raw.strip_prefix('@') {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?
    } else if raw == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        buf
    } else {
        raw.to_string()
    };
    serde_json::from_str(&text).map_err(|e| format!("invalid JSON input: {e}"))
}

/// Write a plan file as canonical JSON.
pub fn write_plan_file(path: &Path, file: &PlanFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {parent:?}: {e}"))?;
    }
    systole_core::ir::writer::write_atomic(path, &format_value(&file.to_value()))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Read a plan file back.
pub fn read_plan_file(path: &Path) -> Result<PlanFile, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not a plan file: {e}", path.display()))?;
    PlanFile::from_value(&value)
        .map_err(|e| format!("{} is not a plan file: {e}", path.display()))
}

pub fn mutability_str(m: Mutability) -> &'static str {
    match m {
        Mutability::Read => "read",
        Mutability::Write => "write",
        Mutability::Destructive => "destructive",
    }
}

/// `+ create`, `~ modify`, `- delete` — one line per change, and the canonical
/// before/after values under `--verbose`.
pub fn print_diff(diff: &Diff, verbose: bool) {
    for change in &diff.changes {
        let glyph = match (&change.before, &change.after) {
            (None, Some(_)) => "+",
            (Some(_), None) => "-",
            _ => "~",
        };
        println!("{glyph} {}", change.path);
        if verbose {
            for (label, value) in [("before", &change.before), ("after", &change.after)] {
                let text = match value {
                    Some(v) => String::from_utf8_lossy(&format_value(v)).to_string(),
                    None => "null\n".to_string(),
                };
                for line in text.lines() {
                    println!("  {label}: {line}");
                }
            }
        }
    }
}

/// One stderr line per finding, blocking ones marked.
pub fn print_findings(findings: &[Finding]) {
    for f in findings {
        eprintln!(
            "{}{}{}",
            f.code,
            if f.blocking { " (blocking)" } else { "" },
            f.location
                .path
                .as_ref()
                .map(|p| format!(" at {p}"))
                .unwrap_or_default(),
        );
    }
}

/// Print a structured refusal: `{ "error": { "code", "message" } }` on stdout
/// under `--json` (with `project_root`), human text on stderr otherwise.
/// Returns the exit code (ADR-0004's ladder: 1 = not-applicable/refused-by-
/// state, 2 = refused/error).
pub fn report_engine_error(root: &Path, err: &EngineError, json: bool) -> i32 {
    if let EngineError::Project(pe) = err {
        if !json {
            return report_project_error(root, pe);
        }
        // Under --json even integrity refusals are structured.
        return report_structured(root, "project.integrity", &err.to_string(), 2, json);
    }
    let (code, exit) = error_code(err);
    if json {
        report_structured(root, code, &err.to_string(), exit, json)
    } else {
        eprintln!("{err}");
        if let EngineError::Blocked(findings) = err {
            print_findings(findings);
        }
        exit
    }
}

/// The structured code and exit code for an engine error (ADR-0004's ladder:
/// 1 = not-applicable/refused-by-state, 2 = refused/error).
fn error_code(err: &EngineError) -> (&'static str, i32) {
    match err {
        EngineError::ReadOnly => ("project.read_only", 2),
        EngineError::CapabilityDenied { .. } => ("capability.denied", 2),
        EngineError::ApprovalRequired { .. } => ("capability.approval_required", 2),
        EngineError::StalePlan { .. } => ("plan.stale", 1),
        EngineError::Blocked(_) => ("plan.blocked", 1),
        EngineError::InvalidRequest(_) => ("op.invalid_request", 2),
        EngineError::Locked { .. } => ("project.locked", 2),
        EngineError::NotHead { .. } => ("audit.not_head", 1),
        EngineError::NotReversible { .. } => ("audit.not_reversible", 1),
        EngineError::PendingTransactions { .. } => ("project.pending_transaction", 2),
        EngineError::Chain(_) => ("audit.chain_broken", 2),
        EngineError::Op(OpError::UnknownOp(_)) => ("op.unknown", 2),
        EngineError::Op(OpError::InvalidRequest(_)) => ("op.invalid_request", 2),
        EngineError::Op(_) => ("op.failed", 2),
        EngineError::Commit(_) | EngineError::Io(_) => ("engine.io", 2),
        EngineError::Project(_) => ("project.integrity", 2),
    }
}

/// A structured refusal outside the engine-error ladder (finding selection,
/// CLI usage): `{"error": {code, message}, "project_root"}` on stdout under
/// `--json`, the message on stderr otherwise.
pub fn structured_refusal(
    root: &Path,
    code: &str,
    message: &str,
    exit: i32,
    json: bool,
) -> i32 {
    report_structured(root, code, message, exit, json)
}

fn report_structured(
    root: &Path,
    code: &str,
    message: &str,
    exit: i32,
    json: bool,
) -> i32 {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "error": { "code": code, "message": message },
                "project_root": root.display().to_string(),
            })
        );
    } else {
        eprintln!("{message}");
    }
    exit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_input_accepts_a_json_literal() {
        let v = read_input(r#"{"text":"hello"}"#).unwrap();
        assert_eq!(v["text"], "hello");
    }

    #[test]
    fn read_input_rejects_malformed_json() {
        assert!(read_input("{nope").is_err());
    }

    #[test]
    fn the_plan_file_round_trips_its_envelope() {
        let file = PlanFile {
            request: PlanRequest {
                op_id: "fixture.put_note".into(),
                op_version: 1,
                input: serde_json::json!({ "text": "x" }),
                actor: CLI_ACTOR.into(),
            },
            plan: OperationPlan {
                plan_id: "plan_x".into(),
                op_id: "fixture.put_note".into(),
                op_version: 1,
                base_project_revision: "rev_00000".into(),
                base_project_hash: "sha256:a".into(),
                engine_version: "0.1.0".into(),
                module_versions: Default::default(),
                payload: serde_json::json!({ "text": "x" }),
            },
        };
        let value = file.to_value();
        let back = PlanFile::from_value(&value).unwrap();
        assert_eq!(back.request.actor, "cli_local");
        assert_eq!(back.plan.plan_id, "plan_x");
    }

    #[test]
    fn engine_errors_map_to_their_structured_codes_and_exits() {
        let cases: [(EngineError, &str, i32); 12] = [
            (EngineError::ReadOnly, "project.read_only", 2),
            (
                EngineError::CapabilityDenied {
                    op_id: "o".into(),
                    capability: "c".into(),
                    actor: "a".into(),
                },
                "capability.denied",
                2,
            ),
            (
                EngineError::ApprovalRequired {
                    op_id: "o".into(),
                    capability: "c".into(),
                    stable_id: None,
                },
                "capability.approval_required",
                2,
            ),
            (
                EngineError::StalePlan {
                    base: "rev_0".into(),
                    current: "rev_1".into(),
                    hint: "h".into(),
                },
                "plan.stale",
                1,
            ),
            (EngineError::Blocked(vec![]), "plan.blocked", 1),
            (
                EngineError::InvalidRequest("x".into()),
                "op.invalid_request",
                2,
            ),
            (EngineError::Locked { pid: 1 }, "project.locked", 2),
            (
                EngineError::NotHead {
                    requested: "aud_1".into(),
                    head: Some("aud_2".into()),
                },
                "audit.not_head",
                1,
            ),
            (
                EngineError::NotReversible {
                    audit_id: "aud_1".into(),
                    reason: "r".into(),
                },
                "audit.not_reversible",
                1,
            ),
            (
                EngineError::Op(OpError::UnknownOp("o".into())),
                "op.unknown",
                2,
            ),
            (
                EngineError::Op(OpError::InvalidRequest("r".into())),
                "op.invalid_request",
                2,
            ),
            (
                EngineError::Op(OpError::Apply("a".into())),
                "op.failed",
                2,
            ),
        ];
        for (err, code, exit) in cases {
            assert_eq!(error_code(&err), (code, exit), "for {err}");
        }
        assert_eq!(error_code(&EngineError::Io("io".into())), ("engine.io", 2));
    }
}
