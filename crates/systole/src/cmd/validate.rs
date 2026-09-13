//! `systole validate [--all] [--json]` — run every registered module
//! validator over the loaded project and print the findings (ADR-0004,
//! ADR-0010): a pure function of project state — nothing is written, staged,
//! or audited, and the read-only kill switch allows it.

use std::path::Path;

use super::{compose, module_validators, report_engine_error};
use systole_core::engine::Engine;
use systole_core::finding::Finding;

pub fn run(root: &Path, json: bool) -> i32 {
    let (registry, _) = compose();
    let engine = match Engine::open(root, registry) {
        Ok(e) => e,
        Err(e) => return report_engine_error(root, &e, json),
    };
    let findings = validate(engine.project());
    let blocking = findings.iter().filter(|f| f.blocking).count();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": blocking == 0,
                "project_root": root.display().to_string(),
                "findings": findings,
            })
        );
    } else {
        for f in &findings {
            println!(
                "{} {} {} {} — {} (fixes: {})",
                if f.blocking { "blocking" } else { "advisory" },
                f.code,
                f.location.stable_id.as_deref().unwrap_or("-"),
                f.location
                    .path
                    .as_ref()
                    .map(|p| p.as_str())
                    .unwrap_or("-"),
                summary(f),
                f.suggested_fixes.len(),
            );
        }
        println!(
            "validate: {} findings, {} blocking",
            findings.len(),
            blocking
        );
    }
    if blocking > 0 {
        1
    } else {
        0
    }
}

/// Every module validator over the project, concatenated in registration
/// order and sorted by `finding_id` (ADR-0010). Shared with
/// `plan --from-finding`.
pub fn validate(project: &systole_core::ir::project::Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for v in module_validators() {
        findings.extend(v.run(project));
    }
    findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    findings
}

/// The finding's one-line rendering: its `message` when the kernel cannot
/// repair it, else a compact evidence summary.
fn summary(f: &Finding) -> String {
    f.evidence
        .get("message")
        .and_then(|m| m.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| serde_json::to_string(&f.evidence).unwrap_or_default())
}
