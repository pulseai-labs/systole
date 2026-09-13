//! `systole plan <op_id> --input <json | @file | -> [--out <path>]` and
//! `systole plan --from-finding <finding_id | code> [--fix <n>] [--out
//! <path>]` — the latter re-runs the validators, takes the finding's
//! `suggested_fixes[n]`, rewrites its actor to the invoking actor, and
//! materializes it through the ordinary lifecycle (ADR-0004).

use std::path::Path;

use super::{
    absolutize, compose, is_read_only, module_validators, read_input, report_engine_error,
    structured_refusal, write_plan_file, PlanFile, CLI_ACTOR,
};
use systole_core::engine::Engine;
use systole_core::finding::Finding;
use systole_core::op::PlanRequest;

#[allow(clippy::too_many_arguments)]
pub fn run(
    root: &Path,
    op_id: Option<&str>,
    input_raw: Option<&str>,
    out: Option<&Path>,
    from_finding: Option<&str>,
    fix: Option<usize>,
    json: bool,
) -> i32 {
    // `plan` writes a plan file — the kill switch refuses it (spec §32).
    if is_read_only() {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "error": { "code": "project.read_only", "message": "refused: SYSTOLE_READ_ONLY=1" },
                    "project_root": root.display().to_string(),
                })
            );
        } else {
            eprintln!("refused: SYSTOLE_READ_ONLY=1");
        }
        return 2;
    }
    match (from_finding, op_id, input_raw, fix) {
        (Some(key), None, None, fix) => {
            plan_from_finding(root, key, fix.unwrap_or(0), out, json)
        }
        (None, Some(op_id), Some(input_raw), None) => {
            plan_for_op(root, op_id, input_raw, out, json)
        }
        _ => structured_refusal(
            root,
            "cli.usage",
            "usage: plan <op_id> --input <json> or plan --from-finding \
             <finding_id|code> [--fix <n>]",
            2,
            json,
        ),
    }
}

fn plan_for_op(
    root: &Path,
    op_id: &str,
    input_raw: &str,
    out: Option<&Path>,
    json: bool,
) -> i32 {
    let (registry, _) = compose();
    let engine = match Engine::open(root, registry) {
        Ok(e) => e,
        Err(e) => return report_engine_error(root, &e, json),
    };
    let input = match read_input(input_raw) {
        Ok(i) => i,
        Err(m) => {
            return report_engine_error(
                root,
                &systole_core::op::OpError::InvalidRequest(m).into(),
                json,
            )
        }
    };
    let version = match engine.registry().latest_version(op_id) {
        Some(v) => v,
        None => {
            return report_engine_error(
                root,
                &systole_core::op::OpError::UnknownOp(op_id.to_string()).into(),
                json,
            )
        }
    };
    let req = PlanRequest {
        op_id: op_id.to_string(),
        op_version: version,
        input,
        actor: CLI_ACTOR.to_string(),
    };
    let plan = match engine.materialize(&req) {
        Ok(p) => p,
        Err(e) => return report_engine_error(root, &e, json),
    };
    write_and_report(root, req, plan, out, json, None)
}

/// Findings are a pure function of the project and their ids are
/// deterministic, so `plan --from-finding` re-runs the validators exactly as
/// `validate` does — nothing is persisted between the two commands.
fn plan_from_finding(
    root: &Path,
    key: &str,
    fix_index: usize,
    out: Option<&Path>,
    json: bool,
) -> i32 {
    let (registry, _) = compose();
    let engine = match Engine::open(root, registry) {
        Ok(e) => e,
        Err(e) => return report_engine_error(root, &e, json),
    };
    let mut findings = Vec::new();
    for v in module_validators() {
        findings.extend(v.run(engine.project()));
    }
    findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));

    let finding = match findings.iter().find(|f| f.finding_id == key) {
        Some(f) => f,
        None => {
            let matches: Vec<&Finding> =
                findings.iter().filter(|f| f.code == key).collect();
            match matches.len() {
                1 => matches[0],
                0 => {
                    return structured_refusal(
                        root,
                        "finding.unknown",
                        &format!("no finding with id or code {key:?}"),
                        2,
                        json,
                    )
                }
                _ => {
                    return structured_refusal(
                        root,
                        "finding.ambiguous",
                        &format!(
                            "{key:?} matches {} findings: {}",
                            matches.len(),
                            matches
                                .iter()
                                .map(|f| f.finding_id.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        2,
                        json,
                    )
                }
            }
        }
    };

    let mut req = match finding.suggested_fixes.get(fix_index) {
        Some(req) => req.clone(),
        None => {
            return structured_refusal(
                root,
                "finding.no_fix",
                &format!(
                    "finding {} has {} suggested fix(es); no fix at index {fix_index}",
                    finding.finding_id,
                    finding.suggested_fixes.len()
                ),
                2,
                json,
            )
        }
    };
    // The finding's fix was authored under the module's marker actor; the
    // plan is materialized under the invoking actor (ADR-0005).
    req.actor = CLI_ACTOR.to_string();
    let plan = match engine.materialize(&req) {
        Ok(p) => p,
        Err(e) => return report_engine_error(root, &e, json),
    };
    write_and_report(root, req, plan, out, json, Some((&finding.finding_id, fix_index)))
}

fn write_and_report(
    root: &Path,
    req: PlanRequest,
    plan: systole_core::op::OperationPlan,
    out: Option<&Path>,
    json: bool,
    origin: Option<(&str, usize)>,
) -> i32 {
    let path = out
        .map(|p| absolutize(p))
        .unwrap_or_else(|| root.join("plans").join(format!("{}.json", plan.plan_id)));
    if let Err(m) = write_plan_file(&path, &PlanFile { request: req, plan: plan.clone() }) {
        eprintln!("{m}");
        return 2;
    }
    if json {
        println!("{}", serde_json::to_string(&plan).expect("a plan serializes"));
    } else {
        match origin {
            Some((finding_id, fix_index)) => println!(
                "plan {} at {} from {} fix {}",
                plan.plan_id, plan.base_project_revision, finding_id, fix_index
            ),
            None => println!("plan {} at {}", plan.plan_id, plan.base_project_revision),
        }
    }
    0
}
