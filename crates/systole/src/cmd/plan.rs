//! `systole plan <op_id> --input <json | @file | -> [--out <path>]`.

use std::path::Path;

use super::{
    absolutize, compose, is_read_only, read_input, report_engine_error, write_plan_file,
    PlanFile, CLI_ACTOR,
};
use systole_core::engine::Engine;
use systole_core::op::PlanRequest;

pub fn run(
    root: &Path,
    op_id: &str,
    input_raw: &str,
    out: Option<&Path>,
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
        println!("plan {} at {}", plan.plan_id, plan.base_project_revision);
    }
    0
}
