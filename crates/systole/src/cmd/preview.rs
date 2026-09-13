//! `systole preview (<plan-file> | <op_id> --input <json | @file | ->)`.
//! Never writes, never audits (risk gate `ir-write-path`).

use std::path::Path;

use super::{
    absolutize, open_engine, print_diff, print_findings, read_input, read_plan_file,
    report_engine_error, CLI_ACTOR,
};
use systole_core::engine::Engine;
use systole_core::op::{OperationPlan, PlanRequest};

/// Resolve `(request, plan)` for `preview`/`apply`: a plan file when no
/// `--input` was given, else materialize fresh from the op id.
pub fn resolve(
    engine: &Engine,
    target: &str,
    input: Option<&str>,
) -> Result<(PlanRequest, OperationPlan), EngineErr> {
    match input {
        Some(raw) => {
            let input = read_input(raw).map_err(|m| EngineErr::msg(m, 2))?;
            let version = engine
                .registry()
                .latest_version(target)
                .ok_or_else(|| EngineErr::msg(format!("unknown operation: {target}"), 2))?;
            let req = PlanRequest {
                op_id: target.to_string(),
                op_version: version,
                input,
                actor: CLI_ACTOR.to_string(),
            };
            let plan = engine
                .materialize(&req)
                .map_err(EngineErr::Engine)?;
            Ok((req, plan))
        }
        None => {
            let file = read_plan_file(&absolutize(Path::new(target)))
                .map_err(|m| EngineErr::msg(m, 2))?;
            Ok((file.request, file.plan))
        }
    }
}

/// Either an engine error (rendered by `report_engine_error`) or a plain
/// refusal message with its exit code.
pub enum EngineErr {
    Engine(systole_core::engine::EngineError),
    Raw(String, i32),
}

impl EngineErr {
    pub fn msg(message: String, exit: i32) -> Self {
        EngineErr::Raw(message, exit)
    }
}

pub fn report(root: &Path, err: EngineErr, json: bool) -> i32 {
    match err {
        EngineErr::Engine(e) => report_engine_error(root, &e, json),
        EngineErr::Raw(m, exit) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": { "code": "op.invalid_request", "message": m },
                        "project_root": root.display().to_string(),
                    })
                );
            } else {
                eprintln!("{m}");
            }
            exit
        }
    }
}

pub fn run(root: &Path, target: &str, input: Option<&str>, verbose: bool, json: bool) -> i32 {
    let engine = match open_engine(root) {
        Ok(e) => e,
        Err(e) => return report_engine_error(root, &e, json),
    };
    let (_req, plan) = match resolve(&engine, target, input) {
        Ok(rp) => rp,
        Err(e) => return report(root, e, json),
    };
    match engine.preview(&plan) {
        Ok(preview) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": !preview.blocking,
                        "project_root": root.display().to_string(),
                        "plan_id": plan.plan_id,
                        "diff": preview.diff,
                        "findings": preview.findings,
                        "blocking": preview.blocking,
                    })
                );
            } else {
                print_diff(&preview.diff, verbose);
                print_findings(&preview.findings);
            }
            if preview.blocking {
                1
            } else {
                0
            }
        }
        Err(e) => report_engine_error(root, &e, json),
    }
}
