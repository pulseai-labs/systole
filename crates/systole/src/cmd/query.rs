//! `systole query <read_op_id> --input <json | @file | ->` — read-side
//! dispatch; never writes, never audits (ADR-0003 D44).

use std::path::Path;

use super::{open_engine, read_input, report_engine_error, CLI_ACTOR};
use systole_core::op::{OpError, PlanRequest};

pub fn run(root: &Path, op_id: &str, input_raw: &str, json: bool) -> i32 {
    let engine = match open_engine(root) {
        Ok(e) => e,
        Err(e) => return report_engine_error(root, &e, json),
    };
    let input = match read_input(input_raw) {
        Ok(i) => i,
        Err(m) => {
            return report_engine_error(root, &OpError::InvalidRequest(m).into(), json)
        }
    };
    let version = match engine.registry().latest_version(op_id) {
        Some(v) => v,
        None => {
            return report_engine_error(
                root,
                &OpError::UnknownOp(op_id.to_string()).into(),
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
    match engine.query(&req) {
        Ok(output) => {
            // Canonical JSON — the same bytes format_value writes to disk.
            print!(
                "{}",
                String::from_utf8_lossy(&systole_core::ir::format::format_value(&output))
            );
            0
        }
        Err(e) => report_engine_error(root, &e, json),
    }
}
