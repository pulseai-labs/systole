//! `systole apply (<plan-file> | <op_id> --input <json | @file | ->)` —
//! everything `preview` does, then commit (ADR-0007).

use std::path::Path;

use super::{open_engine, preview, print_diff, print_findings, report_engine_error};

pub fn run(root: &Path, target: &str, input: Option<&str>, verbose: bool, json: bool) -> i32 {
    let mut engine = match open_engine(root) {
        Ok(e) => e,
        Err(e) => return report_engine_error(root, &e, json),
    };
    let (req, plan) = match preview::resolve(&engine, target, input) {
        Ok(rp) => rp,
        Err(e) => return preview::report(root, e, json),
    };

    // The preview half: print the diff and findings exactly as `preview` does.
    let preview = match engine.preview(&plan) {
        Ok(p) => p,
        Err(e) => return report_engine_error(root, &e, json),
    };
    if !json {
        print_diff(&preview.diff, verbose);
        print_findings(&preview.findings);
    }
    if preview.blocking {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "error": { "code": "plan.blocked", "message": "plan blocked by findings" },
                    "project_root": root.display().to_string(),
                    "findings": preview.findings,
                })
            );
        }
        return 1;
    }

    match engine.commit(&req, plan) {
        Ok(entry) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "project_root": root.display().to_string(),
                        "audit_id": entry.audit_id,
                        "project_revision": entry.project_revision,
                        "changes": entry.changes,
                        "output": entry.output,
                    })
                );
            } else {
                println!("committed {} at {}", entry.audit_id, entry.project_revision);
            }
            0
        }
        Err(e) => report_engine_error(root, &e, json),
    }
}
