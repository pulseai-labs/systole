//! `systole rollback <audit_id>` — compensating rollback of the head entry.

use std::path::Path;

use super::{open_engine, report_engine_error};

pub fn run(root: &Path, audit_id: &str, json: bool) -> i32 {
    let mut engine = match open_engine(root) {
        Ok(e) => e,
        Err(e) => return report_engine_error(root, &e, json),
    };
    match engine.rollback(audit_id) {
        Ok(entry) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "project_root": root.display().to_string(),
                        "rolled_back": audit_id,
                        "audit_id": entry.audit_id,
                        "project_revision": entry.project_revision,
                    })
                );
            } else {
                println!(
                    "rolled back {} as {} at {}",
                    audit_id, entry.audit_id, entry.project_revision
                );
            }
            0
        }
        Err(e) => report_engine_error(root, &e, json),
    }
}
