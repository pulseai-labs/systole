//! `systole project format [--check]`.

use std::path::Path;

use super::{is_read_only, report_project_error};
use systole_core::ir::project::Project;

pub fn run(root: &Path, check: bool, json: bool) -> i32 {
    if !check && is_read_only() {
        eprintln!("refused: SYSTOLE_READ_ONLY=1 is set; refusing to write");
        return 2;
    }
    let mut project = match Project::load(root) {
        Ok(project) => project,
        Err(err) => return report_project_error(root, &err),
    };

    let noncanonical = match project.noncanonical_files() {
        Ok(files) => files,
        Err(err) => return report_project_error(root, &err),
    };

    if check {
        if noncanonical.is_empty() {
            if json {
                println!("{}", serde_json::json!({ "ok": true, "changed": [] }));
            } else {
                println!("format ok: all files canonical");
            }
            return 0;
        }
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "changed": noncanonical.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                })
            );
        } else {
            for path in &noncanonical {
                eprintln!("not canonical: {path}");
            }
        }
        return 1;
    }

    // Rewrite every IR file to canonical bytes and update the file table and
    // hash together.
    project.refresh_integrity();
    if let Err(err) = project.write_all() {
        return report_project_error(root, &err);
    }
    let count = noncanonical.len();
    if json {
        println!(
            "{}",
            serde_json::json!({ "ok": true, "rewritten": count })
        );
    } else {
        println!("formatted: {count} file(s) rewritten");
    }
    0
}
