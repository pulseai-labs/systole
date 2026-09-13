//! `systole project format [--check]`.

use std::path::Path;

use super::{is_read_only, report_project_error, structured_refusal};
use systole_core::ir::project::Project;
use systole_core::lock::{LockError, WriteLock};

pub fn run(root: &Path, check: bool, json: bool) -> i32 {
    if !check && is_read_only() {
        eprintln!("refused: SYSTOLE_READ_ONLY=1 is set; refusing to write");
        return 2;
    }
    // The write path rewrites the manifest, lock and IR files: it takes the
    // same write lock as a commit and refuses while a pending crash marker
    // exists — `doctor` must resolve it first.
    let _lock = if check {
        None
    } else {
        match WriteLock::acquire(root) {
            Ok(lock) => Some(lock),
            Err(LockError::Held { pid }) => {
                return structured_refusal(
                    root,
                    "project.locked",
                    &format!("project is locked by pid {pid}"),
                    2,
                    json,
                )
            }
            Err(LockError::Io(e)) => {
                return structured_refusal(root, "engine.io", &e.to_string(), 2, json)
            }
        }
    };
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
