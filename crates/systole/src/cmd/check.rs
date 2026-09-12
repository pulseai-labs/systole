//! `systole project check`.

use std::path::Path;

use super::report_project_error;
use systole_core::ir::project::Project;

pub fn run(root: &Path, json: bool) -> i32 {
    match Project::load(root) {
        Ok(project) => {
            let manifest = &project.manifest;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "project_schema": manifest.project_schema,
                        "project_revision": manifest.project_revision,
                        "project_hash": manifest.project_hash,
                        "project_root": root.display().to_string(),
                    })
                );
            } else {
                println!(
                    "project ok: schema {}, revision {}",
                    manifest.project_schema, manifest.project_revision
                );
            }
            0
        }
        Err(err) => report_project_error(root, &err),
    }
}
