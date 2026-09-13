//! `systole project check`.

use std::path::Path;

use super::report_engine_error;
use systole_core::audit;
use systole_core::engine::EngineError;
use systole_core::ir::project::Project;

pub fn run(root: &Path, json: bool) -> i32 {
    match Project::load(root) {
        Ok(project) => {
            // The audit log sits outside the project hash: verify the chain
            // against the manifest's audit_head before reporting ok.
            if let Err(break_at) =
                audit::verify_chain(root, project.manifest.audit_head.as_ref())
            {
                return report_engine_error(root, &EngineError::Chain(break_at), json);
            }
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
        // Route through the engine-error reporter so `--json` failures are
        // structured — missing, malformed, and integrity-failing projects
        // all emit a parseable error object, never human-only text.
        Err(err) => report_engine_error(root, &EngineError::Project(err), json),
    }
}
