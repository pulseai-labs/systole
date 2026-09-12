//! `systole project init <dir> [--force]`.

use std::path::Path;

use super::{compose, is_read_only, report_project_error};
use systole_core::ir::project::Project;

pub fn run(dir: &Path, force: bool, json: bool) -> i32 {
    if is_read_only() {
        eprintln!("refused: SYSTOLE_READ_ONLY=1 is set; refusing to write");
        return 2;
    }
    let (_, modules) = compose();
    match Project::init(dir, force, &modules) {
        Ok(project) => {
            let root = project.root.display();
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "ok": true, "project_root": root.to_string() })
                );
            } else {
                println!("initialized project at {root}");
            }
            0
        }
        Err(err) => report_project_error(&super::absolutize(dir), &err),
    }
}
