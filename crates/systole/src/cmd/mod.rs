//! CLI command implementations and the composition root (ADR-0002): the
//! binary links core and rpg, and modules register at startup.

pub mod check;
pub mod format;
pub mod init;

use std::path::Path;

use systole_core::ir::project::ProjectError;
use systole_core::module::{CoreModule, Module, ModuleManifest};
use systole_core::registry::Registry;

/// Build the registry from `systole.core` and `systole.rpg`, and collect the
/// module manifests a new project records. The engine itself is not a project
/// module; only genre modules go into `project.systole.json`.
pub fn compose() -> (Registry, Vec<ModuleManifest>) {
    let mut registry = Registry::new();
    let core = CoreModule;
    let rpg = systole_rpg::RpgModule;
    core.register(&mut registry);
    rpg.register(&mut registry);
    (registry, vec![rpg.manifest()])
}

/// The kill switch (risk gate `ir-integrity`): `SYSTOLE_READ_ONLY=1` refuses
/// every write path without a rebuild.
pub fn is_read_only() -> bool {
    std::env::var("SYSTOLE_READ_ONLY").as_deref() == Ok("1")
}

/// Resolve a project root in ADR-0001 order: `--project`, `$SYSTOLE_PROJECT`,
/// the current directory.
pub fn project_root(explicit: Option<&Path>) -> std::path::PathBuf {
    if let Some(p) = explicit {
        return absolutize(p);
    }
    if let Some(env) = std::env::var_os("SYSTOLE_PROJECT") {
        return absolutize(Path::new(&env));
    }
    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

pub fn absolutize(path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(path)
    }
}

/// Print a project error to stderr and return its exit code. Integrity
/// refusals render the fixed multi-line refusal text (ADR-0006): the reason,
/// one line per changed file, the recorded revision, and the repair hint
/// (`doctor` itself is w2; the hint text is fixed now).
pub fn report_project_error(root: &Path, err: &ProjectError) -> i32 {
    match err {
        ProjectError::Integrity(integrity) => {
            eprintln!("refused: project files changed outside a transaction");
            for path in &integrity.changed {
                eprintln!("  changed: {path}");
            }
            let revision = recorded_revision(root);
            eprintln!("recorded revision {revision}");
            eprintln!("systole project doctor --absorb");
        }
        other => eprintln!("{other}"),
    }
    2
}

/// Best-effort read of the manifest's recorded revision for refusal text.
fn recorded_revision(root: &Path) -> String {
    std::fs::read(root.join(systole_core::ir::MANIFEST_FILE))
        .ok()
        .and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| {
                    v.get("project_revision")
                        .and_then(|r| r.as_str())
                        .map(str::to_string)
                })
        })
        .unwrap_or_else(|| "unknown".to_string())
}
