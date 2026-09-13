//! Module validators: engine-side project checks that emit `Finding`s
//! (ADR-0004). `core.reference_integrity` is the engine's own; genre modules
//! carry theirs (e.g. `systole.rpg`'s reachability).

pub mod reference_integrity;

use crate::ir::project::Project;
use crate::op::{OpError, PlanRequest};
use crate::registry::Registry;
use crate::tx::Transaction;

/// The fix contract's machinery (ADR-0004): materialize a suggested fix and
/// apply it into a `Transaction`, then merge the staged after-images into a
/// cloned `Project`. Nothing is written, locked, or audited — the result is a
/// hypothetical project state a validator re-runs itself against to prove the
/// fix makes its finding disappear before the fix is emitted.
pub fn staged_apply(
    project: &Project,
    registry: &Registry,
    req: &PlanRequest,
) -> Result<Project, OpError> {
    let plan = registry.materialize(project, req)?;
    let mut tx = Transaction::new(project);
    registry.apply(&mut tx, plan)?;
    let mut staged = project.clone();
    for change in tx.staged() {
        match &change.after {
            Some(value) => {
                staged.files.insert(change.path.clone(), value.clone());
            }
            None => {
                staged.files.remove(&change.path);
            }
        }
    }
    staged.manifest.stable_id_counter = tx.stable_id_counter();
    staged.refresh_integrity();
    Ok(staged)
}
