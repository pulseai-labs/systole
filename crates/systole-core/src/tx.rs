//! The transaction: staged writes, inverse data, id allocations. Nothing
//! touches disk until commit — which is `r0.s1.w2`.

use std::collections::BTreeMap;

use crate::ids::{IdAllocator, IdKind, StableId};
use crate::ir::project::Project;
use crate::ir::RelPath;
use crate::op::FileChange;

/// An in-memory transaction over a project. Writes stage against a snapshot of
/// the loaded project; every first write to a path records that path's
/// before-image as inverse data (null for a creation), which rollback will
/// restore.
pub struct Transaction {
    files: BTreeMap<RelPath, serde_json::Value>,
    staged: Vec<FileChange>,
    inverse: serde_json::Value,
    allocator: IdAllocator,
}

impl Transaction {
    pub fn new(project: &Project) -> Self {
        Transaction {
            files: project.files.clone(),
            staged: Vec::new(),
            inverse: serde_json::Value::Object(Default::default()),
            allocator: IdAllocator::new(project.manifest.stable_id_counter),
        }
    }

    /// The staged-over-project view: the staged after-image if this
    /// transaction touched the path, else the loaded value.
    pub fn read(&self, path: &RelPath) -> Option<&serde_json::Value> {
        for change in &self.staged {
            if &change.path == path {
                return change.after.as_ref();
            }
        }
        self.files.get(path)
    }

    /// Stage a write, recording the path's before-image as inverse data on
    /// first touch.
    pub fn write(&mut self, path: RelPath, value: serde_json::Value) {
        let before = self.before_image(&path);
        match self.staged.iter_mut().find(|c| c.path == path) {
            Some(change) => change.after = Some(value),
            None => self.staged.push(FileChange {
                path: path.clone(),
                before: before.clone(),
                after: Some(value),
            }),
        }
        self.record_inverse(&path, before);
    }

    /// Stage a deletion (`after = None`).
    pub fn delete(&mut self, path: RelPath) {
        let before = self.before_image(&path);
        match self.staged.iter_mut().find(|c| c.path == path) {
            Some(change) => change.after = None,
            None => self.staged.push(FileChange {
                path: path.clone(),
                before: before.clone(),
                after: None,
            }),
        }
        self.record_inverse(&path, before);
    }

    /// Allocate a stable id from the shared counter. The counter is persisted
    /// only by a commit (w2); never reused within a transaction.
    pub fn alloc_id(&mut self, kind: IdKind) -> StableId {
        self.allocator.next(kind)
    }

    pub fn staged(&self) -> &[FileChange] {
        &self.staged
    }

    /// The accumulated inverse data: an object mapping each touched path to
    /// its before-image (null for creations).
    pub fn inverse(&self) -> &serde_json::Value {
        &self.inverse
    }

    fn before_image(&self, path: &RelPath) -> Option<serde_json::Value> {
        if let Some(change) = self.staged.iter().find(|c| &c.path == path) {
            return change.before.clone();
        }
        self.files.get(path).cloned()
    }

    fn record_inverse(&mut self, path: &RelPath, before: Option<serde_json::Value>) {
        if let serde_json::Value::Object(table) = &mut self.inverse {
            table.insert(
                path.as_str().to_string(),
                before.unwrap_or(serde_json::Value::Null),
            );
        }
    }
}
