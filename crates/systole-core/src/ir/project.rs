//! The project in memory: manifest, lock, and every IR file under
//! `regions/**` and `entities/**`, plus init/load/write.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::module::ModuleManifest;
use crate::revision::{self, blanked_manifest_value, digest_of, project_hash};

use super::format::format_value;
use super::lock::Lock;
use super::manifest::{
    Engine, Manifest, ModuleEntry, FIRST_REVISION, PROJECT_SCHEMA,
};
use super::writer::{sync_dir, write_atomic};
use super::{RelPath, LOCK_FILE, MANIFEST_FILE};

const AUDIT_LOG: &str = "audit/audit.jsonl";
const IR_DIRS: [&str; 2] = ["regions", "entities"];
/// Directories that would otherwise be empty and invisible to git; markers are
/// never IR files (the loader and hash only see `*.json`).
const MARKER_DIRS: [&str; 4] = ["audit/pending", "plans", "regions", "entities"];
const MARKER_FILE: &str = ".gitkeep";

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON in {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("missing project file: {0}")]
    Missing(String),
    #[error("refused: {dir} is not empty; pass --force {dir} to initialize anyway")]
    NonEmpty { dir: String },
    #[error("not a directory: {path}")]
    NotADirectory { path: String },
    #[error(transparent)]
    Integrity(#[from] revision::IntegrityError),
}

fn io(path: &str, source: std::io::Error) -> ProjectError {
    ProjectError::Io {
        path: path.to_string(),
        source,
    }
}

/// A loaded project. `files` holds every `*.json` IR file under `regions/**`
/// and `entities/**`; the manifest and lock are typed fields.
#[derive(Clone, Debug)]
pub struct Project {
    pub root: PathBuf,
    pub manifest: Manifest,
    pub lock: Lock,
    pub files: BTreeMap<RelPath, serde_json::Value>,
}

impl Project {
    /// Create a new project at `root` (refusing a non-empty directory unless
    /// `force`), writing the full Release-0 layout at `rev_00000`.
    pub fn init(root: &Path, force: bool, modules: &[ModuleManifest]) -> Result<Project, ProjectError> {
        let dir = root.display().to_string();
        let mut replace = false;
        match fs::symlink_metadata(root) {
            Ok(meta) if meta.is_file() => {
                return Err(ProjectError::NotADirectory { path: dir });
            }
            Ok(_) => {
                let mut entries = match fs::read_dir(root) {
                    Ok(entries) => entries,
                    Err(source) => return Err(io(&dir, source)),
                };
                if entries.next().is_some() {
                    if !force {
                        return Err(ProjectError::NonEmpty { dir });
                    }
                    replace = true;
                }
            }
            Err(_) => { /* does not exist yet; create it below */ }
        }

        if replace {
            return Self::init_replacing(root, modules);
        }

        fs::create_dir_all(root).map_err(|e| io(&dir, e))?;
        fs::create_dir_all(root.join("audit/pending")).map_err(|e| io(&dir, e))?;
        for dir_rel in MARKER_DIRS {
            fs::create_dir_all(root.join(dir_rel))
                .map_err(|e| io(dir_rel, e))?;
        }
        for dir_rel in MARKER_DIRS {
            let marker = root.join(dir_rel).join(MARKER_FILE);
            if !marker.exists() {
                write_atomic(&marker, b"").map_err(|e| io(dir_rel, e))?;
            }
        }
        write_atomic(&root.join(AUDIT_LOG), b"").map_err(|e| io(AUDIT_LOG, e))?;

        let engine = Engine {
            name: super::manifest::ENGINE_NAME.to_string(),
            version: super::manifest::engine_version(),
        };
        let manifest = Manifest {
            engine: engine.clone(),
            project_schema: PROJECT_SCHEMA,
            modules: modules
                .iter()
                .map(|m| {
                    (
                        m.module_id.clone(),
                        ModuleEntry {
                            version: m.version.clone(),
                            schema: m.schema,
                        },
                    )
                })
                .collect(),
            stable_id_counter: 0,
            project_revision: FIRST_REVISION.to_string(),
            project_hash: String::new(), // set by refresh_integrity
            audit_head: None,
            files: BTreeMap::new(),
        };
        let lock = Lock {
            engine,
            modules: modules
                .iter()
                .map(|m| (m.module_id.clone(), m.version.clone()))
                .collect(),
        };
        let mut project = Project {
            root: root.to_path_buf(),
            manifest,
            lock,
            files: BTreeMap::new(),
        };
        project.refresh_integrity();
        project.write_all()?;
        // Load back through the same path every command uses.
        Project::load(root)
    }

    /// `init --force` on a non-empty directory: the fresh layout is built in
    /// a sibling staging directory first, then every managed path is swapped
    /// in by rename — never written over the old tree in place. The previous
    /// tree moves aside wholesale and is deleted only after the replacement
    /// completes, so an existing audit log is never truncated mid-init and
    /// stale IR files cannot survive into the fresh project.
    fn init_replacing(root: &Path, modules: &[ModuleManifest]) -> Result<Project, ProjectError> {
        let dir = root.display().to_string();
        let parent = root.parent().unwrap_or_else(|| Path::new("."));
        let pid = std::process::id();
        let staging = parent.join(format!(".systole-init-staging-{pid}"));
        let trash = parent.join(format!(".systole-init-trash-{pid}"));
        // Leftovers from a crashed earlier run.
        for scratch in [&staging, &trash] {
            if scratch.exists() {
                fs::remove_dir_all(scratch).map_err(|e| io(&dir, e))?;
            }
        }
        // A complete, verified fresh project beside the target — same
        // filesystem, so every rename below is atomic.
        Self::init(&staging, false, modules)?;
        fs::create_dir_all(&trash).map_err(|e| io(&dir, e))?;

        // Every path init manages, at the project root's top level.
        const MANAGED: [&str; 6] = [
            "audit",
            "plans",
            "regions",
            "entities",
            MANIFEST_FILE,
            LOCK_FILE,
        ];
        let mut moved: Vec<&str> = Vec::new();
        for rel in MANAGED {
            let current = root.join(rel);
            let incoming = staging.join(rel);
            let step = (|| -> std::io::Result<()> {
                if fs::symlink_metadata(&current).is_ok() {
                    fs::rename(&current, trash.join(rel))?;
                }
                fs::rename(&incoming, &current)
            })();
            match step {
                Ok(()) => {
                    if trash.join(rel).exists() {
                        moved.push(rel);
                    }
                }
                Err(source) => {
                    // Best effort: put back whatever was moved aside.
                    for prev in &moved {
                        let _ = fs::rename(trash.join(prev), root.join(prev));
                    }
                    return Err(io(rel, source));
                }
            }
        }
        let _ = fs::remove_dir_all(&trash);
        let _ = fs::remove_dir_all(&staging);
        let _ = sync_dir(root);
        Project::load(root)
    }

    /// Read and verify a project from disk. Fails with
    /// [`ProjectError::Integrity`] when the on-disk bytes no longer match the
    /// recorded hash.
    pub fn load(root: &Path) -> Result<Project, ProjectError> {
        let project = Self::load_unverified(root)?;
        revision::verify(&project).map_err(ProjectError::Integrity)?;
        Ok(project)
    }

    /// Read a project from disk WITHOUT the integrity check — for `doctor`,
    /// which must see the on-disk state exactly as it is when the recorded
    /// hash no longer matches. Nothing but doctor's recovery/absorb path
    /// should use this; every command path goes through `load`.
    pub fn load_unverified(root: &Path) -> Result<Project, ProjectError> {
        let manifest: Manifest = read_json(root, MANIFEST_FILE)?;
        let lock: Lock = read_json(root, LOCK_FILE)?;
        let mut files = BTreeMap::new();
        for base in IR_DIRS {
            walk_json(&root.join(base), base, &mut files)?;
        }
        Ok(Project {
            root: root.to_path_buf(),
            manifest,
            lock,
            files,
        })
    }

    /// The canonical bytes of the manifest as written to disk (unblanked).
    pub fn manifest_bytes(&self) -> Vec<u8> {
        format_value(
            &serde_json::to_value(&self.manifest).expect("manifest serializes"),
        )
    }

    /// The canonical bytes of the lock as written to disk.
    pub fn lock_bytes(&self) -> Vec<u8> {
        format_value(&serde_json::to_value(&self.lock).expect("lock serializes"))
    }

    /// Recompute the per-file digest table and the project hash from the
    /// in-memory state and record both on the manifest.
    pub fn refresh_integrity(&mut self) {
        let mut table = BTreeMap::new();
        let mut domain: BTreeMap<RelPath, Vec<u8>> = BTreeMap::new();

        let lock_bytes = self.lock_bytes();
        table.insert(RelPath::new(LOCK_FILE), digest_of(&lock_bytes));
        domain.insert(RelPath::new(LOCK_FILE), lock_bytes);

        for (path, value) in &self.files {
            let bytes = format_value(value);
            table.insert(path.clone(), digest_of(&bytes));
            domain.insert(path.clone(), bytes);
        }

        // The manifest is hashed (blanked) but not in its own digest table;
        // the table must be set before its bytes are taken.
        self.manifest.files = table;
        domain.insert(
            RelPath::new(MANIFEST_FILE),
            format_value(&blanked_manifest_value(&self.manifest)),
        );
        self.manifest.project_hash = project_hash(&domain);
    }

    /// Persist every IR file (manifest, lock, `regions/**`, `entities/**`) in
    /// canonical form via temp file + atomic rename.
    pub fn write_all(&self) -> Result<(), ProjectError> {
        let manifest_path = self.root.join(MANIFEST_FILE);
        write_atomic(&manifest_path, &self.manifest_bytes())
            .map_err(|e| io(MANIFEST_FILE, e))?;
        let lock_path = self.root.join(LOCK_FILE);
        write_atomic(&lock_path, &self.lock_bytes()).map_err(|e| io(LOCK_FILE, e))?;
        for (path, value) in &self.files {
            let abs = self.root.join(path.as_str());
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| io(path.as_str(), e))?;
            }
            let bytes = format_value(value);
            write_atomic(&abs, &bytes).map_err(|e| io(path.as_str(), e))?;
        }
        Ok(())
    }

    /// Every IR file whose on-disk bytes are not canonical. Reads from disk;
    /// the returned paths are relative.
    pub fn noncanonical_files(&self) -> Result<Vec<RelPath>, ProjectError> {
        let mut out = Vec::new();
        for rel in [MANIFEST_FILE, LOCK_FILE] {
            let bytes = fs::read(self.root.join(rel)).map_err(|e| io(rel, e))?;
            if !super::format::is_canonical(&bytes) {
                out.push(RelPath::new(rel));
            }
        }
        for path in self.files.keys() {
            let bytes =
                fs::read(self.root.join(path.as_str())).map_err(|e| io(path.as_str(), e))?;
            if !super::format::is_canonical(&bytes) {
                out.push(path.clone());
            }
        }
        Ok(out)
    }
}

fn read_json<T: serde::de::DeserializeOwned>(root: &Path, rel: &str) -> Result<T, ProjectError> {
    let path = root.join(rel);
    let bytes = fs::read(&path).map_err(|_| ProjectError::Missing(rel.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|source| ProjectError::Parse {
        path: rel.to_string(),
        source,
    })
}

fn walk_json(
    dir: &Path,
    rel: &str,
    files: &mut BTreeMap<RelPath, serde_json::Value>,
) -> Result<(), ProjectError> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(()); // a missing base dir is an empty project
    };
    let mut names: Vec<(String, bool)> = entries
        .filter_map(|e| e.ok())
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            (name, is_dir)
        })
        .collect();
    names.sort();
    for (name, is_dir) in names {
        let child_rel = format!("{rel}/{name}");
        if is_dir {
            walk_json(&dir.join(&name), &child_rel, files)?;
        } else if name.ends_with(".json") {
            let bytes =
                fs::read(dir.join(&name)).map_err(|e| io(&child_rel, e))?;
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(
                |source| ProjectError::Parse {
                    path: child_rel.clone(),
                    source,
                },
            )?;
            files.insert(RelPath::new(child_rel), value);
        }
    }
    Ok(())
}
