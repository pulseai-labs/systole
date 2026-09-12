//! The `Module` trait and the validator framework (ADR-0002): modules
//! register at startup and carry their manifest.

use crate::finding::Finding;
use crate::ir::project::Project;
use crate::registry::Registry;

#[derive(Clone, PartialEq, Debug, schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
pub struct ModuleManifest {
    pub module_id: String,
    pub version: String,
    pub schema: u32,
    pub depends_on: Vec<(String, String)>,
}

pub trait Module {
    fn manifest(&self) -> ModuleManifest;
    fn register(&self, registry: &mut Registry);
    fn validators(&self) -> Vec<Box<dyn Validator>>;
}

pub trait Validator: Send + Sync {
    fn id(&self) -> &'static str;
    fn run(&self, project: &Project) -> Vec<Finding>;
}

/// The engine's own module shell, `systole.core`. It registers no operations
/// in Release 0's first item; the composition root pairs it with the genre
/// module so the seam is real from day one (ADR-0011).
pub struct CoreModule;

impl Module for CoreModule {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest {
            module_id: "systole.core".into(),
            version: crate::ir::manifest::engine_version(),
            schema: crate::ir::manifest::PROJECT_SCHEMA,
            depends_on: vec![],
        }
    }

    fn register(&self, _registry: &mut Registry) {}

    fn validators(&self) -> Vec<Box<dyn Validator>> {
        Vec::new()
    }
}
