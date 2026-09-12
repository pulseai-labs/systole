//! `systole-rpg` — the genre module for top-down 2.5D RPG authoring. Module
//! id `systole.rpg`. This item ships only the crate shell and an empty
//! `Module` impl; region and entity operations are `r0.s1.w3`.

use systole_core::module::{Module, ModuleManifest, Validator};
use systole_core::registry::Registry;

pub struct RpgModule;

impl Module for RpgModule {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest {
            module_id: "systole.rpg".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            schema: 1,
            depends_on: vec![("systole.core".into(), "*".into())],
        }
    }

    fn register(&self, _registry: &mut Registry) {}

    fn validators(&self) -> Vec<Box<dyn Validator>> {
        Vec::new()
    }
}
