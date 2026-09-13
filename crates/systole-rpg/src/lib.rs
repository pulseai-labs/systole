//! `systole-rpg` — the genre module for top-down 2.5D RPG authoring. Module
//! id `systole.rpg`. Registers the seven Release-0 region operations
//! (ADR-0012): six writes and one read.
//!
//! ```
//! use systole_core::module::Module;
//! use systole_core::registry::Registry;
//! use systole_rpg::RpgModule;
//!
//! let mut registry = Registry::new();
//! RpgModule.register(&mut registry);
//! assert_eq!(registry.list().len(), 7);
//! ```

pub mod ops;
pub mod schema;

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

    fn register(&self, registry: &mut Registry) {
        registry.register::<ops::create_region::CreateRegion>();
        registry.register::<ops::paint_area::PaintArea>();
        registry.register::<ops::paint_path::PaintPath>();
        registry.register::<ops::set_collision::SetCollision>();
        registry.register::<ops::place_npc::PlaceNpc>();
        registry.register::<ops::mark_warp::MarkWarp>();
        registry.register_read::<ops::query_region::QueryRegion>();
    }

    fn validators(&self) -> Vec<Box<dyn Validator>> {
        Vec::new()
    }
}
