//! AC-5: a registry built from `CoreModule` + `RpgModule` lists exactly the
//! seven `rpg.*` operations — six writes and one read (ADR-0012's final set).

use systole_core::module::{CoreModule, Module};
use systole_core::registry::Registry;
use systole_rpg::RpgModule;

#[test]
fn catalog() {
    let mut registry = Registry::new();
    CoreModule.register(&mut registry);
    RpgModule.register(&mut registry);

    let mut ids: Vec<String> = registry.list().into_iter().map(|d| d.id).collect();
    ids.sort();
    for id in &ids {
        println!("{id}");
    }
    assert_eq!(
        ids,
        vec![
            "rpg.create_region",
            "rpg.mark_warp",
            "rpg.paint_area",
            "rpg.paint_path",
            "rpg.place_npc",
            "rpg.query_region",
            "rpg.set_collision",
        ]
    );
}
