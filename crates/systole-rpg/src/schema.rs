//! The region and entity file bodies the rpg ops read and write (ADR-0003
//! layout, `systole.rpg` module schema 1). Coordinates are zero-based, `x` to
//! the right, `y` down; a tile is `[x, y]`.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use systole_core::ir::project::Project;
use systole_core::ir::RelPath;

pub const OWNER_MODULE: &str = "systole.rpg";
pub const MAX_REGION_DIMENSION: u32 = 256;
pub const MAX_HANDLE_LEN: usize = 64;

/// Cardinal facing for placements and entities.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Facing {
    #[default]
    Down,
    Up,
    Left,
    Right,
}

/// The five Release-0 terrain kinds. `wall` and `water` are solid by default;
/// the rest are walkable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Terrain {
    Grass,
    Floor,
    Path,
    Wall,
    Water,
}

impl Terrain {
    pub fn from_kind(kind: &str) -> Option<Terrain> {
        Some(match kind {
            "grass" => Terrain::Grass,
            "floor" => Terrain::Floor,
            "path" => Terrain::Path,
            "wall" => Terrain::Wall,
            "water" => Terrain::Water,
            _ => return None,
        })
    }

    pub fn kind(self) -> &'static str {
        match self {
            Terrain::Grass => "grass",
            Terrain::Floor => "floor",
            Terrain::Path => "path",
            Terrain::Wall => "wall",
            Terrain::Water => "water",
        }
    }

    pub fn glyph(self) -> char {
        match self {
            Terrain::Grass => '.',
            Terrain::Floor => ':',
            Terrain::Path => '-',
            Terrain::Wall => '#',
            Terrain::Water => '~',
        }
    }

    pub fn solid(self) -> bool {
        matches!(self, Terrain::Wall | Terrain::Water)
    }
}

/// The fixed terrain legend written into every `layers/terrain.json`.
pub fn legend() -> Value {
    json!({ ".": "grass", ":": "floor", "-": "path", "#": "wall", "~": "water" })
}

/// A terrain glyph is solid iff its kind is wall or water (the legend is
/// fixed, so glyph and kind are interchangeable here).
pub fn glyph_solid(glyph: char) -> bool {
    matches!(glyph, '#' | '~')
}

/// Handles match `^[a-z][a-z0-9_]{0,63}$` and are unique across their scope
/// (`regions/**` for regions, `entities/**` for entities).
pub fn valid_handle(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_HANDLE_LEN
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

pub fn region_path(stable_id: &str) -> RelPath {
    RelPath::new(format!("regions/{stable_id}/region.json"))
}

pub fn terrain_path(stable_id: &str) -> RelPath {
    RelPath::new(format!("regions/{stable_id}/layers/terrain.json"))
}

pub fn collision_path(stable_id: &str) -> RelPath {
    RelPath::new(format!("regions/{stable_id}/layers/collision.json"))
}

pub fn npc_path(stable_id: &str) -> RelPath {
    RelPath::new(format!("entities/npc/{stable_id}.json"))
}

/// The `(stable_id, region value)` whose `id` handle matches, if any.
pub fn find_region<'p>(project: &'p Project, handle: &str) -> Option<(String, &'p Value)> {
    project.files.iter().find_map(|(path, value)| {
        let p = path.as_str();
        if p.starts_with("regions/")
            && p.ends_with("/region.json")
            && value.get("kind").and_then(Value::as_str) == Some("region")
            && value.get("id").and_then(Value::as_str) == Some(handle)
        {
            Some((value.get("stable_id")?.as_str()?.to_string(), value))
        } else {
            None
        }
    })
}

/// The `(stable_id, entity value)` whose `id` handle matches, if any.
pub fn find_entity<'p>(project: &'p Project, handle: &str) -> Option<(String, &'p Value)> {
    project.files.iter().find_map(|(path, value)| {
        let p = path.as_str();
        if p.starts_with("entities/")
            && p.ends_with(".json")
            && value.get("id").and_then(Value::as_str) == Some(handle)
        {
            Some((value.get("stable_id")?.as_str()?.to_string(), value))
        } else {
            None
        }
    })
}

/// The entity value carrying `stable_id`, if any (placements reference
/// entities by stable id).
pub fn find_entity_by_stable_id<'p>(project: &'p Project, stable_id: &str) -> Option<&'p Value> {
    project.files.iter().find_map(|(path, value)| {
        let p = path.as_str();
        if p.starts_with("entities/")
            && p.ends_with(".json")
            && value.get("stable_id").and_then(Value::as_str) == Some(stable_id)
        {
            Some(value)
        } else {
            None
        }
    })
}

/// The region's `(width, height)` from its `region.json` value. Saturating:
/// a value beyond u32 must not wrap into a small, plausible dimension.
pub fn region_size(region: &Value) -> (u32, u32) {
    (
        region["width"]
            .as_u64()
            .unwrap_or(0)
            .min(u64::from(u32::MAX)) as u32,
        region["height"]
            .as_u64()
            .unwrap_or(0)
            .min(u64::from(u32::MAX)) as u32,
    )
}

pub fn point_inside(x: u32, y: u32, width: u32, height: u32) -> bool {
    x < width && y < height
}

/// The rectangle `[x, x+w) × [y, y+h)` lies inside `width × height`; `w`/`h`
/// of zero are out of bounds (64-bit math so `x + w` cannot wrap).
pub fn rect_inside(x: u32, y: u32, w: u32, h: u32, width: u32, height: u32) -> bool {
    w >= 1
        && h >= 1
        && u64::from(x) + u64::from(w) <= u64::from(width)
        && u64::from(y) + u64::from(h) <= u64::from(height)
}

/// The tiles of a rect as a set.
pub fn rect_tiles(x: u32, y: u32, w: u32, h: u32) -> BTreeSet<(u32, u32)> {
    let mut tiles = BTreeSet::new();
    for dy in 0..h {
        for dx in 0..w {
            tiles.insert((x + dx, y + dy));
        }
    }
    tiles
}

/// The L-shaped path from `from` to `to`: horizontal at `from.y` to `to.x`,
/// then vertical at `to.x` to `to.y`. The corner is one tile.
pub fn l_path_tiles(from: [u32; 2], to: [u32; 2]) -> BTreeSet<(u32, u32)> {
    let mut tiles = BTreeSet::new();
    let (lo_x, hi_x) = if from[0] <= to[0] {
        (from[0], to[0])
    } else {
        (to[0], from[0])
    };
    for x in lo_x..=hi_x {
        tiles.insert((x, from[1]));
    }
    let (lo_y, hi_y) = if from[1] <= to[1] {
        (from[1], to[1])
    } else {
        (to[1], from[1])
    };
    for y in lo_y..=hi_y {
        tiles.insert((to[0], y));
    }
    tiles
}

fn rows_as_chars(file: &Value) -> Vec<Vec<char>> {
    file["rows"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|r| r.as_str().unwrap_or_default().chars().collect())
                .collect()
        })
        .unwrap_or_default()
}

fn chars_to_rows(rows: &[Vec<char>]) -> Value {
    Value::Array(
        rows.iter()
            .map(|r| Value::String(r.iter().collect()))
            .collect(),
    )
}

/// `region.json` for a fresh region: empty placements and warps.
pub fn region_file(id: &str, stable_id: &str, width: u32, height: u32, spawn: [u32; 2]) -> Value {
    json!({
        "id": id,
        "stable_id": stable_id,
        "kind": "region",
        "tags": [],
        "intent": "",
        "constraints": [],
        "owner_module": OWNER_MODULE,
        "width": width,
        "height": height,
        "spawn": spawn,
        "placements": [],
        "warps": [],
    })
}

/// `layers/terrain.json` filled with `fill`.
pub fn terrain_file(width: u32, height: u32, fill: Terrain) -> Value {
    let row: String = std::iter::repeat_n(fill.glyph(), width as usize).collect();
    let rows: Vec<String> = std::iter::repeat_n(row, height as usize).collect();
    json!({
        "kind": "terrain",
        "width": width,
        "height": height,
        "legend": legend(),
        "rows": rows,
    })
}

/// `layers/collision.json` derived from a terrain file with no overrides.
pub fn collision_file(width: u32, height: u32, terrain: &Value) -> Value {
    let rows = derive_rows(terrain, &Map::new());
    json!({
        "kind": "collision",
        "width": width,
        "height": height,
        "rows": rows,
        "overrides": {},
    })
}

/// `entities/npc/<stable_id>.json` — every ADR-0003 field; the entity itself
/// carries no coordinates (placements live on the region).
pub fn npc_file(
    id: &str,
    stable_id: &str,
    tags: &[String],
    intent: &str,
    constraints: &[String],
    human_name: Option<&str>,
    facing: Facing,
) -> Value {
    json!({
        "id": id,
        "stable_id": stable_id,
        "kind": "npc",
        "tags": tags,
        "intent": intent,
        "constraints": constraints,
        "owner_module": OWNER_MODULE,
        "human_name": human_name,
        "facing": facing,
    })
}

/// Effective solidity rows for `terrain` under `overrides` (`"x,y" -> bool`).
pub fn derive_rows(terrain: &Value, overrides: &Map<String, Value>) -> Vec<String> {
    terrain["rows"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .enumerate()
                .map(|(y, row)| {
                    row.as_str()
                        .unwrap_or_default()
                        .chars()
                        .enumerate()
                        .map(|(x, glyph)| {
                            match overrides.get(&format!("{x},{y}")) {
                                Some(Value::Bool(solid)) => {
                                    if *solid {
                                        '#'
                                    } else {
                                        '.'
                                    }
                                }
                                _ => {
                                    if glyph_solid(glyph) {
                                        '#'
                                    } else {
                                        '.'
                                    }
                                }
                            }
                        })
                        .collect::<String>()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Effective solidity at `(x, y)` — the override if present, else the terrain
/// glyph's default.
pub fn effective_solid(terrain: &Value, overrides: &Map<String, Value>, x: u32, y: u32) -> bool {
    if let Some(Value::Bool(solid)) = overrides.get(&format!("{x},{y}")) {
        return *solid;
    }
    terrain["rows"]
        .as_array()
        .and_then(|rows| rows.get(y as usize))
        .and_then(|row| row.as_str())
        .and_then(|row| row.chars().nth(x as usize))
        .is_some_and(glyph_solid)
}

/// Set `tiles` in a terrain file's rows to `kind`'s glyph. Returns the number
/// of tiles whose glyph actually changed.
pub fn paint_terrain(terrain: &mut Value, tiles: &BTreeSet<(u32, u32)>, kind: Terrain) -> u64 {
    let mut rows = rows_as_chars(terrain);
    let mut changed = 0u64;
    for &(x, y) in tiles {
        let Some(row) = rows.get_mut(y as usize) else {
            continue;
        };
        let Some(cell) = row.get_mut(x as usize) else {
            continue;
        };
        if *cell != kind.glyph() {
            *cell = kind.glyph();
            changed += 1;
        }
    }
    terrain["rows"] = chars_to_rows(&rows);
    changed
}

/// Recompute a collision file's effective `rows` for `tiles` after a terrain
/// change: tiles with an override keep it; the rest take the new terrain
/// glyph's default. Overrides are never touched (they survive paints).
pub fn recompute_collision(
    collision: &mut Value,
    terrain: &Value,
    tiles: &BTreeSet<(u32, u32)>,
) {
    let empty = Map::new();
    let overrides = collision["overrides"].as_object().unwrap_or(&empty);
    let terrain_rows = rows_as_chars(terrain);
    let mut rows = rows_as_chars(collision);
    for &(x, y) in tiles {
        if overrides.contains_key(&format!("{x},{y}")) {
            continue;
        }
        let solid = terrain_rows
            .get(y as usize)
            .and_then(|row| row.get(x as usize))
            .is_some_and(|g| glyph_solid(*g));
        if let Some(cell) = rows.get_mut(y as usize).and_then(|r| r.get_mut(x as usize)) {
            *cell = if solid { '#' } else { '.' };
        }
    }
    collision["rows"] = chars_to_rows(&rows);
}

/// Record `solid` overrides for every tile of the rect and set the effective
/// rows accordingly. Returns the number of tiles whose effective solidity
/// changed (a repeated request is a no-op and reports zero).
pub fn apply_collision_override(
    collision: &mut Value,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    solid: bool,
) -> Result<u64, String> {
    let mut rows = rows_as_chars(collision);
    let mut changed = 0u64;
    {
        let overrides = collision["overrides"]
            .as_object_mut()
            .ok_or_else(|| String::from("collision overrides must be an object"))?;
        for dy in 0..h {
            for dx in 0..w {
                let (tx, ty) = (x + dx, y + dy);
                overrides.insert(format!("{tx},{ty}"), Value::Bool(solid));
                if let Some(cell) = rows
                    .get_mut(ty as usize)
                    .and_then(|r| r.get_mut(tx as usize))
                {
                    let next = if solid { '#' } else { '.' };
                    if *cell != next {
                        *cell = next;
                        changed += 1;
                    }
                }
            }
        }
    }
    collision["rows"] = chars_to_rows(&rows);
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_match_the_handle_grammar() {
        assert!(valid_handle("town"));
        assert!(valid_handle("route_1"));
        assert!(!valid_handle("Town"));
        assert!(!valid_handle("_town"));
        assert!(!valid_handle(""));
        assert!(!valid_handle("town!"));
    }

    #[test]
    fn rects_must_have_area_and_fit() {
        assert!(rect_inside(0, 0, 4, 4, 16, 16));
        assert!(rect_inside(15, 15, 1, 1, 16, 16));
        assert!(!rect_inside(14, 15, 4, 2, 16, 16));
        assert!(!rect_inside(0, 0, 0, 4, 16, 16));
        assert!(!rect_inside(0, 0, 4, 0, 16, 16));
    }

    #[test]
    fn l_path_bends_horizontal_then_vertical() {
        let tiles = l_path_tiles([1, 1], [3, 4]);
        assert_eq!(
            tiles,
            BTreeSet::from([(1, 1), (2, 1), (3, 1), (3, 2), (3, 3), (3, 4)])
        );
    }

    #[test]
    fn derived_rows_apply_overrides_over_terrain_defaults() {
        let terrain = terrain_file(4, 2, Terrain::Grass);
        let mut overrides = Map::new();
        overrides.insert("1,0".to_string(), Value::Bool(true));
        assert_eq!(derive_rows(&terrain, &overrides), vec![".#..", "...."]);
        assert!(effective_solid(&terrain, &overrides, 1, 0));
        assert!(!effective_solid(&terrain, &overrides, 0, 0));
    }
}
