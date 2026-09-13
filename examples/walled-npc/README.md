# walled-npc

A committed Systole project exercising the validate → plan → apply repair
loop end to end. Built entirely through the CLI (`project init`,
`rpg.create_region`, `rpg.paint_area`, `rpg.place_npc`, `rpg.mark_warp`), so
its audit chain and project hash are consistent — `project check` passes.

Contents: a 16×16 `town` (spawn `(1,1)`) with `elder` placed at `(5,5)`
inside a closed 3×3 wall ring whose centre tile is floor, plus a warp at
`(15,8)` pointing at the unbuilt `route_1`.

`validate --all` here exits 1 with two findings:

- `rpg.reachability.unreachable_npc` (blocking) — the elder is sealed inside
  the ring; its suggested `rpg.set_collision` door fix, planned via
  `plan --from-finding` and applied through `apply`, clears it.
- `rpg.warp.dangling_target` (advisory) — `route_1` does not exist yet; the
  suggested `rpg.create_region` fix carries the source region's dimensions
  and spawn.

This fixture is the release's exit-criterion-2 project and the starting
point for `examples/` work in later items. Nothing writes into it after
commit; copy it first (`cp -R examples/walled-npc <dest>`) before applying
fixes.
