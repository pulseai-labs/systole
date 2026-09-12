# Systole — executive summary

Systole is an agent-native game engine written in Rust. The canonical state of a game project is a machine-readable authoring graph, the Project IR, stored as canonical JSON that the engine owns and formats. Every change to that graph is a typed, previewable, reversible transaction: a request is materialized against the current project, diffed, validated, committed atomically, and recorded in an append-only audit log with the inverse data needed to roll it back. There is no GUI editor. Coding agents such as Claude Code and Codex drive the engine through a command-line interface; the runtime is one consumer of the graph among several.

The problem it solves: in GUI-first engines a coding agent can write game logic but cannot do editor work, because the editor is the obstacle. Systole removes the editor from the authoring path and gives the agent a small catalog of deterministic operations, structured validation findings with suggested repairs, and headless simulation, so that correctness never depends on a screenshot.

The first genre module targets top-down 2.5D creature-collector RPGs. Validation and agent task evaluations are release criteria: the engine is judged by whether an agent can build and repair a game with it from a clean checkout.

## What Release 0 delivers

At Release 0 close, a coding agent can, from a clean checkout of this repository, initialize a project, create a town region with one NPC and one warp through audited, reversible transactions via the `systole` CLI, and pass validation.

The path an agent walks:

1. `systole project init` creates a project at schema 1.
2. `systole op list` and `systole op describe` expose the operation catalog with schemas and examples.
3. Region, terrain, collision, NPC, and warp operations are previewed, applied, and audited one transaction at a time.
4. `systole validate --all` reports reference-integrity and reachability findings as JSON with stable ids; a suggested fix flows through the same transaction lifecycle.
5. `systole rollback` reverses a transaction with a compensating audit entry.
6. Any out-of-band edit to project files is refused at load time with a repair hint.
7. An eval harness runs the whole journey with an agent and checks the result.

Release 0 contains no scripting, no MCP server, no runtime or renderer, and no AI providers. Those follow once the skeleton proves the loop.
