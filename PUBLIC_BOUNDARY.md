# PUBLIC_BOUNDARY.md

This repository is intended to become public. The rules below hold from the first commit so that flipping visibility is one ceremony, not a history rewrite.

## Machine-checkable rules
<!-- Executed by the release-close boundary audit. Patterns only; nothing here describes content. -->
never-tracked: **/.env, **/.env.*, **/*.pem, **/*.key, **/id_rsa*
never-tracked: **/secrets/**, **/credentials.json, **/*.keychain
never-tracked: **/SPEC.md, **/MASTER-SPEC*, docs/planning/**, docs/handoffs/**, **/.archive/**
never-tracked: **/*.transcript.*, **/transcripts/**
fixtures-must-be: synthetic

## Working-tree hygiene allowlist
<!-- Classes of untracked files that may exist in a local clone, named by pattern only. -->
- `.env*` (untracked)
- `docs/private/**` (untracked)
- `*.local.json` (untracked)
- `.worktrees/**` (untracked)

## Never here (prose rules)
- No secrets, tokens, or credentials of any kind, including provider API keys.
- No downstream strategy, roadmap, competitive material, or planning documents.
- No non-synthetic fixtures. The reference project and every eval fixture are neutral, invented content.
- No AI-workspace material: specs in progress, planning docs, agent transcripts, session handoffs.
- No prototype or spike code. Spikes are discarded; behavior is reimplemented here under normal ceremony.
- No private-side implementation of a declared port. This repo holds the module port; a private module lives elsewhere.
- No content, mechanics, or names belonging to any privately developed title.
