//! `systole-core` — Project IR, core contracts, and the transaction engine's
//! substrate. Module id `systole.core`.
//!
//! This item (r0.s1.w1) provides the IR on disk, its canonical format and
//! hash, and the operation/registry/module contracts. The engine lifecycle
//! around them (revision binding, two-phase commit, audit append) is
//! r0.s1.w2.

pub mod audit;
pub mod capability;
pub mod doctor;
pub mod engine;
pub mod finding;
#[cfg(feature = "fixture-ops")]
pub mod fixture;
pub mod ids;
pub mod ir;
pub mod lock;
pub mod module;
pub mod op;
pub mod registry;
pub mod revision;
pub mod tx;
