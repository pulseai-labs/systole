//! `systole.lock.json` — the resolved engine and module versions a project
/// was last written against.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::manifest::Engine;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Lock {
    pub engine: Engine,
    pub modules: BTreeMap<String, String>,
}
