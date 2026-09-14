//! Stable ids from the manifest's shared counter (ADR-0003): counter-allocated,
//! never reused, and only persisted by a commit (which is `r0.s1.w2`).

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum IdKind {
    Ent,
    Region,
    Flag,
    Warp,
}

impl IdKind {
    pub fn prefix(&self) -> &'static str {
        match self {
            IdKind::Ent => "ent",
            IdKind::Region => "region",
            IdKind::Flag => "flag",
            IdKind::Warp => "warp",
        }
    }
}

/// A stable id rendered `ent_00041` / `region_00003` / `flag_00012` — kind
/// prefix, underscore, five-digit zero-padded counter.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(into = "String", try_from = "String")]
pub struct StableId {
    pub kind: IdKind,
    pub n: u64,
}

impl StableId {
    pub fn new(kind: IdKind, n: u64) -> Self {
        StableId { kind, n }
    }
}

impl fmt::Display for StableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{:05}", self.kind.prefix(), self.n)
    }
}

impl From<StableId> for String {
    fn from(id: StableId) -> String {
        id.to_string()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid stable id: {0}")]
pub struct StableIdParseError(String);

impl TryFrom<String> for StableId {
    type Error = StableIdParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (prefix, n) = s
            .rsplit_once('_')
            .ok_or_else(|| StableIdParseError(s.clone()))?;
        let n: u64 = n
            .parse()
            .map_err(|_| StableIdParseError(s.clone()))?;
        let kind = match prefix {
            "ent" => IdKind::Ent,
            "region" => IdKind::Region,
            "flag" => IdKind::Flag,
            "warp" => IdKind::Warp,
            _ => return Err(StableIdParseError(s)),
        };
        Ok(StableId { kind, n })
    }
}

/// Reads the manifest's shared counter. The number space is shared across all
/// kinds so an id is never reused even when kinds interleave.
pub struct IdAllocator {
    counter: u64,
}

impl IdAllocator {
    pub fn new(start: u64) -> Self {
        IdAllocator { counter: start }
    }

    pub fn next(&mut self, kind: IdKind) -> StableId {
        self.counter += 1;
        StableId::new(kind, self.counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_id_round_trips_through_its_string_form() {
        let id = StableId::try_from("region_00007".to_string()).unwrap();
        assert_eq!(id.kind, IdKind::Region);
        assert_eq!(id.n, 7);
        assert_eq!(id.to_string(), "region_00007");
        assert!(StableId::try_from("nope".to_string()).is_err());

        let warp = StableId::try_from("warp_00003".to_string()).unwrap();
        assert_eq!(warp.kind, IdKind::Warp);
        assert_eq!(warp.to_string(), "warp_00003");
    }
}
