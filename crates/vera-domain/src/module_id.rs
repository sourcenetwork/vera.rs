//! Native module identifiers in canonical partition order.

use serde::{Deserialize, Serialize};

/// Identifies an authenticated native module partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    /// Access control policy module.
    Acp = 0,
    /// Bulletin board module.
    Bulletin = 1,
    /// Vera identity module.
    Vera = 2,
    /// Native BLS nonce tracking.
    NativeNonce = 3,
}

impl ModuleId {
    /// Returns the index of this module in the roots array.
    pub const fn index(self) -> usize {
        self as usize
    }
}
