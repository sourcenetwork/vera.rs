//! Genesis-bound limits for pipelined Simplex.

use serde::{Deserialize, Serialize};

/// Shared consensus parameters for a pipelined deployment.
///
/// These parameters are fixed by the deployment genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimplexParameters {
    /// Consecutive views assigned to one leader.
    pub term_length: u64,
    /// Maximum optimistic distance from certified ancestry.
    pub optimistic_views: u64,
    /// Maximum finality stall before abandoning the leader's term.
    pub stall_timeout_ms: u64,
}

impl Default for SimplexParameters {
    fn default() -> Self {
        Self {
            term_length: 16,
            optimistic_views: 4,
            stall_timeout_ms: 5_000,
        }
    }
}

impl SimplexParameters {
    /// Validate resource bounds before constructing Commonware's elector.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.term_length < 2 || self.term_length > 64 {
            return Err("Simplex term_length must be between 2 and 64");
        }
        if self.optimistic_views > 16 || self.optimistic_views >= self.term_length {
            return Err("Simplex optimistic_views must be at most 16 and less than term_length");
        }
        if self.stall_timeout_ms == 0 || self.stall_timeout_ms > 60_000 {
            return Err("Simplex stall_timeout_ms must be between 1 and 60000");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unbounded_or_inconsistent_pipeline_parameters() {
        let defaults = SimplexParameters::default();
        assert!(defaults.validate().is_ok());
        for term_length in [0, 1, 65, u64::MAX] {
            assert!(
                SimplexParameters {
                    term_length,
                    ..defaults
                }
                .validate()
                .is_err()
            );
        }
        for optimistic_views in [16, 17, u64::MAX] {
            assert!(
                SimplexParameters {
                    optimistic_views,
                    ..defaults
                }
                .validate()
                .is_err()
            );
        }
        for stall_timeout_ms in [0, 60_001, u64::MAX] {
            assert!(
                SimplexParameters {
                    stall_timeout_ms,
                    ..defaults
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            SimplexParameters {
                optimistic_views: 0,
                ..defaults
            }
            .validate()
            .is_ok()
        );
    }
}
