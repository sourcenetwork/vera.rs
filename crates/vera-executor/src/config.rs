//! Execution configuration.

use revm::primitives::hardfork::SpecId;

/// Execution configuration.
#[derive(Clone, Debug)]
pub struct ExecutionConfig {
    /// Epoch length for execution-derived membership selection on native nodes.
    pub membership_epoch_length: Option<std::num::NonZeroU64>,
    /// Consecutive views per leader; one selects rotating leaders.
    pub membership_term_length: std::num::NonZeroU64,
    /// Genesis record identifier used to bind administrative approvals.
    pub genesis_id: [u8; 32],
    /// Chain ID for transaction validation.
    pub chain_id: u64,
    /// Hardfork specification.
    pub spec_id: SpecId,
}

impl ExecutionConfig {
    /// Create a new execution config with the given chain ID.
    pub const fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            membership_epoch_length: None,
            membership_term_length: std::num::NonZeroU64::MIN,
            genesis_id: [0; 32],
            spec_id: SpecId::CANCUN,
        }
    }

    /// Maximum active committee allowed by the deployment epoch length.
    pub fn max_active_members(&self) -> u32 {
        self.membership_epoch_length
            .map_or(vera_domain::MAX_DKG_PARTICIPANTS.get(), |length| {
                vera_domain::max_epoch_participants(length, self.membership_term_length)
            })
    }

    /// Set the hardfork specification.
    #[must_use]
    pub const fn with_spec_id(mut self, spec_id: SpecId) -> Self {
        self.spec_id = spec_id;
        self
    }
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default() {
        let config = ExecutionConfig::default();
        assert_eq!(config.chain_id, 1);
        assert_eq!(config.spec_id, SpecId::CANCUN);
    }

    #[test]
    fn config_builder() {
        let config = ExecutionConfig::new(42).with_spec_id(SpecId::PRAGUE);

        assert_eq!(config.chain_id, 42);
        assert_eq!(config.spec_id, SpecId::PRAGUE);
    }
}
