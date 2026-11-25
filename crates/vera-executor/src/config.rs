//! Execution configuration.

/// Execution configuration.
#[derive(Clone, Debug)]
pub struct ExecutionConfig {
    /// Epoch length for execution-derived membership selection on native nodes.
    pub membership_epoch_length: Option<std::num::NonZeroU64>,
    /// Consecutive views per leader.
    pub membership_term_length: std::num::NonZeroU64,
    /// Genesis record identifier used to bind administrative approvals.
    pub genesis_id: [u8; 32],
    /// Chain ID for transaction validation.
    pub chain_id: u64,
}

impl ExecutionConfig {
    /// Create a new execution config with the given chain ID.
    pub const fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            membership_epoch_length: None,
            membership_term_length: std::num::NonZeroU64::MIN,
            genesis_id: [0; 32],
        }
    }

    /// Maximum active committee allowed by the deployment epoch length.
    pub fn max_active_members(&self) -> u32 {
        self.membership_epoch_length
            .map_or(vera_domain::MAX_DKG_PARTICIPANTS.get(), |length| {
                vera_domain::max_epoch_participants(length, self.membership_term_length)
            })
    }

    /// Bounds membership commands keep the registry within.
    pub fn membership_limits(&self) -> vera_modules::validator_registry::MembershipLimits {
        vera_modules::validator_registry::MembershipLimits {
            members: vera_domain::MAX_DKG_PARTICIPANTS.get(),
            active: self.max_active_members(),
        }
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
        assert_eq!(
            config.membership_limits().members,
            vera_domain::MAX_DKG_PARTICIPANTS.get()
        );
    }
}
