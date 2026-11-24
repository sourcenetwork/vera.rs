//! Genesis configuration builder for e2e test clusters.
//!
//! Uses local mirror types that match vera-genesis's JSON schema exactly,
//! so vera-harness can construct genesis.json without importing vera-genesis.

use std::path::Path;

use serde::Serialize;
use vera_modules::acp::{
    PolicySeed,
    types::{PolicyMarshalingType, PolicyNonce},
};
use vera_modules::vera::administration::OperatorPolicy;
use vera_modules::vera::rings::reports::NodeDemeritSeed;

/// Matches vera-genesis VeraGenesis JSON schema exactly.
#[derive(Clone, Debug, Serialize)]
pub struct VeraGenesis {
    /// Chain ID for the test network.
    pub chain_id: u64,
    /// Initial operator approval policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operators: Option<OperatorPolicy>,
    /// ACP policies seeded with caller-assigned counters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicySeed>,
    /// Orbis node-demerit scores seeded directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_demerits: Vec<NodeDemeritSeed>,
    /// Genesis timestamp (unix seconds).
    pub timestamp: u64,
    /// Initial validator set.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Hex-encoded epoch-0 DKG `EpochInfo` (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_info: Option<String>,
    /// Number of blocks in each DKG epoch.
    pub blocks_per_epoch: u64,
    /// Pipelined consensus parameters.
    pub simplex: vera_domain::SimplexParameters,
}

/// An initial validator entry.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorConfig {
    /// Validator's registry address.
    pub address: String,
    /// Validator's consensus public key.
    pub consensus_pubkey: String,
    /// Validator's P2P listen address.
    pub p2p_address: String,
}

/// Builder for test genesis configurations.
#[derive(Debug)]
pub struct GenesisBuilder {
    chain_id: u64,
    operators: Option<OperatorPolicy>,
    policies: Vec<PolicySeed>,
    node_demerits: Vec<NodeDemeritSeed>,
    validators: Vec<ValidatorConfig>,
    epoch_info: Option<String>,
    blocks_per_epoch: Option<u64>,
    simplex: vera_domain::SimplexParameters,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            chain_id: 9001,
            operators: None,
            policies: Vec::new(),
            node_demerits: Vec::new(),
            validators: Vec::new(),
            epoch_info: None,
            blocks_per_epoch: None,
            simplex: vera_domain::SimplexParameters::default(),
        }
    }
}

impl GenesisBuilder {
    /// Create a builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-configured for devnet: chain ID 9001 and pipelined consensus.
    pub fn devnet() -> Self {
        Self::default()
    }

    /// Set the initial operator approval policy.
    #[must_use]
    pub fn operators(mut self, policy: OperatorPolicy) -> Self {
        self.operators = Some(policy);
        self
    }

    /// Seed one ACP policy at genesis under `GENESIS_POLICY_CREATOR` and
    /// `nonce`. Predict its resulting id with `AcpModule::predict_policy_id`
    /// before calling `build`/`build_and_write`.
    #[must_use]
    pub fn policy(
        mut self,
        definition: impl Into<String>,
        marshal_type: PolicyMarshalingType,
        nonce: PolicyNonce,
    ) -> Self {
        self.policies.push(PolicySeed {
            definition: definition.into(),
            marshal_type,
            nonce,
        });
        self
    }

    /// Seed one Orbis node-demerit score at genesis, bypassing the normal
    /// report-submission path entirely.
    #[must_use]
    pub fn node_demerit(
        mut self,
        ring_id: impl Into<String>,
        node_key: impl Into<String>,
        points: u64,
        window_started_at: u64,
    ) -> Self {
        self.node_demerits.push(NodeDemeritSeed {
            ring_id: ring_id.into(),
            node_key: node_key.into(),
            points,
            window_started_at,
        });
        self
    }

    /// Set the chain ID.
    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// Set the initial validator set.
    #[must_use]
    pub fn validators(mut self, configs: Vec<ValidatorConfig>) -> Self {
        self.validators = configs;
        self
    }

    pub(crate) fn validators_if_empty(mut self, configs: Vec<ValidatorConfig>) -> Self {
        if self.validators.is_empty() {
            self.validators = configs;
        }
        self
    }

    /// Set the hex-encoded epoch-0 DKG `EpochInfo`.
    #[must_use]
    pub fn epoch_info(mut self, epoch_info: impl Into<String>) -> Self {
        self.epoch_info = Some(epoch_info.into());
        self
    }

    /// Set the number of blocks in each DKG epoch.
    #[must_use]
    pub const fn blocks_per_epoch(mut self, blocks_per_epoch: u64) -> Self {
        self.blocks_per_epoch = Some(blocks_per_epoch);
        self
    }

    /// Set the pipelined consensus parameters.
    #[must_use]
    pub const fn simplex(mut self, parameters: vera_domain::SimplexParameters) -> Self {
        self.simplex = parameters;
        self
    }

    /// The epoch length: 192 blocks unless explicitly set.
    fn epoch_length(&self) -> u64 {
        self.blocks_per_epoch.unwrap_or(192)
    }

    /// Build the genesis configuration.
    pub fn build(self) -> VeraGenesis {
        let blocks_per_epoch = self.epoch_length();
        VeraGenesis {
            chain_id: self.chain_id,
            operators: self.operators.clone(),
            policies: self.policies,
            node_demerits: self.node_demerits,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_secs(),
            validators: self.validators,
            epoch_info: self.epoch_info,
            blocks_per_epoch,
            simplex: self.simplex,
        }
    }

    /// Build and write genesis.json to a directory.
    pub fn build_and_write(&self, dir: &Path) -> eyre::Result<VeraGenesis> {
        let genesis = VeraGenesis {
            chain_id: self.chain_id,
            operators: self.operators.clone(),
            policies: self.policies.clone(),
            node_demerits: self.node_demerits.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_secs(),
            validators: self.validators.clone(),
            epoch_info: self.epoch_info.clone(),
            blocks_per_epoch: self.epoch_length(),
            simplex: self.simplex,
        };

        let json = serde_json::to_string_pretty(&genesis)?;
        std::fs::write(dir.join("genesis.json"), json)?;
        Ok(genesis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_genesis() {
        let genesis = GenesisBuilder::devnet().build();
        assert_eq!(genesis.chain_id, 9001);
        assert_eq!(genesis.simplex, vera_domain::SimplexParameters::default());
    }

    #[test]
    fn custom_genesis() {
        let genesis = GenesisBuilder::new().chain_id(1337).build();
        assert_eq!(genesis.chain_id, 1337);
        assert!(genesis.validators.is_empty());
    }

    #[test]
    fn epoch_default_preserves_explicit_lengths() {
        let parameters = vera_domain::SimplexParameters::default();
        assert_eq!(GenesisBuilder::devnet().build().blocks_per_epoch, 192);
        assert_eq!(
            GenesisBuilder::devnet()
                .simplex(parameters)
                .build()
                .blocks_per_epoch,
            192
        );
        for builder in [
            GenesisBuilder::devnet()
                .blocks_per_epoch(20)
                .simplex(parameters),
            GenesisBuilder::devnet()
                .simplex(parameters)
                .blocks_per_epoch(20),
        ] {
            let dir = tempfile::tempdir().unwrap();
            assert_eq!(
                builder
                    .build_and_write(dir.path())
                    .unwrap()
                    .blocks_per_epoch,
                20
            );
            assert_eq!(builder.build().blocks_per_epoch, 20);
        }
        let dir = tempfile::tempdir().unwrap();
        let generated = GenesisBuilder::devnet()
            .simplex(parameters)
            .build_and_write(dir.path())
            .unwrap();
        let serialized: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("genesis.json")).unwrap())
                .unwrap();
        assert_eq!(generated.blocks_per_epoch, 192);
        assert_eq!(serialized["blocks_per_epoch"], 192);
    }

    #[test]
    fn write_genesis_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = GenesisBuilder::devnet()
            .build_and_write(dir.path())
            .unwrap();

        assert!(dir.path().join("genesis.json").exists());
        assert_eq!(genesis.chain_id, 9001);
    }
}
