//! Genesis configuration builder for e2e test clusters.
//!
//! Uses local mirror types that match vera-genesis's JSON schema exactly,
//! so vera-harness can construct genesis.json without importing vera-genesis.

use std::path::Path;

use serde::Serialize;
use vera_modules::vera::administration::OperatorPolicy;

/// Matches vera-genesis VeraGenesis JSON schema exactly.
#[derive(Clone, Debug, Serialize)]
pub struct VeraGenesis {
    /// Chain ID for the test network.
    pub chain_id: u64,
    /// Initial operator approval policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operators: Option<OperatorPolicy>,
    /// Human-readable chain name.
    pub chain_name: String,
    /// Genesis timestamp (unix seconds).
    pub timestamp: u64,
    /// Pre-funded accounts.
    pub allocations: Vec<GenesisAllocation>,
    /// Native token mint configuration.
    pub native_mint: NativeMintConfig,
    /// Initial validator set.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Contract bytecode deployed at genesis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<GenesisContract>,
    /// Storage slots pre-set at genesis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_storage: Vec<GenesisStorage>,
    /// Hex-encoded epoch-0 DKG `EpochInfo` (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_info: Option<String>,
    /// Number of blocks in each DKG epoch.
    #[serde(default, skip_serializing_if = "is_default_blocks_per_epoch")]
    pub blocks_per_epoch: u64,
    /// Pipelined consensus parameters. Omission preserves rotating leaders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simplex: Option<vera_domain::SimplexParameters>,
}

const fn is_default_blocks_per_epoch(value: &u64) -> bool {
    *value == 20
}

/// A pre-funded account allocation.
#[derive(Clone, Debug, Serialize)]
pub struct GenesisAllocation {
    /// EVM address of the account.
    pub address: String,
    /// Initial balance in wei.
    pub balance: String,
}

/// An initial validator entry.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorConfig {
    /// Validator's EVM address.
    pub evm_address: String,
    /// Validator's consensus public key.
    pub consensus_pubkey: String,
    /// Validator's P2P listen address.
    pub p2p_address: String,
}

/// Native token mint configuration.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NativeMintConfig {
    /// Address allowed to grant minter roles.
    #[serde(default)]
    pub admin: Option<String>,
    /// Addresses allowed to mint.
    #[serde(default)]
    pub minters: Vec<String>,
    /// Native token denomination.
    pub denom: String,
}

/// Arbitrary contract bytecode injected at genesis.
#[derive(Clone, Debug, Serialize)]
pub struct GenesisContract {
    /// Contract address.
    pub address: String,
    /// Hex-encoded init bytecode.
    pub bytecode: String,
}

/// Pre-set storage slot at genesis.
#[derive(Clone, Debug, Serialize)]
pub struct GenesisStorage {
    /// Contract address.
    pub address: String,
    /// Storage slot key.
    pub slot: String,
    /// Storage slot value.
    pub value: String,
}

/// Builder for test genesis configurations.
#[derive(Debug)]
pub struct GenesisBuilder {
    chain_id: u64,
    operators: Option<OperatorPolicy>,
    chain_name: String,
    allocations: Vec<GenesisAllocation>,
    native_mint: NativeMintConfig,
    validators: Vec<ValidatorConfig>,
    contracts: Vec<GenesisContract>,
    extra_storage: Vec<GenesisStorage>,
    epoch_info: Option<String>,
    blocks_per_epoch: Option<u64>,
    simplex: Option<vera_domain::SimplexParameters>,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            chain_id: 9001,
            operators: None,
            chain_name: "vera-test".to_string(),
            allocations: Vec::new(),
            native_mint: NativeMintConfig::default(),
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_info: None,
            blocks_per_epoch: None,
            simplex: None,
        }
    }
}

impl GenesisBuilder {
    /// Create a builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-configured for devnet (matches `VeraGenesis::devnet()`).
    pub fn devnet() -> Self {
        Self {
            chain_id: 9001,
            operators: None,
            chain_name: "vera-devnet".to_string(),
            allocations: vec![
                GenesisAllocation {
                    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                    balance: "1000000000000000000000".to_string(),
                },
                GenesisAllocation {
                    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
                    balance: "1000000000000000000000".to_string(),
                },
            ],
            native_mint: NativeMintConfig {
                admin: Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string()),
                minters: vec!["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string()],
                denom: "abrl".to_string(),
            },
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_info: None,
            blocks_per_epoch: None,
            simplex: None,
        }
    }

    /// Set the initial operator approval policy.
    #[must_use]
    pub fn operators(mut self, policy: OperatorPolicy) -> Self {
        self.operators = Some(policy);
        self
    }

    /// Set the chain ID.
    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// Set the chain name.
    #[must_use]
    pub fn chain_name(mut self, name: impl Into<String>) -> Self {
        self.chain_name = name.into();
        self
    }

    /// Add a pre-funded account allocation.
    #[must_use]
    pub fn allocation(mut self, address: &str, balance: &str) -> Self {
        self.allocations.push(GenesisAllocation {
            address: address.to_string(),
            balance: balance.to_string(),
        });
        self
    }

    /// Add pre-funded test accounts (up to 10).
    #[must_use]
    pub fn funded_accounts(mut self, count: usize, balance: &str) -> Self {
        const TEST_ADDRESSES: [&str; 10] = [
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
            "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
            "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
            "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
            "0x14dC79964da2C08daa4968306Dba23d250591E0A",
            "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
            "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
        ];

        for addr in TEST_ADDRESSES.iter().take(count) {
            self.allocations.push(GenesisAllocation {
                address: (*addr).to_string(),
                balance: balance.to_string(),
            });
        }
        self
    }

    /// Set the native token mint configuration.
    #[must_use]
    pub fn native_mint(mut self, config: NativeMintConfig) -> Self {
        self.native_mint = config;
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

    /// Add arbitrary contract bytecode at genesis.
    #[must_use]
    pub fn contract(mut self, address: &str, bytecode: &str) -> Self {
        self.contracts.push(GenesisContract {
            address: address.to_string(),
            bytecode: bytecode.to_string(),
        });
        self
    }

    /// Pre-set a storage slot at genesis.
    #[must_use]
    pub fn storage(mut self, address: &str, slot: &str, value: &str) -> Self {
        self.extra_storage.push(GenesisStorage {
            address: address.to_string(),
            slot: slot.to_string(),
            value: value.to_string(),
        });
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

    /// Configure bounded stable-leader consensus for this deployment.
    /// Unless explicitly set, the epoch length becomes 192 blocks.
    pub const fn simplex(mut self, parameters: vera_domain::SimplexParameters) -> Self {
        self.simplex = Some(parameters);
        self
    }

    fn epoch_length(&self) -> u64 {
        self.blocks_per_epoch
            .unwrap_or(if self.simplex.is_some() { 192 } else { 20 })
    }

    /// Build the genesis configuration.
    pub fn build(self) -> VeraGenesis {
        let blocks_per_epoch = self.epoch_length();
        VeraGenesis {
            chain_id: self.chain_id,
            operators: self.operators.clone(),
            chain_name: self.chain_name,
            timestamp: 0,
            allocations: self.allocations,
            native_mint: self.native_mint,
            validators: self.validators,
            contracts: self.contracts,
            extra_storage: self.extra_storage,
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
            chain_name: self.chain_name.clone(),
            timestamp: 0,
            allocations: self.allocations.clone(),
            native_mint: self.native_mint.clone(),
            validators: self.validators.clone(),
            contracts: self.contracts.clone(),
            extra_storage: self.extra_storage.clone(),
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
        assert_eq!(genesis.allocations.len(), 2);
        assert_eq!(genesis.native_mint.denom, "abrl");
    }

    #[test]
    fn custom_genesis() {
        let genesis = GenesisBuilder::new()
            .chain_id(1337)
            .allocation(
                "0xdead000000000000000000000000000000000000",
                "1000000000000000000000",
            )
            .build();

        assert_eq!(genesis.chain_id, 1337);
        assert_eq!(genesis.allocations.len(), 1);
    }

    #[test]
    fn funded_accounts_genesis() {
        let genesis = GenesisBuilder::new()
            .funded_accounts(3, "1000000000000000000000")
            .build();

        assert_eq!(genesis.allocations.len(), 3);
        assert!(genesis.allocations[0].address.starts_with("0xf39F"));
    }

    #[test]
    fn genesis_with_contracts_and_storage() {
        let genesis = GenesisBuilder::new()
            .contract(
                "0x1234000000000000000000000000000000000000",
                "0x600160005260206000f3",
            )
            .storage("0x1234000000000000000000000000000000000000", "0x0", "0x2a")
            .build();

        assert_eq!(genesis.contracts.len(), 1);
        assert_eq!(genesis.extra_storage.len(), 1);
    }

    #[test]
    fn pipelined_epoch_default_preserves_explicit_lengths() {
        let parameters = vera_domain::SimplexParameters::default();
        assert_eq!(GenesisBuilder::devnet().build().blocks_per_epoch, 20);
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
