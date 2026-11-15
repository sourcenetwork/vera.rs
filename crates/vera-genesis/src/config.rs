//! Vera genesis configuration.

use std::{path::Path, str::FromStr};

use crate::{
    VeraGenesisError,
    state::GenesisState,
    validators::{PRECOMPILE_SENTINEL_BYTECODE, validator_storage_entries},
};
use alloy_evm::revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use vera_modules::validator_registry::layout::ADDRESS as VALIDATOR_REGISTRY_ADDRESS;

/// Vera genesis configuration: the EVM allocations and code together with
/// the deployment's operators, seeded policies, validators and consensus
/// parameters.
///
/// A key this struct does not define is an error, so a misspelled optional
/// section cannot fall back to its default unnoticed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VeraGenesis {
    /// Chain ID.
    pub chain_id: u64,
    /// Initial operator approval policy. Omission disables administrative writes.
    #[serde(default)]
    pub operators: Option<vera_modules::vera::administration::OperatorPolicy>,
    /// ACP policies seeded with caller-assigned counters (1, 2, ... in list
    /// order), bypassing the live creation counter -- lets a deployment (or
    /// test harness) know a policy's id before genesis exists, the same way
    /// `operators` is seeded directly rather than through a live tx.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<vera_modules::acp::PolicySeed>,
    /// ACP policies seeded under counters and owners the deployment chooses,
    /// so a host that already names a policy by its identifier finds it there.
    /// Not combined with `policies`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placed_policies: Vec<vera_modules::acp::PlacedPolicy>,
    /// Orbis node-demerit scores seeded directly, bypassing the normal
    /// report-submission path entirely. Each entry's `ring_id` is the
    /// caller's own responsibility to predict (`RingConfig::id()` composed
    /// with a genesis-seeded `policy_id` above) -- nothing here creates the
    /// ring itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_demerits: Vec<vera_modules::vera::rings::reports::NodeDemeritSeed>,
    /// Genesis timestamp.
    #[serde(default = "default_timestamp")]
    pub timestamp: u64,
    /// Initial account allocations.
    pub allocations: Vec<GenesisAllocation>,
    /// Genesis validators for the ValidatorRegistry precompile.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Arbitrary contract bytecode to deploy at genesis.
    #[serde(default)]
    pub contracts: Vec<GenesisContract>,
    /// Pre-set storage slot values at genesis.
    #[serde(default)]
    pub extra_storage: Vec<GenesisStorage>,
    /// Hex-encoded `EpochInfo<MinSig, ed25519::PublicKey, Unit>` for epoch 0
    /// (commonware codec `Encode`d bytes), produced by the bootstrap DKG.
    #[serde(default)]
    pub epoch_info: Option<String>,
    /// Number of blocks in each DKG epoch.
    #[serde(default = "default_blocks_per_epoch")]
    pub blocks_per_epoch: u64,
    /// Pipelined consensus parameters. Omission preserves rotating leaders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simplex: Option<vera_domain::SimplexParameters>,
    /// Limit, in seconds, on how far a block's timestamp may advance past its
    /// parent's; omission keeps the application default. A deployment that
    /// finalizes less often than the limit, or pauses, falls behind the clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_step_secs: Option<u64>,
}

const fn default_blocks_per_epoch() -> u64 {
    20
}

const fn default_timestamp() -> u64 {
    0
}

/// A single genesis allocation entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAllocation {
    /// Account address (hex with 0x prefix).
    pub address: String,
    /// Account balance (decimal string).
    pub balance: String,
}

/// A genesis validator entry for the ValidatorRegistry precompile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// EVM address (hex with 0x prefix).
    pub evm_address: String,
    /// Ed25519 consensus public key (hex string, 64 chars).
    pub consensus_pubkey: String,
    /// P2P network address (e.g., "127.0.0.1:30300").
    pub p2p_address: String,
}

/// Arbitrary contract bytecode to deploy at genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisContract {
    /// Contract address (hex with 0x prefix).
    pub address: String,
    /// Contract bytecode (hex with 0x prefix).
    pub bytecode: String,
}

/// Pre-set storage slot at genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisStorage {
    /// Account address (hex with 0x prefix).
    pub address: String,
    /// Storage slot (hex with 0x prefix).
    pub slot: String,
    /// Storage value (hex with 0x prefix).
    pub value: String,
}

impl VeraGenesis {
    /// Load genesis from a JSON file.
    pub fn load(path: &Path) -> Result<Self, VeraGenesisError> {
        let content = std::fs::read_to_string(path)?;
        let genesis: Self = serde_json::from_str(&content)?;
        Ok(genesis)
    }

    /// Require a shared launch time for bounded block timestamps.
    pub fn validate_timestamp(&self) -> Result<(), VeraGenesisError> {
        if self.timestamp == 0 {
            return Err(VeraGenesisError::Parse(
                "genesis timestamp must be nonzero".into(),
            ));
        }
        Ok(())
    }

    /// Decode the hex-encoded epoch-0 `EpochInfo<MinSig, ed25519::PublicKey, Unit>`.
    pub fn decode_epoch_info(
        &self,
    ) -> Result<
        Option<
            commonware_glue::dkg::types::EpochInfo<
                commonware_cryptography::bls12381::primitives::variant::MinSig,
                commonware_cryptography::ed25519::PublicKey,
                commonware_utils::sequence::Unit,
            >,
        >,
        VeraGenesisError,
    > {
        let Some(raw) = self.epoch_info.as_deref() else {
            return Ok(None);
        };
        let raw = raw.strip_prefix("0x").unwrap_or(raw);
        let bytes = hex::decode(raw)
            .map_err(|e| VeraGenesisError::Parse(format!("invalid epoch_info hex: {e}")))?;
        let info = commonware_codec::Decode::decode_cfg(
            commonware_codec::Copying(bytes.as_slice()),
            &(
                vera_domain::MAX_DKG_PARTICIPANTS,
                commonware_cryptography::bls12381::primitives::sharing::ModeVersion::v0(),
            ),
        )
        .map_err(|e| VeraGenesisError::Parse(format!("invalid epoch_info encoding: {e}")))?;
        Ok(Some(info))
    }

    /// Build the EVM genesis state: balances, registry storage, and code.
    pub fn to_genesis_state(&self) -> Result<GenesisState, VeraGenesisError> {
        if let Some(policy) = &self.operators {
            policy
                .validate()
                .map_err(|error| VeraGenesisError::Parse(error.to_string()))?;
        }
        let mut genesis_alloc = Vec::with_capacity(self.allocations.len());
        for alloc in &self.allocations {
            let address = Address::from_str(&alloc.address)
                .map_err(|e| VeraGenesisError::Parse(format!("invalid address: {}", e)))?;
            let balance = U256::from_str(&alloc.balance)
                .map_err(|e| VeraGenesisError::Parse(format!("invalid balance: {}", e)))?;
            genesis_alloc.push((address, balance));
        }

        let (mut genesis_storage, mut genesis_code) = if self.validators.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let entries = validator_storage_entries(&self.validators)?;
            let storage = vec![(VALIDATOR_REGISTRY_ADDRESS, entries)];
            let code = vec![(
                VALIDATOR_REGISTRY_ADDRESS,
                PRECOMPILE_SENTINEL_BYTECODE.to_vec(),
            )];
            (storage, code)
        };

        for contract in &self.contracts {
            let address = Address::from_str(&contract.address)
                .map_err(|e| VeraGenesisError::Parse(format!("invalid contract address: {}", e)))?;
            let bytecode_hex = contract
                .bytecode
                .strip_prefix("0x")
                .unwrap_or(&contract.bytecode);
            let bytecode = hex::decode(bytecode_hex).map_err(|e| {
                VeraGenesisError::Parse(format!("invalid contract bytecode: {}", e))
            })?;
            genesis_code.push((address, bytecode));
        }

        for entry in &self.extra_storage {
            let address = Address::from_str(&entry.address)
                .map_err(|e| VeraGenesisError::Parse(format!("invalid storage address: {}", e)))?;
            let slot = U256::from_str(&entry.slot)
                .map_err(|e| VeraGenesisError::Parse(format!("invalid storage slot: {}", e)))?;
            let value = U256::from_str(&entry.value)
                .map_err(|e| VeraGenesisError::Parse(format!("invalid storage value: {}", e)))?;

            if let Some(existing) = genesis_storage.iter_mut().find(|(a, _)| *a == address) {
                existing.1.push((slot, value));
            } else {
                genesis_storage.push((address, vec![(slot, value)]));
            }
        }

        let participant_addresses: Vec<Address> = self
            .validators
            .iter()
            .map(|v| {
                Address::from_str(&v.evm_address)
                    .expect("validator address already validated above")
            })
            .collect();

        Ok(GenesisState {
            genesis_alloc,
            genesis_storage,
            genesis_code,
            participant_addresses,
        })
    }

    /// Create a default devnet genesis (chain_id=9001, test allocations).
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            operators: None,
            policies: Vec::new(),
            placed_policies: Vec::new(),
            node_demerits: Vec::new(),
            chain_id: 9001,
            timestamp: 0,
            allocations: vec![
                GenesisAllocation {
                    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                    balance: "1000000000000000000000".to_string(), // 1000 ETH
                },
                GenesisAllocation {
                    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
                    balance: "1000000000000000000000".to_string(),
                },
            ],
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_info: None,
            blocks_per_epoch: 20,
            simplex: None,
            timestamp_step_secs: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_parameters_round_trip_without_changing_legacy_encoding() {
        let mut genesis = VeraGenesis::devnet();
        let legacy = serde_json::to_value(&genesis).unwrap();
        assert!(legacy.get("simplex").is_none());
        let decoded: VeraGenesis = serde_json::from_value(legacy).unwrap();
        assert!(decoded.simplex.is_none());
        genesis.simplex = Some(vera_domain::SimplexParameters::default());
        let decoded: VeraGenesis =
            serde_json::from_str(&serde_json::to_string(&genesis).unwrap()).unwrap();
        assert_eq!(decoded.simplex, genesis.simplex);
    }

    #[test]
    fn devnet_genesis_roundtrip() {
        let genesis = VeraGenesis::devnet();
        let json = serde_json::to_string_pretty(&genesis).unwrap();
        let parsed: VeraGenesis = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, 9001);
        assert_eq!(parsed.allocations.len(), 2);
    }

    #[test]
    fn devnet_to_genesis_state() {
        let genesis = VeraGenesis::devnet();
        let state = genesis.to_genesis_state().unwrap();
        assert_eq!(state.genesis_alloc.len(), 2);
        assert!(state.participant_addresses.is_empty());
    }

    #[test]
    fn genesis_load_from_file() {
        let genesis = VeraGenesis::devnet();
        let json = serde_json::to_string_pretty(&genesis).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis.json");
        std::fs::write(&path, &json).unwrap();

        let loaded = VeraGenesis::load(&path).unwrap();
        assert_eq!(loaded.chain_id, genesis.chain_id);
        assert_eq!(loaded.allocations.len(), genesis.allocations.len());
    }

    #[test]
    fn genesis_parse_error_on_invalid_address() {
        let genesis = VeraGenesis {
            operators: None,
            policies: Vec::new(),
            placed_policies: Vec::new(),
            node_demerits: Vec::new(),
            chain_id: 1,
            timestamp: 0,
            allocations: vec![GenesisAllocation {
                address: "not-an-address".to_string(),
                balance: "100".to_string(),
            }],
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_info: None,
            blocks_per_epoch: 20,
            simplex: None,
            timestamp_step_secs: None,
        };
        let err = genesis.to_genesis_state().unwrap_err();
        assert!(err.to_string().contains("invalid address"));
    }

    fn genesis_with_validators(validators: Vec<ValidatorConfig>) -> VeraGenesis {
        VeraGenesis {
            operators: None,
            policies: Vec::new(),
            placed_policies: Vec::new(),
            node_demerits: Vec::new(),
            chain_id: 1,
            timestamp: 0,
            allocations: Vec::new(),
            validators,
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_info: None,
            blocks_per_epoch: 20,
            simplex: None,
            timestamp_step_secs: None,
        }
    }

    #[test]
    fn genesis_rejects_duplicate_validators() {
        let genesis = genesis_with_validators(vec![
            ValidatorConfig {
                evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: "aa".repeat(32),
                p2p_address: "127.0.0.1:30300".to_string(),
            },
            ValidatorConfig {
                evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: "bb".repeat(32),
                p2p_address: "127.0.0.1:30301".to_string(),
            },
        ]);
        let err = genesis.to_genesis_state().unwrap_err();
        assert!(err.to_string().contains("duplicate validator address"));
    }

    #[test]
    fn genesis_rejects_a_consensus_key_shared_by_two_validators() {
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;

        let key = hex::encode(
            commonware_cryptography::ed25519::PrivateKey::from_seed(1)
                .public_key()
                .encode(),
        );
        let genesis = genesis_with_validators(vec![
            ValidatorConfig {
                evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: key.clone(),
                p2p_address: "127.0.0.1:30300".to_string(),
            },
            ValidatorConfig {
                evm_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
                consensus_pubkey: key,
                p2p_address: "127.0.0.1:30301".to_string(),
            },
        ]);
        let err = genesis.to_genesis_state().unwrap_err();
        assert!(err.to_string().contains("duplicate consensus pubkey"));
    }

    #[test]
    fn unknown_keys_are_rejected_at_the_top_level_and_in_allocations() {
        let mut value = serde_json::to_value(VeraGenesis::devnet()).unwrap();
        value["operator"] = serde_json::Value::Null;
        let error = serde_json::from_value::<VeraGenesis>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field `operator`"));

        let mut value = serde_json::to_value(VeraGenesis::devnet()).unwrap();
        value["allocations"][0]["nonce"] = 1.into();
        assert!(serde_json::from_value::<VeraGenesis>(value).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected_in_seeded_records() {
        let seeded = |section: &str, entry: serde_json::Value| {
            let mut value = serde_json::to_value(VeraGenesis::devnet()).unwrap();
            value[section] = serde_json::Value::Array(vec![entry]);
            value
        };
        let policy =
            serde_json::json!({ "definition": "name: seeded", "marshal_type": "ShortYaml" });
        let placed = serde_json::json!({
            "definition": "name: seeded",
            "marshal_type": "ShortYaml",
            "counter": 1,
            "owner": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        });
        let demerit = serde_json::json!({
            "ring_id": "ring",
            "node_key": "node",
            "points": 1,
            "window_started_at": 0,
        });
        for (section, entry, extra) in [
            ("policies", policy, "owner"),
            ("placed_policies", placed, "owners"),
            ("node_demerits", demerit, "window"),
        ] {
            serde_json::from_value::<VeraGenesis>(seeded(section, entry.clone())).unwrap();
            let mut entry = entry;
            entry[extra] = 5.into();
            let error = serde_json::from_value::<VeraGenesis>(seeded(section, entry)).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown field `{extra}`")),
                "{section}: {error}"
            );
        }
    }

    #[test]
    fn genesis_rejects_invalid_p2p_address() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "aa".repeat(32),
            p2p_address: "not-a-socket-addr".to_string(),
        }]);
        let err = genesis.to_genesis_state().unwrap_err();
        assert!(err.to_string().contains("invalid validator p2p address"));
    }

    #[test]
    fn genesis_rejects_malformed_consensus_key() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            consensus_pubkey: "dd".repeat(32),
            p2p_address: "127.0.0.1:30300".into(),
        }]);
        assert!(genesis.to_genesis_state().is_err());
    }

    #[test]
    fn genesis_rejects_zero_consensus_key() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "00".repeat(32),
            p2p_address: "127.0.0.1:30300".to_string(),
        }]);
        let err = genesis.to_genesis_state().unwrap_err();
        assert!(
            err.to_string()
                .contains("consensus pubkey cannot be all zeros")
        );
    }

    #[test]
    fn genesis_sets_precompile_bytecode() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "aa".repeat(32),
            p2p_address: "127.0.0.1:30300".to_string(),
        }]);
        let bootstrap = genesis.to_genesis_state().unwrap();
        assert_eq!(bootstrap.genesis_code.len(), 1);
        assert_eq!(bootstrap.genesis_code[0].0, VALIDATOR_REGISTRY_ADDRESS);
        assert_eq!(bootstrap.genesis_code[0].1, PRECOMPILE_SENTINEL_BYTECODE);
    }

    #[test]
    fn epoch_info_defaults_to_none_and_decodes() {
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;

        let genesis = VeraGenesis::devnet();
        assert_eq!(genesis.blocks_per_epoch, 20);
        assert!(genesis.decode_epoch_info().unwrap().is_none());

        let players = commonware_utils::ordered::Set::from_iter_dedup((0..4).map(|seed| {
            commonware_cryptography::ed25519::PrivateKey::from_seed(seed).public_key()
        }));
        let (output, _) = commonware_cryptography::bls12381::dkg::feldman_desmedt::deal::<
            commonware_cryptography::bls12381::primitives::variant::MinSig,
            _,
            commonware_utils::N3f1,
        >(
            commonware_utils::TestRng::new(1),
            commonware_cryptography::bls12381::primitives::sharing::Mode::NonZeroCounter,
            players.clone(),
        )
        .expect("trusted deal");
        let info = commonware_glue::dkg::types::EpochInfo {
            outcome: commonware_glue::dkg::types::EpochOutcome::Success,
            epoch: commonware_consensus::types::Epoch::new(0),
            output,
            players: players.clone(),
            next_players: players,
            directory: commonware_utils::sequence::Unit,
        };
        let mut genesis = VeraGenesis::devnet();
        genesis.epoch_info = Some(hex::encode(info.encode()));
        let decoded = genesis.decode_epoch_info().unwrap().expect("epoch info");
        assert_eq!(decoded, info);
    }

    #[test]
    fn epoch_info_rejects_invalid_hex() {
        let mut genesis = VeraGenesis::devnet();
        genesis.epoch_info = Some("not-hex".to_string());
        assert!(genesis.decode_epoch_info().is_err());
    }
    #[test]
    fn genesis_timestamp_must_be_nonzero() {
        let mut genesis = VeraGenesis::devnet();
        assert!(genesis.validate_timestamp().is_err());
        genesis.timestamp = 1;
        assert!(genesis.validate_timestamp().is_ok());
    }
}
