//! Vera genesis configuration.

use std::path::Path;

use crate::{VeraGenesisError, validators::registry_members};
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Vera genesis configuration: the deployment's operators, seeded policies,
/// validators and consensus parameters.
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
    /// ACP policies seeded under `vera_modules::acp::GENESIS_POLICY_CREATOR`,
    /// each with its own nonce -- lets a deployment (or test harness) know a
    /// policy's id before genesis exists (`AcpModule::predict_policy_id`),
    /// the same way `operators` is seeded directly rather than through a
    /// live tx.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<vera_modules::acp::PolicySeed>,
    /// ACP policies seeded under owners and nonces the deployment chooses; a
    /// host computes their ids before the deployment exists. Not combined
    /// with `policies`.
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
    /// Genesis members of the validator registry.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Hex-encoded `EpochInfo<MinSig, ed25519::PublicKey, Unit>` for epoch 0
    /// (commonware codec `Encode`d bytes), produced by the bootstrap DKG.
    #[serde(default)]
    pub epoch_info: Option<String>,
    /// Number of blocks in each DKG epoch; omission selects 192.
    #[serde(default = "default_blocks_per_epoch")]
    pub blocks_per_epoch: u64,
    /// Pipelined consensus parameters; omission selects the defaults.
    #[serde(default)]
    pub simplex: vera_domain::SimplexParameters,
    /// Limit, in seconds, on how far a block's timestamp may advance past its
    /// parent's; omission keeps the application default. A deployment that
    /// finalizes less often than the limit, or pauses, falls behind the clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_step_secs: Option<u64>,
}

const fn default_blocks_per_epoch() -> u64 {
    192
}

const fn default_timestamp() -> u64 {
    0
}

/// A genesis member of the validator registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// Registry address identifying the validator (hex with 0x prefix).
    pub address: String,
    /// Ed25519 consensus public key (hex string, 64 chars).
    pub consensus_pubkey: String,
    /// P2P network address (e.g., "127.0.0.1:30300").
    pub p2p_address: String,
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

    /// The validator registry's genesis members: address, consensus key and
    /// network address, validated.
    pub fn registry_members(&self) -> Result<Vec<(Address, [u8; 32], String)>, VeraGenesisError> {
        registry_members(&self.validators)
    }

    /// Check the operator policy and the validator registry's genesis members.
    pub fn validate(&self) -> Result<(), VeraGenesisError> {
        if let Some(policy) = &self.operators {
            policy
                .validate()
                .map_err(|error| VeraGenesisError::Parse(error.to_string()))?;
        }
        self.registry_members().map(drop)
    }

    /// Create a default devnet genesis (chain_id=9001).
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            operators: None,
            policies: Vec::new(),
            placed_policies: Vec::new(),
            node_demerits: Vec::new(),
            chain_id: 9001,
            timestamp: 0,
            validators: Vec::new(),
            epoch_info: None,
            blocks_per_epoch: default_blocks_per_epoch(),
            simplex: vera_domain::SimplexParameters::default(),
            timestamp_step_secs: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_pipeline_parameters_select_the_defaults() {
        let mut genesis = VeraGenesis::devnet();
        let mut encoded = serde_json::to_value(&genesis).unwrap();
        encoded.as_object_mut().unwrap().remove("simplex");
        let decoded: VeraGenesis = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.simplex, vera_domain::SimplexParameters::default());
        genesis.simplex.term_length = 8;
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
    }

    #[test]
    fn genesis_rejects_an_invalid_validator_address() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            address: "not-an-address".to_string(),
            consensus_pubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .to_string(),
            p2p_address: "127.0.0.1:30300".to_string(),
        }]);
        let err = genesis.validate().unwrap_err();
        assert!(err.to_string().contains("invalid validator address"));
    }

    fn genesis_with_validators(validators: Vec<ValidatorConfig>) -> VeraGenesis {
        VeraGenesis {
            operators: None,
            policies: Vec::new(),
            placed_policies: Vec::new(),
            node_demerits: Vec::new(),
            chain_id: 1,
            timestamp: 0,
            validators,
            epoch_info: None,
            blocks_per_epoch: 20,
            simplex: vera_domain::SimplexParameters::default(),
            timestamp_step_secs: None,
        }
    }

    #[test]
    fn genesis_rejects_duplicate_validators() {
        let genesis = genesis_with_validators(vec![
            ValidatorConfig {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: "aa".repeat(32),
                p2p_address: "127.0.0.1:30300".to_string(),
            },
            ValidatorConfig {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: "bb".repeat(32),
                p2p_address: "127.0.0.1:30301".to_string(),
            },
        ]);
        let err = genesis.validate().unwrap_err();
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
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: key.clone(),
                p2p_address: "127.0.0.1:30300".to_string(),
            },
            ValidatorConfig {
                address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
                consensus_pubkey: key,
                p2p_address: "127.0.0.1:30301".to_string(),
            },
        ]);
        let err = genesis.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate consensus pubkey"));
    }

    #[test]
    fn unknown_keys_are_rejected_at_the_top_level_and_account_sections_are_unknown() {
        let mut value = serde_json::to_value(VeraGenesis::devnet()).unwrap();
        value["operator"] = serde_json::Value::Null;
        let error = serde_json::from_value::<VeraGenesis>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field `operator`"));

        for section in ["allocations", "contracts", "extra_storage"] {
            let mut value = serde_json::to_value(VeraGenesis::devnet()).unwrap();
            value[section] = serde_json::json!([]);
            let error = serde_json::from_value::<VeraGenesis>(value).unwrap_err();
            assert!(error.to_string().contains("unknown field"), "{section}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected_in_seeded_records() {
        let seeded = |section: &str, entry: serde_json::Value| {
            let mut value = serde_json::to_value(VeraGenesis::devnet()).unwrap();
            value[section] = serde_json::Value::Array(vec![entry]);
            value
        };
        let nonce = "00".repeat(32);
        let policy = serde_json::json!({
            "definition": "name: seeded",
            "marshal_type": "ShortYaml",
            "nonce": nonce,
        });
        let placed = serde_json::json!({
            "definition": "name: seeded",
            "marshal_type": "ShortYaml",
            "nonce": nonce,
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
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "aa".repeat(32),
            p2p_address: "not-a-socket-addr".to_string(),
        }]);
        let err = genesis.validate().unwrap_err();
        assert!(err.to_string().contains("invalid validator p2p address"));
    }

    #[test]
    fn genesis_rejects_malformed_consensus_key() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            consensus_pubkey: "dd".repeat(32),
            p2p_address: "127.0.0.1:30300".into(),
        }]);
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn genesis_rejects_zero_consensus_key() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "00".repeat(32),
            p2p_address: "127.0.0.1:30300".to_string(),
        }]);
        let err = genesis.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("consensus pubkey cannot be all zeros")
        );
    }

    #[test]
    fn genesis_validators_become_registry_members() {
        let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: key.to_string(),
            p2p_address: "[2001:db8::1]:30300".to_string(),
        }]);
        let members = genesis.registry_members().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(hex::encode(members[0].1), key);
        assert_eq!(members[0].2, "[2001:db8::1]:30300");
    }

    #[test]
    fn epoch_info_defaults_to_none_and_decodes() {
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;

        let genesis = VeraGenesis::devnet();
        assert_eq!(genesis.blocks_per_epoch, 192);
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
