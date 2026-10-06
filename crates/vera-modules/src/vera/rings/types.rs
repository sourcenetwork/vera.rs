#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{Result, invalid};

pub const MAX_RING_REQUEST_BYTES: usize = 48 * 1024;
pub const MAX_RING_RECORD_BYTES: usize = 128 * 1024;
pub const MAX_RING_MEMBERS: usize = 256;

/// Creation parameters retained independently of subsequent ring state.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingConfig {
    pub policy_id: String,
    pub peer_node_keys: Vec<String>,
    pub threshold: u32,
    pub pss_interval: u64,
    pub current_version: u64,
    pub requires_pet: bool,
    pub nonce: [u8; 32],
    /// None permanently disables relays; Some allows a bounded canonical set.
    pub trusted_auth_relay_dids: Option<Vec<String>>,
    pub reporting: ReportingConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingConfig {
    pub node_offline_demerits: u64,
    pub invalid_crypto_response_demerits: u64,
    pub unauthorized_request_demerits: u64,
    pub reset_interval_seconds: u64,
    pub kick_threshold: u64,
    pub backup_node_keys: Vec<String>,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            node_offline_demerits: 1,
            invalid_crypto_response_demerits: 1,
            unauthorized_request_demerits: 1,
            reset_interval_seconds: 86400,
            kick_threshold: 3,
            backup_node_keys: Vec::new(),
        }
    }
}

impl RingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.policy_id.len() != 64
            || hex::decode(&self.policy_id).is_err()
            || self.policy_id.bytes().any(|b| b.is_ascii_uppercase())
        {
            return Err(invalid("invalid ring policy identifier"));
        }
        keys(&self.peer_node_keys, false)?;
        keys(&self.reporting.backup_node_keys, true)?;
        if self.threshold == 0
            || self.threshold as usize > self.peer_node_keys.len()
            || self.pss_interval < 86400
            || self.reporting.reset_interval_seconds == 0
            || self.reporting.kick_threshold == 0
            || self.reporting.node_offline_demerits == 0
            || self.reporting.invalid_crypto_response_demerits == 0
            || self.reporting.unauthorized_request_demerits == 0
        {
            return Err(invalid(
                "invalid ring threshold, refresh interval or reporting bounds",
            ));
        }
        if let Some(relays) = &self.trusted_auth_relay_dids {
            if relays.len() > MAX_RING_MEMBERS || !sorted(relays) {
                return Err(invalid("relay set must be bounded, sorted and unique"));
            }
            for did in relays {
                if did.len() > 256 {
                    return Err(invalid("relay identity exceeds byte limit"));
                }
                let encoded = did
                    .strip_prefix("did:key:z")
                    .ok_or_else(|| invalid("relay must be an Ed25519 key DID"))?;
                let bytes = bs58::decode(encoded).into_vec().map_err(invalid)?;
                if bytes.len() != 34
                    || !bytes.starts_with(&[0xed, 0x01])
                    || bs58::encode(&bytes).into_string() != encoded
                {
                    return Err(invalid("relay must be a canonical Ed25519 key DID"));
                }
            }
        }
        Ok(())
    }

    /// Bind the immutable identity to the deployment, creator and all creation parameters.
    pub fn id(&self, deployment_root: [u8; 32], creator: &str) -> Result<String> {
        self.validate()?;
        identity::Did::new(creator).map_err(invalid)?;
        let bytes = borsh::to_vec(&(deployment_root, creator, self)).map_err(invalid)?;
        if bytes.len() > MAX_RING_REQUEST_BYTES {
            return Err(invalid("ring configuration exceeds byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"vera/orbis/ring/v2\0");
        hash.update(bytes);
        Ok(hex::encode(hash.finalize()))
    }
}

/// Public key agreement produced by the configured DKG protocols.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingPublicKeys {
    pub public_key: String,
    pub pet_public_key: Option<String>,
}

impl RingPublicKeys {
    pub fn validate(&self, requires_pet: bool) -> Result<()> {
        public_key_value(&self.public_key)?;
        if self.pet_public_key.is_some() != requires_pet {
            return Err(invalid("public key agreement does not match ring PET mode"));
        }
        if let Some(key) = &self.pet_public_key {
            public_key_value(key)?;
        }
        Ok(())
    }
}

/// Confirmation requires every configured participant, matching the fresh-DKG protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RingState {
    Pending {
        keys: Option<RingPublicKeys>,
        confirmations: Vec<String>,
    },
    Active {
        keys: RingPublicKeys,
    },
    Cancelled {
        by: String,
    },
    Conflict {
        first_keys: RingPublicKeys,
        conflicting_keys: RingPublicKeys,
        by: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingRecord {
    pub id: String,
    pub deployment_root: [u8; 32],
    pub creator: String,
    pub config: RingConfig,
    pub state: RingState,
    pub revision: crate::types::Timestamp,
    /// Absent in initial records; current settings then equal the creation configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<RingSettings>,
    /// Advances on every mutation, including multiple changes in the same revision.
    #[serde(default)]
    pub sequence: u64,
}

impl RingRecord {
    pub fn validate(&self, expected: &str) -> Result<()> {
        if self.id != expected
            || self.config.id(self.deployment_root, &self.creator)? != expected
            || self.revision.block_height == 0
            || self.revision.seconds == 0
        {
            return Err(invalid("ring record identity or revision mismatch"));
        }
        if let Some(settings) = &self.settings {
            settings.validate(self)?;
        }
        match &self.state {
            RingState::Pending {
                keys: declared_keys,
                confirmations,
            } => {
                keys(confirmations, true)?;
                if confirmations.len() >= self.config.peer_node_keys.len()
                    || confirmations
                        .iter()
                        .any(|key| self.config.peer_node_keys.binary_search(key).is_err())
                    || declared_keys.is_some() == confirmations.is_empty()
                {
                    return Err(invalid("invalid pending confirmations"));
                }
                if let Some(keys) = declared_keys {
                    keys.validate(self.config.requires_pet)?;
                }
            }
            RingState::Active { keys } => keys.validate(self.config.requires_pet)?,
            RingState::Cancelled { by } => {
                identity::Did::new(by).map_err(invalid)?;
            }
            RingState::Conflict {
                first_keys,
                conflicting_keys,
                by,
            } => {
                first_keys.validate(self.config.requires_pet)?;
                conflicting_keys.validate(self.config.requires_pet)?;
                if first_keys == conflicting_keys
                    || self.config.peer_node_keys.binary_search(by).is_err()
                {
                    return Err(invalid("invalid conflicting confirmation"));
                }
            }
        }
        Ok(())
    }
}

/// Mutable service configuration; the creation commitment stays unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingSettings {
    pub peer_node_keys: Vec<String>,
    pub threshold: u32,
    pub pss_interval: u64,
    pub current_version: u64,
    pub scheduled_upgrade: Option<ScheduledUpgrade>,
    pub reporting: ReportingConfig,
    pub trusted_auth_relay_dids: Option<Vec<String>>,
    pub pending_reshare: Option<ReshareTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledUpgrade {
    pub version: u64,
    pub activates_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReshareTarget {
    pub peer_node_keys: Vec<String>,
    pub threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RingUpdate {
    SetPssInterval(u64),
    ScheduleUpgrade(ScheduledUpgrade),
    CancelUpgrade,
    SetReporting(ReportingConfig),
    AddRelay(String),
    RemoveRelay(String),
    StartReshare {
        peer_node_keys: Option<Vec<String>>,
        threshold: Option<u32>,
    },
}

impl RingRecord {
    pub fn current_settings(&self) -> RingSettings {
        self.settings.clone().unwrap_or_else(|| RingSettings {
            peer_node_keys: self.config.peer_node_keys.clone(),
            threshold: self.config.threshold,
            pss_interval: self.config.pss_interval,
            current_version: self.config.current_version,
            scheduled_upgrade: None,
            reporting: self.config.reporting.clone(),
            trusted_auth_relay_dids: self.config.trusted_auth_relay_dids.clone(),
            pending_reshare: None,
        })
    }
}

impl RingSettings {
    pub fn effective_version(&self, timestamp: u64) -> u64 {
        self.scheduled_upgrade
            .as_ref()
            .filter(|upgrade| timestamp >= upgrade.activates_at)
            .map_or(self.current_version, |upgrade| upgrade.version)
    }

    pub(super) fn normalize_upgrade(&mut self, timestamp: u64) {
        if self
            .scheduled_upgrade
            .as_ref()
            .is_some_and(|upgrade| timestamp >= upgrade.activates_at)
        {
            self.current_version = self
                .scheduled_upgrade
                .take()
                .expect("matured upgrade")
                .version;
        }
    }

    fn validate(&self, record: &RingRecord) -> Result<()> {
        let mut config = record.config.clone();
        config.peer_node_keys.clone_from(&self.peer_node_keys);
        config.threshold = self.threshold;
        config.pss_interval = self.pss_interval;
        config.current_version = self.current_version;
        config.reporting.clone_from(&self.reporting);
        config
            .trusted_auth_relay_dids
            .clone_from(&self.trusted_auth_relay_dids);
        config.validate()?;
        if self.current_version < record.config.current_version
            || self.trusted_auth_relay_dids.is_some()
                != record.config.trusted_auth_relay_dids.is_some()
        {
            return Err(invalid("ring version or immutable relay setting changed"));
        }
        if self.scheduled_upgrade.as_ref().is_some_and(|upgrade| {
            upgrade.version <= self.current_version || upgrade.activates_at == 0
        }) {
            return Err(invalid("invalid scheduled ring upgrade"));
        }
        if let Some(target) = &self.pending_reshare {
            keys(&target.peer_node_keys, false)?;
            if !matches!(record.state, RingState::Active { .. })
                || target.threshold == 0
                || target.threshold as usize > target.peer_node_keys.len()
                || (target.peer_node_keys == self.peer_node_keys
                    && target.threshold == self.threshold)
            {
                return Err(invalid("invalid pending reshare"));
            }
        }
        if !matches!(record.state, RingState::Active { .. })
            && (self.peer_node_keys != record.config.peer_node_keys
                || self.threshold != record.config.threshold
                || self.pss_interval != record.config.pss_interval
                || self.current_version != record.config.current_version
                || self.scheduled_upgrade.is_some()
                || self.reporting != record.config.reporting)
        {
            return Err(invalid("inactive ring has active service settings"));
        }
        Ok(())
    }
}

/// Commands requiring an actor's delegation and ACP authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RingCommand {
    Create(RingConfig),
    Update {
        ring_id: String,
        expected_sequence: u64,
        update: RingUpdate,
    },
    Cancel {
        ring_id: String,
    },
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RingParticipantCommand {
    Confirm(RingPublicKeys),
    Cancel,
}

/// Participant confirmation, independent of the submission worker's identity and sequence.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingParticipantRequest {
    pub deployment_root: [u8; 32],
    pub deployment_id: u64,
    pub ring_id: String,
    pub node_key: String,
    pub command: RingParticipantCommand,
    pub expires_at: u64,
}

impl RingParticipantRequest {
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let bytes = borsh::to_vec(self).map_err(invalid)?;
        if bytes.len() > MAX_RING_REQUEST_BYTES {
            return Err(invalid("confirmation exceeds byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"vera/orbis/ring-participant/v2\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRingParticipantRequest {
    pub request: RingParticipantRequest,
    pub signature: String,
}

pub(super) fn sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

pub(super) fn keys(values: &[String], empty: bool) -> Result<()> {
    if (!empty && values.is_empty()) || values.len() > MAX_RING_MEMBERS || !sorted(values) {
        return Err(invalid("node set must be bounded, sorted and unique"));
    }
    for key in values {
        super::super::nodes::node_key(key).map_err(invalid)?;
    }
    Ok(())
}

pub(super) fn public_key_value(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 8192
        || hex::decode(value).is_err()
        || value.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(invalid("invalid public key declaration"));
    }
    Ok(())
}
