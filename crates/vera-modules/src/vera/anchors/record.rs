//! The latest anchor of one deployment, as stored and as proven to readers.

use alloy_primitives::{B256, Bytes};
use commonware_codec::{DecodeExt as _, Encode as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use vera_domain::ConsensusPublicKey;

use super::AnchorError;

const DEPLOYMENT_NAMESPACE: &[u8] = b"vera/anchor/deployment/v1\0";
const KEY_PREFIX: &[u8] = b"anchor/v1/";
/// Longest stored anchor record, in bytes.
pub const MAX_ANCHOR_RECORD_BYTES: usize = 1024;

/// The identifier of the deployment whose blocks verify against `key`.
#[must_use]
pub fn deployment_id(key: &ConsensusPublicKey) -> B256 {
    let mut hash = Sha256::new();
    hash.update(DEPLOYMENT_NAMESPACE);
    hash.update(key.encode());
    B256::from_slice(&hash.finalize())
}

/// Decode a deployment's consensus key from its canonical encoding.
pub fn decode_consensus_key(bytes: &[u8]) -> Result<ConsensusPublicKey, AnchorError> {
    ConsensusPublicKey::decode(commonware_codec::Copying(bytes))
        .map_err(|_| AnchorError::InvalidConsensusKey)
}

/// Storage key of a deployment's latest anchor in the identity partition.
#[must_use]
pub fn anchor_key(deployment: &B256) -> Vec<u8> {
    [KEY_PREFIX, hex::encode(deployment).as_bytes()].concat()
}

/// The newest finalized revision of a deployment recorded in this deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorRecord {
    /// [`deployment_id`] of `consensus_key`.
    pub deployment: B256,
    /// Canonical encoding of the deployment's consensus key.
    pub consensus_key: Bytes,
    /// Number of anchors this deployment has recorded, this one included.
    pub sequence: u64,
    /// Height of the anchored revision.
    pub height: u64,
    /// Identifier of the anchored block.
    pub block_hash: B256,
    /// Term of the anchored block.
    pub term: u64,
    /// Timestamp of the anchored block.
    pub timestamp: u64,
    /// Native module state root of the anchored block.
    pub module_state_root: B256,
    /// Height of the revision of this deployment that recorded the anchor.
    pub anchored_at: u64,
}

impl AnchorRecord {
    /// Decode a stored record and check it belongs to `deployment`.
    pub fn decode(deployment: &B256, bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > MAX_ANCHOR_RECORD_BYTES {
            return Err(AnchorError::MalformedRecord);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| AnchorError::MalformedRecord)?;
        let key = decode_consensus_key(&record.consensus_key)
            .map_err(|_| AnchorError::MalformedRecord)?;
        if record.deployment != *deployment
            || deployment_id(&key) != *deployment
            || record.sequence == 0
        {
            return Err(AnchorError::MalformedRecord);
        }
        Ok(record)
    }

    /// The deployment's consensus key.
    pub fn consensus_key(&self) -> Result<ConsensusPublicKey, AnchorError> {
        decode_consensus_key(&self.consensus_key)
    }

    /// Canonical stored encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("anchor records serialize")
    }
}
