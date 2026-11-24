//! The append-only record of every anchor of a deployment.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use super::{AnchorError, AnchorRecord, anchor_key};
use crate::kv_store::ModuleKvStore as _;
use crate::vera::VeraModule;

/// Longest stored history entry, in bytes.
pub const MAX_ANCHOR_ENTRY_BYTES: usize = 640;

/// Prefix of every history entry of `deployment` in the identity partition.
/// Entries follow it in sequence order.
#[must_use]
pub fn anchor_history_prefix(deployment: &B256) -> Vec<u8> {
    [anchor_key(deployment).as_slice(), b"/"].concat()
}

/// Storage key of the history entry of the anchor numbered `sequence`.
#[must_use]
pub fn anchor_entry_key(deployment: &B256, sequence: u64) -> Vec<u8> {
    [
        anchor_history_prefix(deployment).as_slice(),
        format!("{sequence:016x}").as_bytes(),
    ]
    .concat()
}

/// One anchor of a deployment as its history keeps it: an [`AnchorRecord`]
/// without the consensus key, which the deployment's identifier already binds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorEntry {
    /// The deployment's identifier.
    pub deployment: B256,
    /// Position of the anchor among the deployment's anchors; 1 for the first.
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

impl From<&AnchorRecord> for AnchorEntry {
    fn from(record: &AnchorRecord) -> Self {
        Self {
            deployment: record.deployment,
            sequence: record.sequence,
            height: record.height,
            block_hash: record.block_hash,
            term: record.term,
            timestamp: record.timestamp,
            module_state_root: record.module_state_root,
            anchored_at: record.anchored_at,
        }
    }
}

impl AnchorEntry {
    /// Decode the entry stored at `key` and check it is the entry that key names.
    pub fn decode(deployment: &B256, key: &[u8], bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > MAX_ANCHOR_ENTRY_BYTES {
            return Err(AnchorError::MalformedRecord);
        }
        let entry: Self =
            serde_json::from_slice(bytes).map_err(|_| AnchorError::MalformedRecord)?;
        if entry.deployment != *deployment
            || entry.sequence == 0
            || anchor_entry_key(deployment, entry.sequence) != key
        {
            return Err(AnchorError::MalformedRecord);
        }
        Ok(entry)
    }

    /// Canonical stored encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("anchor entries serialize")
    }
}

impl VeraModule {
    /// Append `record` to its deployment's history.
    pub(super) fn append_anchor_entry(&mut self, record: &AnchorRecord) {
        let entry = AnchorEntry::from(record);
        self.store.put(
            &anchor_entry_key(&entry.deployment, entry.sequence),
            entry.encode(),
        );
    }

    /// The anchor of `deployment` numbered `sequence`, if it was recorded.
    pub fn anchor_entry(
        &self,
        deployment: &B256,
        sequence: u64,
    ) -> Result<Option<AnchorEntry>, AnchorError> {
        let key = anchor_entry_key(deployment, sequence);
        self.store
            .get(&key)
            .map(|bytes| AnchorEntry::decode(deployment, &key, &bytes))
            .transpose()
    }
}
