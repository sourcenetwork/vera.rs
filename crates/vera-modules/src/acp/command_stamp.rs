//! Submission metadata a command stamps on the records it creates.

use super::{Did, RecordMetadata, SuppliedMetadata, Timestamp};

/// Empty for context-free commands; contextual commands carry their finalized revision.
#[derive(Clone, Debug, Default)]
pub(super) struct CommandStamp {
    pub(super) creation_ts: Timestamp,
    pub(super) tx_hash: Vec<u8>,
    pub(super) tx_signer: String,
    pub(super) supplied: SuppliedMetadata,
}

impl CommandStamp {
    pub(super) fn metadata(&self, owner: &Did) -> RecordMetadata {
        self.metadata_at(owner, self.creation_ts.clone())
    }

    /// Registration priority may predate the revision that records it.
    pub(super) fn metadata_at(&self, owner: &Did, creation_ts: Timestamp) -> RecordMetadata {
        RecordMetadata {
            creation_ts,
            tx_hash: self.tx_hash.clone(),
            tx_signer: self.tx_signer.clone(),
            owner_did: owner.to_string(),
        }
    }
}
