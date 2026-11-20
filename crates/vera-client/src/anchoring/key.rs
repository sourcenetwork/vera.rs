//! A deployment's consensus key as anchors name it.

use alloy_primitives::B256;
use commonware_codec::{DecodeExt as _, Encode as _};
use vera_domain::ConsensusPublicKey;
use vera_modules::vera::anchors::{AnchorError, AnchorRecord};

/// The identifier of the deployment whose blocks verify against `key`.
#[must_use]
pub fn deployment_id(key: &ConsensusPublicKey) -> B256 {
    vera_modules::vera::anchors::deployment_id(&key.encode())
}

/// The consensus key an anchor record names.
pub fn anchored_key(record: &AnchorRecord) -> Result<ConsensusPublicKey, AnchorError> {
    ConsensusPublicKey::decode(commonware_codec::Copying(&record.consensus_key[..]))
        .map_err(|_| AnchorError::MalformedRecord)
}
