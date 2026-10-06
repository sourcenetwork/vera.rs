//! Native encrypted-document and signing-derivation registration and certified reads.

use crate::{ClientError, ModuleId, RECORD_PROOF_BYTES, VeraClient};
use alloy_primitives::Bytes;
use alloy_sol_types::SolCall as _;
use vera_domain::ConsensusPublicKey;
pub use vera_modules::vera::objects::{
    EncryptedDocument, KeyDerivation, ObjectKind, ObjectRecord, StoredObject, ThresholdObject,
};
use vera_modules::vera::{
    abi::IVera,
    objects::{MAX_OBJECT_RECORD_BYTES, object_key},
};

/// Encode an actor-delegated registration for durable worker submission.
pub fn encode_threshold_object(
    object: &ThresholdObject,
    token: &str,
) -> Result<Bytes, ClientError> {
    object
        .validate()
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    Ok(IVera::storeThresholdObjectCall {
        request: serde_json::to_vec(object)?.into(),
        bearerToken: token.into(),
    }
    .abi_encode()
    .into())
}

/// Certified presence or absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct ObjectRead {
    /// Finalized revision covering this read.
    pub revision: u64,
    /// Finalized revision's Unix timestamp.
    pub timestamp: u64,
    /// Authenticated record, when present.
    pub record: Option<ObjectRecord>,
}

impl VeraClient {
    /// Verify the exact object identity and kind against caller-provisioned consensus trust.
    pub async fn read_threshold_object(
        &self,
        kind: ObjectKind,
        id: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<ObjectRead, ClientError> {
        let key = object_key(kind, id).map_err(|e| ClientError::Signing(e.to_string()))?;
        let response = self
            .read_current_record(ModuleId::Vera, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let record = response
            .record
            .value
            .map(|bytes| {
                if bytes.len() > MAX_OBJECT_RECORD_BYTES {
                    return Err(ClientError::InvalidResponse(
                        "object record exceeds byte limit",
                    ));
                }
                let record: ObjectRecord = serde_json::from_slice(&bytes)?;
                record
                    .validate(kind, id)
                    .map_err(|_| ClientError::InvalidResponse("invalid object record"))?;
                Ok::<_, ClientError>(record)
            })
            .transpose()?;
        Ok(ObjectRead {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            record,
        })
    }
}

#[cfg(test)]
mod tests;
