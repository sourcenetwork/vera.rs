use alloy_primitives::{B256, Bytes};
use vera_domain::ConsensusPublicKey;
use vera_modules::acp::{keys, types::RegistrationsCommitment};
use vera_permission::{ModuleId, PAGE_PROOF_BYTES, PrefixPageRequest, RECORD_PROOF_BYTES};

use crate::{ClientError, VeraClient};

/// Build commitment material locally without disclosing object identifiers to a server.
/// This does not check policy existence, resource validity or current ownership.
pub fn generate_registration_commitment(
    policy: B256,
    objects: &[vera_modules::acp::types::Object],
    actor: &vera_modules::acp::types::Actor,
) -> Result<vera_modules::acp::types::GenerateCommitmentResult, vera_modules::acp::error::AcpError>
{
    vera_modules::acp::AcpModule::generate_registration_commitment(
        &hex::encode(policy),
        objects,
        actor,
    )
}

/// Certified commitment identifiers at one revision; subsequent pages may select newer state.
#[derive(Clone, Debug)]
pub struct CommitmentIdPage {
    /// Finalized revision authenticating this page.
    pub revision: u64,
    /// Matching identifiers in ascending order.
    pub ids: Vec<u64>,
    /// Inclusive start for the next page.
    pub continuation: Option<Bytes>,
}

/// A registration commitment or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct CommitmentRecord {
    /// Finalized revision authenticating the selected record.
    pub revision: u64,
    /// Execution timestamp of the selected revision.
    pub timestamp: u64,
    /// Stored commitment, including its issuance metadata and expiry status.
    pub value: Option<RegistrationsCommitment>,
}

impl VeraClient {
    /// Read a commitment with certified absence and explicit policy/identifier binding.
    /// Presence does not establish that the commitment remains usable for a reveal.
    pub async fn read_registration_commitment(
        &self,
        policy: B256,
        id: u64,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<CommitmentRecord, ClientError> {
        if id == 0 {
            return Err(ClientError::InvalidResponse(
                "invalid commitment identifier",
            ));
        }
        let response = self
            .read_current_record(
                ModuleId::Acp,
                &keys::commitment_key(id),
                minimum,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode_commitment(bytes, policy, id))
            .transpose()?;
        Ok(CommitmentRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }

    /// Discover commitment IDs matching a root without scanning unrelated history.
    pub async fn read_registration_commitment_ids(
        &self,
        root: B256,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<CommitmentIdPage, ClientError> {
        let prefix = Bytes::from(keys::commitment_by_commitment_index_prefix(root.as_slice()));
        let request = PrefixPageRequest {
            module: ModuleId::Acp,
            start: cursor.unwrap_or_else(|| prefix.clone()),
            prefix,
            limit,
        };
        let (response, page) = self
            .verified_prefix_page(&request, minimum, trusted, PAGE_PROOF_BYTES)
            .await?;
        let ids = page
            .entries
            .iter()
            .map(|entry| decode_id(&request.prefix, &entry.key, &entry.value))
            .collect::<Result<_, _>>()?;
        Ok(CommitmentIdPage {
            revision: response.revision.height,
            ids,
            continuation: page.continuation,
        })
    }
}

fn decode_commitment(
    bytes: &[u8],
    policy: B256,
    id: u64,
) -> Result<RegistrationsCommitment, ClientError> {
    let record: RegistrationsCommitment = borsh::from_slice(bytes)
        .map_err(|_| ClientError::InvalidResponse("invalid registration commitment encoding"))?;
    if id == 0
        || record.id != id
        || record.policy_id != hex::encode(policy)
        || record.commitment.len() != 32
    {
        return Err(ClientError::InvalidResponse(
            "registration commitment differs from selection",
        ));
    }
    Ok(record)
}

fn decode_id(prefix: &[u8], key: &[u8], value: &[u8]) -> Result<u64, ClientError> {
    if !key.starts_with(prefix) || key.len() != prefix.len() + 8 || !value.is_empty() {
        return Err(ClientError::InvalidResponse(
            "invalid commitment root index",
        ));
    }
    let id = u64::from_be_bytes(
        key[prefix.len()..]
            .try_into()
            .map_err(|_| ClientError::InvalidResponse("invalid commitment identifier"))?,
    );
    if id == 0 {
        return Err(ClientError::InvalidResponse(
            "invalid commitment identifier",
        ));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commitment_id_decoding_binds_root_and_shape() {
        let root = [9; 32];
        let prefix = keys::commitment_by_commitment_index_prefix(&root);
        let key = keys::commitment_by_commitment_index_key(&root, 7);
        assert_eq!(decode_id(&prefix, &key, &[]).unwrap(), 7);
        assert!(decode_id(&prefix, &key, &[0]).is_err());
        assert!(decode_id(&prefix, &key[..key.len() - 1], &[]).is_err());
        assert!(
            decode_id(
                &prefix,
                &keys::commitment_by_commitment_index_key(&[8; 32], 7),
                &[]
            )
            .is_err()
        );
        assert!(
            decode_id(
                &prefix,
                &keys::commitment_by_commitment_index_key(&root, 0),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn commitment_record_binds_selection_and_rejects_malformed_bytes() {
        use vera_modules::{
            acp::types::RecordMetadata,
            types::{Duration, Timestamp},
        };
        let policy = B256::repeat_byte(7);
        let mut record = RegistrationsCommitment {
            id: 1,
            policy_id: hex::encode(policy),
            commitment: vec![9; 32],
            expired: true,
            validity: Duration::Seconds(600),
            metadata: RecordMetadata {
                creation_ts: Timestamp {
                    seconds: 10,
                    block_height: 2,
                },
                tx_hash: vec![3; 32],
                tx_signer: "worker".into(),
                owner_did: "owner".into(),
            },
        };
        let bytes = borsh::to_vec(&record).unwrap();
        assert_eq!(decode_commitment(&bytes, policy, 1).unwrap(), record);
        assert!(decode_commitment(&bytes, B256::ZERO, 1).is_err());
        assert!(decode_commitment(&bytes, policy, 2).is_err());
        assert!(decode_commitment(&bytes, policy, 0).is_err());
        assert!(decode_commitment(&bytes[..bytes.len() - 1], policy, 1).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_commitment(&trailing, policy, 1).is_err());
        record.commitment.pop();
        assert!(decode_commitment(&borsh::to_vec(&record).unwrap(), policy, 1).is_err());
    }
}
