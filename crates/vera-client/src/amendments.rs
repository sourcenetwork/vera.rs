//! Certified ownership-amendment history and native hijack reports.

use crate::{ClientError, VeraClient};
use alloy_primitives::{B256, Bytes};
use vera_domain::ConsensusPublicKey;
use vera_modules::acp::{keys, types::AmendmentEvent};
use vera_permission::{ModuleId, PAGE_PROOF_BYTES, PrefixPageRequest, RECORD_PROOF_BYTES};

/// Certified amendment identifiers at one revision; subsequent pages may select newer state.
#[derive(Clone, Debug)]
pub struct AmendmentIdPage {
    /// Finalized revision authenticating this page.
    pub revision: u64,
    /// Matching identifiers in ascending order.
    pub ids: Vec<u64>,
    /// Inclusive start for the next page.
    pub continuation: Option<Bytes>,
}

/// An ownership amendment or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct AmendmentRecord {
    /// Finalized revision authenticating the selected record.
    pub revision: u64,
    /// Execution timestamp of the selected revision.
    pub timestamp: u64,
    /// Stored ownership amendment and its reporting flag.
    pub value: Option<AmendmentEvent>,
}

impl VeraClient {
    /// Read an amendment with certified absence and explicit policy/identifier binding.
    /// A reporting flag records an allegation, not an independent finding.
    pub async fn read_amendment(
        &self,
        policy: B256,
        id: u64,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<AmendmentRecord, ClientError> {
        if id == 0 {
            return Err(ClientError::InvalidResponse("invalid amendment identifier"));
        }
        let response = self
            .read_current_record(
                ModuleId::Acp,
                &keys::amendment_event_key(id),
                minimum,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode_amendment(bytes, policy, id))
            .transpose()?;
        Ok(AmendmentRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }

    /// Discover all amendment IDs for one policy, including unflagged events.
    pub async fn read_amendment_ids(
        &self,
        policy: B256,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<AmendmentIdPage, ClientError> {
        let prefix = Bytes::from(keys::amendment_event_policy_index_prefix(&hex::encode(
            policy,
        )));
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
        Ok(AmendmentIdPage {
            revision: response.revision.height,
            ids,
            continuation: page.continuation,
        })
    }
}

fn decode_amendment(bytes: &[u8], policy: B256, id: u64) -> Result<AmendmentEvent, ClientError> {
    let event: AmendmentEvent = borsh::from_slice(bytes)
        .map_err(|_| ClientError::InvalidResponse("invalid amendment encoding"))?;
    if id == 0 || event.id != id || event.policy_id != hex::encode(policy) {
        return Err(ClientError::InvalidResponse(
            "amendment differs from selection",
        ));
    }
    Ok(event)
}

fn decode_id(prefix: &[u8], key: &[u8], value: &[u8]) -> Result<u64, ClientError> {
    if !key.starts_with(prefix) || key.len() != prefix.len() + 8 || !value.is_empty() {
        return Err(ClientError::InvalidResponse(
            "invalid amendment policy index",
        ));
    }
    let id = u64::from_be_bytes(
        key[prefix.len()..]
            .try_into()
            .map_err(|_| ClientError::InvalidResponse("invalid amendment identifier"))?,
    );
    if id == 0 {
        return Err(ClientError::InvalidResponse("invalid amendment identifier"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vera_modules::{
        acp::types::{Actor, Object, RecordMetadata},
        types::Timestamp,
    };

    #[test]
    fn amendment_decoding_binds_policy_identity_and_complete_encoding() {
        let policy = B256::repeat_byte(7);
        let event = AmendmentEvent {
            id: 1,
            policy_id: hex::encode(policy),
            object: Object {
                resource: "file".into(),
                id: "report".into(),
            },
            new_owner: Actor("did:key:new".parse().unwrap()),
            previous_owner: Actor("did:key:old".parse().unwrap()),
            commitment_id: 2,
            hijack_flag: true,
            metadata: RecordMetadata {
                creation_ts: Timestamp::default(),
                tx_hash: vec![],
                tx_signer: "worker".into(),
                owner_did: "did:key:new".into(),
            },
        };
        let bytes = borsh::to_vec(&event).unwrap();
        assert_eq!(decode_amendment(&bytes, policy, 1).unwrap().id, 1);
        assert!(decode_amendment(&bytes, B256::ZERO, 1).is_err());
        assert!(decode_amendment(&bytes, policy, 2).is_err());
        assert!(decode_amendment(&bytes, policy, 0).is_err());
        assert!(decode_amendment(&bytes[..bytes.len() - 1], policy, 1).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_amendment(&trailing, policy, 1).is_err());
        let prefix = keys::amendment_event_policy_index_prefix(&event.policy_id);
        let key = keys::amendment_event_policy_index_key(&event.policy_id, 1);
        assert_eq!(decode_id(&prefix, &key, &[]).unwrap(), 1);
        assert!(decode_id(&prefix, &key, &[0]).is_err());
        assert!(decode_id(&prefix, &key[..key.len() - 1], &[]).is_err());
        assert!(
            decode_id(
                &prefix,
                &keys::amendment_event_policy_index_key("other", 1),
                &[]
            )
            .is_err()
        );
        assert!(
            decode_id(
                &prefix,
                &keys::amendment_event_policy_index_key(&event.policy_id, 0),
                &[]
            )
            .is_err()
        );
    }
}
