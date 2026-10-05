//! Policy lookup and discovery from certified native state.

use alloy_primitives::{B256, Bytes};
use vera_domain::ConsensusPublicKey;
use vera_modules::acp::{keys, types::PolicyRecord};
use vera_permission::{
    ModuleId, PAGE_PROOF_BYTES, PAGE_RESPONSE_BYTES, PrefixPageRequest, PrefixPageResponse,
    RECORD_PROOF_BYTES,
};

use crate::{ClientError, VeraClient};

/// Policies at one finalized revision; subsequent pages may select newer state.
#[derive(Clone, Debug)]
pub struct PolicyPage {
    /// Finalized revision authenticating this page.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Policies and their creation metadata in storage-key order.
    pub records: Vec<PolicyRecord>,
    /// Inclusive start of the next page, or the end of the policy prefix.
    pub continuation: Option<Bytes>,
}

/// A policy or certified absence at one finalized revision.
#[derive(Clone, Debug)]
pub struct CertifiedPolicyRecord {
    /// Finalized revision authenticating this record.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Policy definition and creation metadata, if present.
    pub value: Option<PolicyRecord>,
}

impl VeraClient {
    /// Read a policy by ID with certified presence or absence and identity binding.
    pub async fn read_policy(
        &self,
        policy: B256,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<CertifiedPolicyRecord, ClientError> {
        let key = keys::policy_key(&hex::encode(policy));
        let response = self
            .read_current_record(ModuleId::Acp, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode(&key, bytes))
            .transpose()?;
        Ok(CertifiedPolicyRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }

    /// Discover policies using bounded, complete pages authenticated by consensus trust.
    pub async fn read_policy_page(
        &self,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<PolicyPage, ClientError> {
        let prefix = Bytes::from_static(keys::POLICY_PREFIX);
        let request = PrefixPageRequest {
            module: ModuleId::Acp,
            start: cursor.unwrap_or_else(|| prefix.clone()),
            prefix,
            limit,
        };
        request.validate()?;
        let response: PrefixPageResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPrefixPageProof",
                serde_json::json!([request, minimum]),
                PAGE_RESPONSE_BYTES,
            )
            .await?;
        let page = response.verify(&request, minimum, trusted, PAGE_PROOF_BYTES)?;
        let records = page
            .entries
            .iter()
            .map(|entry| decode(&entry.key, &entry.value))
            .collect::<Result<_, _>>()?;
        Ok(PolicyPage {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            records,
            continuation: page.continuation,
        })
    }
}

fn decode(key: &[u8], value: &[u8]) -> Result<PolicyRecord, ClientError> {
    let record: PolicyRecord = serde_json::from_slice(value)?;
    let id = &record.policy.id;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || keys::policy_key(id) != key
    {
        return Err(ClientError::InvalidResponse(
            "policy record differs from selection",
        ));
    }
    record.relations.validate(&record.policy).map_err(|_| {
        ClientError::InvalidResponse("policy relation generations differ from definition")
    })?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vera_modules::acp::{AcpModule, types::PolicyMarshalingType};

    #[test]
    fn policy_records_bind_identity_and_require_complete_json() {
        let mut module = AcpModule::new();
        let mut record = module
            .create_policy(
                &"did:key:owner".parse().unwrap(),
                "name: policy\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        let key = keys::policy_key(&record.policy.id);
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(decode(&key, &bytes).unwrap().policy.id, record.policy.id);
        assert!(decode(&keys::policy_key(&"0".repeat(64)), &bytes).is_err());
        assert!(decode(&key, &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(b'!');
        assert!(decode(&key, &trailing).is_err());
        let mut missing = serde_json::to_value(&record).unwrap();
        missing.as_object_mut().unwrap().remove("relations");
        assert!(decode(&key, &serde_json::to_vec(&missing).unwrap()).is_err());
        let mut invalid = record.clone();
        invalid.relations.next = 0;
        assert!(decode(&key, &serde_json::to_vec(&invalid).unwrap()).is_err());
        record.policy.id = "A".repeat(64);
        assert!(
            decode(
                &keys::policy_key(&record.policy.id),
                &serde_json::to_vec(&record).unwrap()
            )
            .is_err()
        );
    }
}
