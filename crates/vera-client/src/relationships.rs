//! Relationship enumeration authenticated by independently configured consensus trust.

use crate::{ClientError, VeraClient};
use alloy_primitives::{B256, Bytes};
use vera_domain::ConsensusPublicKey;
use vera_modules::acp::{keys, types::RelationshipRecord};
use vera_permission::{
    ModuleId, PAGE_PROOF_BYTES, PAGE_RESPONSE_BYTES, PolicyPrefixPageResponse, PrefixPageRequest,
    VerifiedPrefixPage,
};

/// Current generation relationships from a physical page at one finalized revision.
#[derive(Clone, Debug)]
pub struct RelationshipPage {
    /// Finalized revision authenticating this page.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Relationships with archive status and issuance metadata in storage-key order.
    pub records: Vec<RelationshipRecord>,
    /// Inclusive start of the next page; absence marks the end of the policy prefix.
    pub continuation: Option<Bytes>,
}

impl VeraClient {
    /// Enumerate live policy relationships, including archived records, in certified pages.
    /// An absent or retired policy has no current relationships or continuation.
    /// A live policy can return an empty page with a continuation while retired
    /// physical records await cleanup; callers must follow the continuation.
    pub async fn read_relationship_page(
        &self,
        policy: B256,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<RelationshipPage, ClientError> {
        let policy = hex::encode(policy);
        let prefix = Bytes::from(keys::relationship_policy_prefix(&policy));
        let request = PrefixPageRequest {
            module: ModuleId::Acp,
            start: cursor.unwrap_or_else(|| prefix.clone()),
            prefix,
            limit,
        };
        request.validate()?;
        let response: PolicyPrefixPageResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPolicyPrefixPageProof",
                serde_json::json!([policy, request, minimum]),
                PAGE_RESPONSE_BYTES,
            )
            .await?;
        let page = response.verify(&policy, &request, minimum, trusted, PAGE_PROOF_BYTES)?;
        let (records, continuation) = current_relationships(&policy, page)?;
        Ok(RelationshipPage {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            records,
            continuation,
        })
    }
}

fn current_relationships(
    policy: &str,
    page: Option<VerifiedPrefixPage>,
) -> Result<(Vec<RelationshipRecord>, Option<Bytes>), ClientError> {
    let Some(page) = page else {
        return Ok((Vec::new(), None));
    };
    let records = page
        .entries
        .iter()
        .map(|entry| decode(policy, &entry.key, &entry.value))
        .collect::<Result<_, _>>()?;
    Ok((records, page.continuation))
}

fn decode(policy: &str, key: &[u8], value: &[u8]) -> Result<RelationshipRecord, ClientError> {
    let record: RelationshipRecord = serde_json::from_slice(value)?;
    if (record.relationship.relation == "owner" && record.incarnation != 0)
        || record.policy_id != policy
        || keys::relationship_generation_key(
            policy,
            record.generations,
            &keys::relationship_storage_key(&record.relationship, record.incarnation),
        ) != key
    {
        return Err(ClientError::InvalidResponse(
            "relationship record differs from selection",
        ));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vera_modules::acp::{
        AcpModule,
        types::{Object, PolicyCmd, PolicyMarshalingType},
    };

    #[test]
    fn absent_policy_has_no_relationships_or_continuation() {
        let (records, continuation) = current_relationships(&"a".repeat(64), None).unwrap();
        assert!(records.is_empty());
        assert!(continuation.is_none());
    }

    #[test]
    fn empty_current_page_preserves_the_authenticated_physical_continuation() {
        let cursor = Bytes::from_static(b"next physical row");
        let (records, continuation) = current_relationships(
            &"a".repeat(64),
            Some(VerifiedPrefixPage {
                entries: vec![],
                continuation: Some(cursor.clone()),
            }),
        )
        .unwrap();
        assert!(records.is_empty());
        assert_eq!(continuation, Some(cursor));
    }

    #[test]
    fn relationship_record_binds_policy_and_key_and_requires_complete_json() {
        let mut module = AcpModule::new();
        let actor = "did:key:owner".parse().unwrap();
        let policy = module
            .create_policy(
                &actor,
                "name: sample\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        let object = Object {
            resource: "file".into(),
            id: "report".into(),
        };
        module
            .direct_policy_cmd(&actor, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap();
        let record = module
            .query_object_owner(&policy, &object)
            .unwrap()
            .1
            .unwrap();
        let key = keys::relationship_key(
            &policy,
            &keys::relationship_storage_key(&record.relationship, record.incarnation),
        );
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(
            decode(&policy, &key, &bytes).unwrap().relationship,
            record.relationship
        );
        assert!(decode("other", &key, &bytes).is_err());
        assert!(decode(&policy, b"another", &bytes).is_err());
        assert!(decode(&policy, &key, &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(b'!');
        assert!(decode(&policy, &key, &trailing).is_err());
    }
}
