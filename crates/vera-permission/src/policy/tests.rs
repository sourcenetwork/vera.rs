use super::*;
use crate::{
    PAGE_PROOF_BYTES, PolicyPrefixPageProof, PolicyPrefixProof, PrefixPageProof, PrefixPageRequest,
    PrefixProof, RECORD_PROOF_BYTES,
};
use alloy_primitives::Bytes;

fn record(policy: &str) -> RecordProof {
    RecordProof {
        module: ModuleId::Acp,
        key: keys::policy_key(policy).into(),
        value: None,
        roots: [B256::ZERO; 4],
        proof: Bytes::new(),
    }
}

#[test]
fn policy_prefix_requires_canonical_identity_and_current_namespace() {
    let policy = "ab".repeat(32);
    let prefix = keys::relationship_policy_prefix(&policy);
    validate_policy_prefix(&policy, &prefix).unwrap();
    let mut deeper = prefix.clone();
    deeper.extend_from_slice(b"v2/record");
    validate_policy_prefix(&policy, &deeper).unwrap();
    for invalid in [
        String::new(),
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
    ] {
        assert!(validate_policy_prefix(&invalid, &prefix).is_err());
    }
    for invalid in [
        keys::relationship_policy_prefix(&"cd".repeat(32)),
        keys::policy_key(&policy),
        format!("relationship/{policy}/").into_bytes(),
        format!("relationship/v3/{policy}/").into_bytes(),
        prefix[..prefix.len() - 1].to_vec(),
    ] {
        assert!(validate_policy_prefix(&policy, &invalid).is_err());
    }
    deeper.resize(MAX_KEY_BYTES + 1, b'x');
    assert!(matches!(
        validate_policy_prefix(&policy, &deeper),
        Err(PermissionError::Limit)
    ));
}

#[test]
fn complete_policy_prefix_rejects_aggregate_overflow_and_mixed_roots() {
    let policy = "ab".repeat(32);
    let prefix = keys::relationship_policy_prefix(&policy);
    let mut proof = PolicyPrefixProof {
        policy: record(&policy),
        prefix: PrefixProof {
            module: ModuleId::Acp,
            prefix: prefix.clone().into(),
            roots: [B256::ZERO; 4],
            proof: Bytes::new(),
        },
    };
    let individual_limit = serde_json::to_vec(&proof.policy)
        .unwrap()
        .len()
        .max(serde_json::to_vec(&proof.prefix).unwrap().len());
    assert!(matches!(
        proof.verify(B256::ZERO, &policy, &prefix, individual_limit),
        Err(PermissionError::Limit)
    ));
    proof.prefix.roots[0] = B256::repeat_byte(1);
    assert!(matches!(
        proof.verify(B256::ZERO, &policy, &prefix, RECORD_PROOF_BYTES),
        Err(PermissionError::Invalid(
            "policy and relationships have different roots"
        ))
    ));
}

#[test]
fn policy_page_rejects_aggregate_overflow_mixed_roots_and_wrong_module() {
    let policy = "ab".repeat(32);
    let prefix: Bytes = keys::relationship_policy_prefix(&policy).into();
    let mut request = PrefixPageRequest {
        module: ModuleId::Acp,
        start: prefix.clone(),
        prefix,
        limit: 1,
    };
    let mut proof = PolicyPrefixPageProof {
        policy: record(&policy),
        page: PrefixPageProof {
            request: request.clone(),
            roots: [B256::ZERO; 4],
            proof: Bytes::new(),
        },
    };
    let individual_limit = serde_json::to_vec(&proof.policy)
        .unwrap()
        .len()
        .max(serde_json::to_vec(&proof.page).unwrap().len());
    assert!(matches!(
        proof.verify(B256::ZERO, &policy, &request, individual_limit),
        Err(PermissionError::Limit)
    ));
    proof.page.roots[0] = B256::repeat_byte(1);
    assert!(matches!(
        proof.verify(B256::ZERO, &policy, &request, PAGE_PROOF_BYTES),
        Err(PermissionError::Invalid(
            "policy and relationships have different roots"
        ))
    ));
    request.module = ModuleId::Bulletin;
    assert!(matches!(
        proof.verify(B256::ZERO, &policy, &request, PAGE_PROOF_BYTES),
        Err(PermissionError::Invalid(
            "relationships belong to another module"
        ))
    ));
}

#[test]
fn policy_evidence_requires_both_proofs_and_rejects_unknown_fields() {
    let policy = "ab".repeat(32);
    let proof = PolicyPrefixProof {
        policy: record(&policy),
        prefix: PrefixProof {
            module: ModuleId::Acp,
            prefix: keys::relationship_policy_prefix(&policy).into(),
            roots: [B256::ZERO; 4],
            proof: Bytes::new(),
        },
    };
    let encoded = serde_json::to_value(&proof).unwrap();
    assert!(serde_json::from_value::<PolicyPrefixProof>(encoded.clone()).is_ok());
    let mut missing = encoded.clone();
    missing.as_object_mut().unwrap().remove("policy");
    assert!(serde_json::from_value::<PolicyPrefixProof>(missing).is_err());
    let mut unknown = encoded;
    unknown["policy_exists"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PolicyPrefixProof>(unknown).is_err());
}

const GENERATION_POLICY: &str = "\
name: generations
resources:
  - name: file
    relations:
      - name: reader
  - name: group
    relations:
      - name: member
";

fn generation_fixture() -> (
    vera_modules::acp::AcpModule,
    PolicyRecord,
    RelationshipRecord,
) {
    use vera_modules::acp::{AcpModule, types::PolicyMarshalingType};
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(
            &"did:key:owner".parse().unwrap(),
            GENERATION_POLICY,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    let relationship = zanzibar::Relationship::new(
        "file",
        "report",
        "reader",
        zanzibar::Subject::entity_set("group", "staff", "member"),
    );
    let record = RelationshipRecord {
        generations: policy.relations.pair(&relationship).unwrap(),
        supplied_metadata: Default::default(),
        policy_id: policy.policy.id.clone(),
        relationship,
        archived: false,
        metadata: policy.metadata.clone(),
    };
    (module, policy, record)
}

fn relationship_bytes(record: &RelationshipRecord) -> (Vec<u8>, Vec<u8>) {
    (
        keys::relationship_generation_key(
            &record.policy_id,
            record.generations,
            &keys::relationship_storage_key(&record.relationship),
        ),
        serde_json::to_vec(record).unwrap(),
    )
}

#[test]
fn typed_relationships_reject_retired_source_and_userset_generations_after_readdition() {
    use vera_modules::acp::types::PolicyMarshalingType;
    for relation in ["reader", "member"] {
        let (mut module, policy, mut record) = generation_fixture();
        let (key, value) = relationship_bytes(&record);
        assert!(current_relationship(&policy, &key, &value).unwrap());
        let removed =
            GENERATION_POLICY.replace(&format!("    relations:\n      - name: {relation}\n"), "");
        let (_, retired) = module
            .edit_policy(
                &"did:key:owner".parse().unwrap(),
                &policy.policy.id,
                &removed,
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        assert!(!current_relationship(&retired, &key, &value).unwrap());
        let (_, restored) = module
            .edit_policy(
                &"did:key:owner".parse().unwrap(),
                &policy.policy.id,
                GENERATION_POLICY,
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        assert!(!current_relationship(&restored, &key, &value).unwrap());
        record.generations = restored.relations.pair(&record.relationship).unwrap();
        let (fresh_key, fresh_value) = relationship_bytes(&record);
        assert_ne!(fresh_key, key);
        assert!(current_relationship(&restored, &fresh_key, &fresh_value).unwrap());
    }
}

#[test]
fn typed_relationships_bind_the_generation_stamp_and_require_it_in_encoded_rows() {
    let (_, policy, record) = generation_fixture();
    let (key, value) = relationship_bytes(&record);
    assert!(current_relationship(&policy, b"another-key", &value).is_err());
    let mut changed = record.clone();
    changed.generations.target = record.generations.subject;
    let (changed_key, changed_value) = relationship_bytes(&changed);
    assert!(current_relationship(&policy, &key, &changed_value).is_err());
    assert!(current_relationship(&policy, &changed_key, &changed_value).is_err());
    let mut missing = serde_json::to_value(record).unwrap();
    missing.as_object_mut().unwrap().remove("generations");
    assert!(current_relationship(&policy, &key, &serde_json::to_vec(&missing).unwrap()).is_err());
}
