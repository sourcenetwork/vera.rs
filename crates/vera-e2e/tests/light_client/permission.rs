use super::{broadcast_evm_tx, parse_policy_id};
use alloy_sol_types::SolCall;
use commonware_codec::{Decode as _, Encode as _};
use vera_client::{
    ACP_ADDRESS, AccessRequest, Actor, EvmSigner, Object, Operation, PERMISSION_LIMITS,
    PermissionProof, PermissionRead, PermissionResponse, VeraClient, verify_permission_proof,
};
use vera_domain::{ConsensusPublicKey, verify_light_block};
use vera_e2e::cluster::TestCluster;
use vera_modules::acp::{
    abi::IAcp,
    keys, relationship_index,
    types::{PolicyRecord, RelationPair},
};

pub(super) const READER_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

pub(super) async fn check_permissions(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &EvmSigner,
    policy: &str,
    minimum_height: u64,
    trusted: &ConsensusPublicKey,
) {
    let request = request();
    let response = evidence(client, policy, &request, minimum_height).await;
    assert!(
        response
            .verify(policy, &request, minimum_height, trusted, PERMISSION_LIMITS)
            .unwrap()
    );
    let revision = &response.revision;
    let (_, root) = verify_light_block(revision, trusted).unwrap();
    let proof = response.proof;
    for index in 0..proof.reads.len() {
        let mut missing = proof.clone();
        missing.reads.remove(index);
        assert!(
            verify_permission_proof(
                root,
                revision.height,
                policy,
                &request,
                &missing,
                PERMISSION_LIMITS
            )
            .is_err()
        );
    }
    let mut wrong_request = request.clone();
    wrong_request.actor = Actor(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap(),
    );
    assert!(!matches!(
        verify_permission_proof(
            root,
            revision.height,
            policy,
            &wrong_request,
            &proof,
            PERMISSION_LIMITS
        ),
        Ok(true)
    ));
    let mut duplicate = proof.clone();
    duplicate.reads.push(proof.reads[0].clone());
    assert!(
        verify_permission_proof(
            root,
            revision.height,
            policy,
            &request,
            &duplicate,
            PERMISSION_LIMITS
        )
        .is_err()
    );
    let mut limits = PERMISSION_LIMITS;
    limits.proof_bytes = 1;
    assert!(
        verify_permission_proof(root, revision.height, policy, &request, &proof, limits).is_err()
    );
    limits = PERMISSION_LIMITS;
    limits.reads.reads = 1;
    assert!(
        verify_permission_proof(root, revision.height, policy, &request, &proof, limits).is_err()
    );

    let register = IAcp::registerObjectCall {
        policyId: parse_policy_id(policy),
        resource: "document".into(),
        objectId: "suspensions".into(),
    }
    .abi_encode();
    assert_eq!(
        broadcast_evm_tx(cluster, client, signer, ACP_ADDRESS, register)
            .await
            .status,
        1
    );

    let edge = IAcp::setRelationshipSubjectCall {
        policyId: parse_policy_id(policy),
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "blocked".into(),
        subjectKind: 3,
        subjectResource: "document".into(),
        subjectObjectId: "suspensions".into(),
        subjectRelation: "blocked".into(),
    }
    .abi_encode();
    assert_eq!(
        broadcast_evm_tx(cluster, client, signer, ACP_ADDRESS, edge)
            .await
            .status,
        1
    );
    let block = IAcp::setRelationshipCall {
        policyId: parse_policy_id(policy),
        resource: "document".into(),
        objectId: "suspensions".into(),
        relation: "blocked".into(),
        actor: READER_DID.into(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(cluster, client, signer, ACP_ADDRESS, block).await;
    assert_eq!(receipt.status, 1);
    let response = evidence(client, policy, &request, receipt.block_number).await;
    assert!(
        !response
            .verify(
                policy,
                &request,
                receipt.block_number,
                trusted,
                PERMISSION_LIMITS
            )
            .unwrap()
    );
    let denied_revision = response.revision;
    let (_, denied_root) = verify_light_block(&denied_revision, trusted).unwrap();
    let mut denied = response.proof;
    let mut owner_request = request.clone();
    owner_request.actor = Actor(signer.did().parse().unwrap());
    assert!(
        client
            .verify_current_access(
                policy,
                &owner_request,
                receipt.block_number,
                trusted,
                PERMISSION_LIMITS
            )
            .await
            .unwrap()
            .1
    );
    assert!(
        verify_permission_proof(
            denied_root,
            denied_revision.height,
            policy,
            &request,
            &proof,
            PERMISSION_LIMITS
        )
        .is_err()
    );
    let blocked_prefix = relation_prefix(&denied, policy, "blocked", Some("blocked"));
    assert_eq!(prefix(&denied, &blocked_prefix).entries.len(), 1);
    remove_prefix_records(&mut denied, &blocked_prefix);
    assert!(
        verify_permission_proof(
            denied_root,
            denied_revision.height,
            policy,
            &request,
            &denied,
            PERMISSION_LIMITS
        )
        .is_err()
    );
}

pub(super) fn request() -> AccessRequest {
    AccessRequest {
        actor: Actor(READER_DID.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "document".into(),
                id: "doc1".into(),
            },
            permission: "read".into(),
        }],
    }
}

pub(super) async fn evidence(
    client: &VeraClient,
    policy: &str,
    request: &AccessRequest,
    minimum: u64,
) -> PermissionResponse {
    client
        .rpc_call_typed(
            "vera_getCurrentPermissionProof",
            serde_json::json!([policy, request, minimum]),
        )
        .await
        .unwrap()
}

fn policy_record(proof: &PermissionProof, policy: &str) -> PolicyRecord {
    let expected = keys::policy_key(policy);
    let value = proof
        .reads
        .iter()
        .find_map(|read| match read {
            PermissionRead::CurrentPoint { key, value, .. } if key.as_ref() == expected => {
                value.as_ref()
            }
            _ => None,
        })
        .expect("policy from verified permission evidence");
    serde_json::from_slice(value).unwrap()
}

pub(super) fn relation_prefix(
    proof: &PermissionProof,
    policy: &str,
    relation: &str,
    subject_relation: Option<&str>,
) -> String {
    let record = policy_record(proof, policy);
    let pair = RelationPair {
        target: record.relations.generation("document", relation).unwrap(),
        subject: subject_relation
            .map(|name| record.relations.generation("document", name).unwrap())
            .unwrap_or(0),
    };
    String::from_utf8(keys::relationship_generation_prefix(
        policy,
        pair,
        &keys::relation_prefix("document", "doc1", relation),
    ))
    .unwrap()
}

pub(super) fn assert_absent_relation_directory(
    proof: &PermissionProof,
    policy: &str,
    relation: &str,
) {
    let record = policy_record(proof, policy);
    let generation = record.relations.generation("document", relation).unwrap();
    let expected = relationship_index::active_key(policy, generation);
    assert!(proof.reads.iter().any(|read| matches!(
        read,
        PermissionRead::CurrentPoint { key, value: None, .. } if key.as_ref() == expected
    )));
}

pub(super) fn prefix(
    proof: &PermissionProof,
    expected: &str,
) -> vera_permission::current::PrefixEvidence {
    let bytes = proof
        .reads
        .iter()
        .find_map(|read| match read {
            PermissionRead::CurrentPrefix { prefix, proof }
                if prefix.as_ref() == expected.as_bytes() =>
            {
                Some(proof)
            }
            _ => None,
        })
        .expect("complete native relation evidence");
    vera_permission::current::PrefixEvidence::decode_cfg(
        commonware_codec::Copying(bytes.as_ref()),
        &PERMISSION_LIMITS.reads.records,
    )
    .unwrap()
}

pub(super) fn remove_prefix_records(proof: &mut PermissionProof, expected: &str) {
    let mut evidence = prefix(proof, expected);
    evidence.entries.clear();
    for read in &mut proof.reads {
        if let PermissionRead::CurrentPrefix { prefix, proof } = read
            && prefix.as_ref() == expected.as_bytes()
        {
            *proof = evidence.encode().into();
            return;
        }
    }
    panic!("missing native relation evidence");
}
