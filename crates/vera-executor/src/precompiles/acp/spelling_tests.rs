//! Calls that name a secp256k1 actor in another spelling report its canonical DID.

use alloy_sol_types::SolEvent;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::SigningKey;

use super::*;
use vera_modules::acp::types::{PolicyCmdResult, RelationshipRecord};
use vera_modules::types::Timestamp;

const POLICY: &str = "name: files
actor:
  relations:
    - name: member
resources:
  - name: file
    relations:
      - name: reader
";

/// The canonical DID of a key and its uncompressed Base64URL spelling.
fn spellings(seed: u8) -> (String, String) {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let key = key.verifying_key();
    let mut bytes = vec![0xe7, 0x01];
    bytes.extend_from_slice(key.to_encoded_point(false).as_bytes());
    (
        vera_crypto::secp256k1::did_from_secp256k1_pubkey(key.to_encoded_point(true).as_bytes())
            .unwrap(),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes)),
    )
}

struct Fixture {
    acp: AcpModule,
    policy: B256,
    tx: TxExecCtx,
}

impl Fixture {
    fn new() -> Self {
        let tx = TxExecCtx {
            signer: "did:key:owner".into(),
            tx_hash: vec![1; 32],
            sequence: 0,
        };
        let owner = did_from_signer(&tx.signer).unwrap();
        let mut acp = AcpModule::new();
        let policy = acp
            .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        acp.direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::RegisterObject(Object {
                resource: "file".into(),
                id: "report".into(),
            }),
        )
        .unwrap();
        let policy = B256::from_slice(&hex::decode(policy).unwrap());
        Self { acp, policy, tx }
    }

    fn call<C: SolCall, E: SolEvent>(&mut self, call: C) -> (C::Return, E) {
        let block = BlockExecCtx {
            timestamp: Timestamp {
                seconds: 10,
                block_height: 1,
            },
            ..Default::default()
        };
        let output = dispatch(
            &mut self.acp,
            &mut VeraModule::new(),
            &block,
            &self.tx,
            &call.abi_encode(),
            1_000_000,
        )
        .unwrap();
        assert!(
            !output.precompile.status.is_revert(),
            "{}",
            String::from_utf8_lossy(&output.precompile.bytes)
        );
        assert_eq!(output.logs.len(), 1);
        (
            C::abi_decode_returns(&output.precompile.bytes).unwrap(),
            E::decode_log(&output.logs[0]).unwrap().data,
        )
    }
}

#[test]
fn relationship_events_and_results_name_the_canonical_actor() {
    let (canonical, written) = spellings(2);
    let mut fixture = Fixture::new();
    let policy = fixture.policy;
    let (set, event): (_, IAcp::RelationshipSet) = fixture.call(IAcp::setRelationshipCall {
        policyId: policy,
        resource: "file".into(),
        objectId: "report".into(),
        relation: "reader".into(),
        actor: written.clone(),
    });
    assert_eq!(event.actor, canonical);
    let record: RelationshipRecord = serde_json::from_slice(&set.record).unwrap();
    assert_eq!(
        record.relationship.subject,
        vera_acp::Subject::entity(did_from_actor(&canonical).unwrap())
    );

    let (found, event): (_, IAcp::RelationshipDeleted) =
        fixture.call(IAcp::deleteRelationshipCall {
            policyId: policy,
            resource: "file".into(),
            objectId: "report".into(),
            relation: "reader".into(),
            actor: written,
        });
    assert!(found);
    assert_eq!(event.actor, canonical);
}

#[test]
fn subject_events_name_canonical_actor_objects() {
    let (member, written_member) = spellings(2);
    let (group, written_group) = spellings(3);
    let mut fixture = Fixture::new();
    let policy = fixture.policy;
    let membership = |object: &str, subject: &str| IAcp::setRelationshipSubjectCall {
        policyId: policy,
        resource: "actor".into(),
        objectId: object.into(),
        relation: "member".into(),
        subjectKind: 0,
        subjectResource: String::new(),
        subjectObjectId: subject.into(),
        subjectRelation: String::new(),
    };
    let (set, event): (_, IAcp::RelationshipSubjectSet) =
        fixture.call(membership(&written_group, &written_member));
    assert!(!set.recordExisted);
    assert_eq!(event.objectId, group);
    assert_eq!(event.subjectObjectId, member);
    let (set, _): (_, IAcp::RelationshipSubjectSet) = fixture.call(membership(&group, &member));
    assert!(set.recordExisted);

    let edge = |object: &str| IAcp::setRelationshipSubjectCall {
        policyId: policy,
        resource: "file".into(),
        objectId: "report".into(),
        relation: "reader".into(),
        subjectKind: 2,
        subjectResource: "actor".into(),
        subjectObjectId: object.into(),
        subjectRelation: String::new(),
    };
    let (_, event): (_, IAcp::RelationshipSubjectSet) = fixture.call(edge(&written_group));
    assert_eq!(event.objectId, "report");
    assert_eq!(event.subjectObjectId, group);

    let call = membership(&written_group, &written_member);
    let (found, event): (_, IAcp::RelationshipSubjectDeleted) =
        fixture.call(IAcp::deleteRelationshipSubjectCall {
            policyId: call.policyId,
            resource: call.resource,
            objectId: call.objectId,
            relation: call.relation,
            subjectKind: call.subjectKind,
            subjectResource: call.subjectResource,
            subjectObjectId: call.subjectObjectId,
            subjectRelation: call.subjectRelation,
        });
    assert!(found);
    assert_eq!(event.objectId, group);
    assert_eq!(event.subjectObjectId, member);
}

#[test]
fn a_transfer_event_names_the_canonical_new_owner() {
    let (canonical, written) = spellings(2);
    let mut fixture = Fixture::new();
    let (record, event): (_, IAcp::ObjectTransferred) = fixture.call(IAcp::transferObjectCall {
        policyId: fixture.policy,
        resource: "file".into(),
        objectId: "report".into(),
        newOwner: written,
    });
    assert_eq!(event.newOwner, canonical);
    let PolicyCmdResult::TransferObject { record } = serde_json::from_slice(&record).unwrap()
    else {
        panic!("a transfer returns its owner record");
    };
    assert_eq!(record.metadata.owner_did, canonical);
}
