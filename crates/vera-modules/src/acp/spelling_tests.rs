use k256::ecdsa::SigningKey;
use vera_identity::Did;

use super::super::types::{
    PolicyMarshalingType, RecordMetadata, RegistrationProof, RelationshipRecord,
};
use super::*;
use crate::types::Timestamp;

const DEFINITION: &str = "name: files
resources:
  - name: file
    relations:
      - name: reader
";

/// Compressed then uncompressed Base58BTC spellings of one key.
fn spellings(seed: u8) -> [String; 2] {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    [true, false].map(|compressed| {
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(key.verifying_key().to_encoded_point(compressed).as_bytes());
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    })
}

fn did(spelling: &str) -> Did {
    Did::new(spelling).unwrap()
}

fn module() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(
            &did(&spellings(1)[0]),
            DEFINITION,
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string();
    (module, policy)
}

fn object(resource: &str, id: &str) -> Object {
    Object {
        resource: resource.into(),
        id: id.into(),
    }
}

/// Every command that names an actor, as a caller spelling each one `written`.
fn commands(written: usize) -> Vec<PolicyCmd> {
    let (subject, member) = (&spellings(2)[written], &spellings(3)[written]);
    let relationships = [
        crate::acp::relationship_values::actor_relationship(
            "file",
            "report",
            "reader",
            &did(subject),
        )
        .unwrap(),
        crate::acp::relationship_values::actor_relationship(
            "actor",
            member.as_str(),
            "member",
            &did(subject),
        )
        .unwrap(),
        crate::acp::relationship_values::relationship(
            "file",
            "report",
            "reader",
            crate::acp::relationship_values::actor_set("actor", member.as_str(), "member"),
        ),
        crate::acp::relationship_values::relationship(
            "file",
            "report",
            "reader",
            crate::acp::relationship_values::object_subject("actor", member.as_str()),
        ),
    ];
    let actor = object("actor", member);
    let mut commands: Vec<_> = relationships
        .iter()
        .cloned()
        .map(PolicyCmd::SetRelationship)
        .collect();
    commands.extend(relationships.map(PolicyCmd::DeleteRelationship));
    commands.extend([
        PolicyCmd::TransferObject {
            object: actor.clone(),
            new_owner: Actor(did(subject)),
        },
        PolicyCmd::RegisterObject(actor.clone()),
        PolicyCmd::ArchiveObject(actor.clone()),
        PolicyCmd::UnarchiveObject(actor.clone()),
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: 1,
            proof: RegistrationProof {
                object: actor,
                merkle_proof: Vec::new(),
                leaf_count: 1,
                leaf_index: 0,
            },
        },
    ]);
    commands
}

#[test]
fn every_command_names_its_actors_canonically() {
    for (mut written, canonical) in commands(1).into_iter().zip(commands(0)) {
        let expected = serde_json::to_value(&canonical).unwrap();
        assert_ne!(serde_json::to_value(&written).unwrap(), expected);
        for _ in 0..2 {
            command(&mut written);
            assert_eq!(serde_json::to_value(&written).unwrap(), expected);
        }
    }
}

#[test]
fn identifiers_outside_the_actor_resource_are_not_rewritten() {
    let written = &spellings(2)[1];
    let mut relationship = crate::acp::relationship_values::relationship(
        "file",
        written.as_str(),
        "reader",
        crate::acp::relationship_values::actor_set("file", written.as_str(), "reader"),
    );
    let before = relationship.clone();
    self::relationship(&mut relationship);
    assert_eq!(relationship, before);
    assert!(is_canonical(&relationship));
    assert_eq!(object_id("file", written), written.as_str());
    assert_eq!(object_id("actor", written), spellings(2)[0]);

    let mut query = RelationshipSelector {
        object_selector: Some(ObjectSelector::Exact(object("actor", written))),
        relation_selector: None,
        subject_selector: Some(SubjectSelector::Exact(
            crate::acp::relationship_values::actor_subject(&did(written)).unwrap(),
        )),
    };
    selector(&mut query);
    let query = serde_json::to_string(&query).unwrap();
    assert!(query.contains(&spellings(2)[0]) && !query.contains(written.as_str()));
}

#[test]
fn storage_refuses_a_relationship_that_names_an_actor_in_another_spelling() {
    let (module, policy) = module();
    let record = |relationship: Relationship, owner: &str| RelationshipRecord {
        incarnation: 0,
        generations: module
            .query_policy(&policy)
            .unwrap()
            .relations
            .pair(&relationship)
            .unwrap(),
        supplied_metadata: Default::default(),
        policy_id: policy.clone(),
        relationship,
        archived: false,
        metadata: RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: owner.into(),
        },
    };
    let records = |written: usize| {
        let (owner, actor) = (&spellings(1)[written], &spellings(2)[written]);
        let canonical = &spellings(2)[0];
        [
            record(
                crate::acp::relationship_values::actor_relationship(
                    "file",
                    "report",
                    "reader",
                    &did(actor),
                )
                .unwrap(),
                &spellings(1)[0],
            ),
            record(
                crate::acp::relationship_values::actor_relationship(
                    "file",
                    "notes",
                    "reader",
                    &did(canonical),
                )
                .unwrap(),
                owner,
            ),
        ]
    };
    for (accepted, refused) in records(0).into_iter().zip(records(1)) {
        let mut stored = module.clone();
        assert!(stored.set_relationship(&refused).is_err());
        assert_eq!(stored.store.serialize(), module.store.serialize());
        stored.set_relationship(&accepted).unwrap();
    }
}

#[test]
fn evaluation_meets_every_spelling_at_one_relationship() {
    let (mut module, policy) = module();
    let [canonical, written] = spellings(2);
    let grant = |spelling: &str| {
        crate::acp::relationship_values::actor_relationship(
            "file",
            "report",
            "reader",
            &did(spelling),
        )
        .unwrap()
    };
    let record = RelationshipRecord {
        incarnation: 0,
        generations: module
            .query_policy(&policy)
            .unwrap()
            .relations
            .pair(&grant(&canonical))
            .unwrap(),
        supplied_metadata: Default::default(),
        policy_id: policy.clone(),
        relationship: grant(&canonical),
        archived: false,
        metadata: RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: spellings(1)[0].clone(),
        },
    };
    module.set_relationship(&record).unwrap();
    for spelling in [&canonical, &written] {
        assert!(
            module
                .check_permission(&policy, &object("file", "report"), "reader", &did(spelling))
                .unwrap()
        );
    }
    assert_eq!(
        module
            .recorded_relationship(&policy, grant(&written))
            .unwrap(),
        grant(&canonical)
    );
}
