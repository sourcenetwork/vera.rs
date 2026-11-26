//! Identifiers that are not a secp256k1 key are recorded as written.

use super::*;
use vera_modules::acp::types::RelationshipSelector;

#[test]
fn identifiers_that_are_not_a_secp256k1_key_are_recorded_as_written() {
    let owner = Key::new(42);
    let (mut acp, policy) = fixture(&owner);
    let written = [
        Subject::AllActors,
        vera_modules::acp::relationship_values::actor_subject(
            &Did::new(format!("did:opk:{}", "ab".repeat(32))).unwrap(),
        )
        .unwrap(),
        vera_modules::acp::relationship_values::actor_subject(
            &Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
        )
        .unwrap(),
        vera_modules::acp::relationship_values::actor_subject(&Did::new("did:key:alice").unwrap())
            .unwrap(),
        vera_modules::acp::relationship_values::actor_subject(&Did::new("did:key:uAQID").unwrap())
            .unwrap(),
        vera_modules::acp::relationship_values::object_subject(
            "file",
            owner.spellings()[1].as_str(),
        ),
    ];
    for subject in &written {
        acp.direct_policy_cmd(
            &owner.dids()[0],
            &policy,
            PolicyCmd::SetRelationship(vera_modules::acp::relationship_values::relationship(
                "file",
                "report",
                "viewer",
                subject.clone(),
            )),
        )
        .unwrap();
    }
    let stored: Vec<_> = acp
        .query_filter_relationships(&policy, &RelationshipSelector::default())
        .unwrap()
        .into_iter()
        .filter(|record| record.relationship.relation.as_str() == "viewer")
        .map(|record| record.relationship.subject)
        .collect();
    assert_eq!(stored.len(), written.len());
    for subject in &written {
        assert!(stored.contains(subject), "rewrote {subject:?}");
    }
    let unregistered = Did::new("did:key:alice").unwrap();
    let object = file(owner.spellings()[1].as_str());
    acp.direct_policy_cmd(
        &unregistered,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
    )
    .unwrap();
    let owner_record = acp.query_object_owner(&policy, &object).unwrap().1.unwrap();
    assert_eq!(owner_record.relationship.object.id.as_str(), object.id);
    assert_eq!(owner_record.metadata.owner_did, "did:key:alice");
}
