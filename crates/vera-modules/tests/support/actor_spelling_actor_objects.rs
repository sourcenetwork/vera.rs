//! Actors named as objects of the actor resource, and identifiers that are not keys.

use super::*;
use vera_modules::acp::types::{ObjectSelector, PolicyCmdResult, RelationshipSelector};

#[test]
fn an_actor_named_as_an_object_or_an_object_edge_is_one_actor() {
    let (owner, group, member, guest) = (Key::new(42), Key::new(43), Key::new(44), Key::new(45));
    let (base, policy) = fixture(&owner);
    let owner_did = &owner.dids()[0];
    let actor = |did: &Did| Object {
        resource: "actor".into(),
        id: did.to_string(),
    };
    let mut states = Vec::new();
    for written in 0..4 {
        let other = (written + 1) % 4;
        let mut acp = base.clone();
        let mut set = |relationship| {
            acp.direct_policy_cmd(owner_did, &policy, PolicyCmd::SetRelationship(relationship))
                .unwrap()
        };
        set(Relationship::new(
            "actor",
            group.spellings()[written].as_str(),
            "member",
            Subject::Entity(member.dids()[other].clone()),
        ));
        set(reader(Subject::entity_set(
            "actor",
            group.spellings()[other].as_str(),
            "member",
        )));
        set(reader(Subject::entity_set(
            "actor",
            guest.spellings()[written].as_str(),
            "",
        )));

        let stored = acp
            .query_filter_relationships(&policy, &RelationshipSelector::default())
            .unwrap();
        let named = serde_json::to_string(&stored).unwrap();
        for key in [&group, &member, &guest] {
            assert!(named.contains(&key.canonical()));
            for spelling in &key.spellings()[1..] {
                assert!(!named.contains(spelling.as_str()));
            }
        }
        for spelling in 0..4 {
            let role = actor(&group.dids()[(spelling + 1) % 4]);
            assert!(
                acp.check_management_authority(&owner.dids()[spelling], &policy, &role, "member")
                    .unwrap()
            );
            assert!(
                !acp.check_management_authority(&member.dids()[spelling], &policy, &role, "member")
                    .unwrap()
            );
            for reader in [&member.dids()[spelling], &guest.dids()[spelling]] {
                assert!(
                    acp.query_verify_access_request(&policy, &read(reader, file("report")))
                        .unwrap()
                );
            }
            let membership = AccessRequest {
                actor: Actor(member.dids()[spelling].clone()),
                operations: vec![Operation {
                    object: actor(&group.dids()[(spelling + 2) % 4]),
                    permission: "member".into(),
                }],
            };
            assert!(
                acp.query_verify_access_request(&policy, &membership)
                    .unwrap()
            );
            let selected = acp
                .query_filter_relationships(
                    &policy,
                    &RelationshipSelector {
                        object_selector: Some(ObjectSelector::Exact(actor(
                            &group.dids()[spelling],
                        ))),
                        relation_selector: None,
                        subject_selector: None,
                    },
                )
                .unwrap();
            assert_eq!(selected.len(), 1);
        }
        states.push(acp.store().serialize());

        let removed = acp
            .direct_policy_cmd(
                owner_did,
                &policy,
                PolicyCmd::DeleteRelationship(reader(Subject::entity_set(
                    "actor",
                    guest.spellings()[other].as_str(),
                    "",
                ))),
            )
            .unwrap();
        assert!(matches!(
            removed,
            PolicyCmdResult::DeleteRelationship { record_found: true }
        ));
        assert!(
            !acp.query_verify_access_request(&policy, &read(&guest.dids()[0], file("report")))
                .unwrap()
        );
    }
    assert!(all_equal(&states));
}

#[test]
fn identifiers_that_are_not_a_secp256k1_key_are_recorded_as_written() {
    let owner = Key::new(42);
    let (mut acp, policy) = fixture(&owner);
    let written = [
        Subject::Wildcard,
        Subject::Entity(Did::new(format!("did:opk:{}", "ab".repeat(32))).unwrap()),
        Subject::Entity(
            Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
        ),
        Subject::Entity(Did::new("did:key:alice").unwrap()),
        Subject::Entity(Did::new("did:key:uAQID").unwrap()),
        Subject::entity_set("file", owner.spellings()[1].as_str(), ""),
    ];
    for subject in &written {
        acp.direct_policy_cmd(
            &owner.dids()[0],
            &policy,
            PolicyCmd::SetRelationship(Relationship::new(
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
        .filter(|record| record.relationship.relation == "viewer")
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
    assert_eq!(owner_record.relationship.object_id, object.id);
    assert_eq!(owner_record.metadata.owner_did, "did:key:alice");
}
