//! Policies, relationships and objects under each spelling of one key.

use super::*;
use vera_modules::acp::{
    pages::RelationshipPageRequest,
    types::{ObjectSelector, PolicyCmdResult, RelationshipSelector, SubjectSelector},
};

#[test]
fn a_policy_has_one_owner_whichever_spelling_issues_its_tokens() {
    let (key, stranger, worker) = (Key::new(42), Key::new(43), worker(7));
    let mut states = Vec::new();
    for issuer in key.spellings() {
        let (mut acp, mut vera) = (AcpModule::new(), VeraModule::new());
        let created = acp
            .bearer_create_policy(
                &mut vera,
                &context(100),
                &worker,
                &key.token(&issuer, &worker, DelegationScope::CreatePolicy),
                POLICY,
                FORMAT,
            )
            .unwrap();
        assert_eq!(created.metadata.owner_did, key.canonical());
        let policy = created.policy.id;

        for (round, editor) in (1u64..).zip(key.spellings()) {
            let (_, edited) = acp
                .bearer_edit_policy(
                    &mut vera,
                    &context(100 + round),
                    &worker,
                    &key.token(&editor, &worker, DelegationScope::EditPolicy),
                    &policy,
                    &format!("{POLICY}description: revision {round}\n"),
                    FORMAT,
                )
                .unwrap();
            assert_eq!(edited.metadata.owner_did, key.canonical());
        }
        for owner in key.dids() {
            acp.edit_policy(&owner, &policy, POLICY, FORMAT).unwrap();
            acp.edit_policy_metadata(&owner, &policy, Default::default(), &context(110).timestamp)
                .unwrap();
        }

        for other in stranger.spellings() {
            let before = acp.store().serialize();
            let token = stranger.token(&other, &worker, DelegationScope::EditPolicy);
            assert!(
                acp.bearer_edit_policy(
                    &mut vera,
                    &context(120),
                    &worker,
                    &token,
                    &policy,
                    POLICY,
                    FORMAT
                )
                .is_err()
            );
            assert!(
                acp.delete_policy(&Did::new(other).unwrap(), &policy)
                    .is_err()
            );
            assert_eq!(acp.store().serialize(), before);
        }
        states.push(acp.store().serialize());
        assert!(acp.delete_policy(&key.dids()[3], &policy).unwrap());
    }
    assert!(all_equal(&states));
}

#[test]
fn a_grant_under_one_spelling_is_checked_and_revoked_under_any_other() {
    let (owner, grantee, worker) = (Key::new(42), Key::new(43), worker(7));
    let (base, policy) = fixture(&owner);
    let (mut granted, mut revoked) = (Vec::new(), Vec::new());
    for (written, subject) in grantee.dids().into_iter().enumerate() {
        let (mut acp, mut vera) = (base.clone(), VeraModule::new());
        let result = acp
            .bearer_policy_cmd(
                &mut vera,
                &context(100),
                &worker,
                &owner.token(
                    &owner.spellings()[written],
                    &worker,
                    DelegationScope::PolicyCommands,
                ),
                &policy,
                PolicyCmd::SetRelationship(reader(Subject::Entity(subject))),
            )
            .unwrap();
        let PolicyCmdResult::SetRelationship {
            record_existed: false,
            record,
        } = result
        else {
            panic!("the first grant creates the relationship");
        };
        assert_eq!(
            record.relationship.subject,
            Subject::Entity(grantee.dids()[0].clone())
        );
        assert_eq!(record.metadata.owner_did, owner.canonical());
        granted.push(acp.store().serialize());

        for other in grantee.dids() {
            assert!(
                acp.query_verify_access_request(&policy, &read(&other, file("report")))
                    .unwrap()
            );
            let repeated = acp
                .direct_policy_cmd(
                    &owner.dids()[0],
                    &policy,
                    PolicyCmd::SetRelationship(reader(Subject::Entity(other.clone()))),
                )
                .unwrap();
            assert!(matches!(
                repeated,
                PolicyCmdResult::SetRelationship {
                    record_existed: true,
                    ..
                }
            ));
            let found = acp
                .query_filter_relationships(
                    &policy,
                    &RelationshipSelector {
                        object_selector: Some(ObjectSelector::Exact(file("report"))),
                        relation_selector: None,
                        subject_selector: Some(SubjectSelector::Exact(Subject::Entity(other))),
                    },
                )
                .unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].relationship, record.relationship);
        }
        assert_eq!(acp.store().serialize(), granted[written]);

        let revoking = grantee.dids()[(written + 1) % 4].clone();
        let delete = |acp: &mut AcpModule| {
            acp.direct_policy_cmd(
                &owner.dids()[(written + 2) % 4],
                &policy,
                PolicyCmd::DeleteRelationship(reader(Subject::Entity(revoking.clone()))),
            )
            .unwrap()
        };
        assert!(matches!(
            delete(&mut acp),
            PolicyCmdResult::DeleteRelationship { record_found: true }
        ));
        assert!(matches!(
            delete(&mut acp),
            PolicyCmdResult::DeleteRelationship {
                record_found: false
            }
        ));
        for other in grantee.dids() {
            assert!(
                !acp.query_verify_access_request(&policy, &read(&other, file("report")))
                    .unwrap()
            );
        }
        let remaining = acp
            .query_filter_relationships(&policy, &RelationshipSelector::default())
            .unwrap();
        assert_eq!(remaining.len(), 1, "only the owner relationship remains");
        revoked.push(acp.store().serialize());
    }
    assert!(all_equal(&granted));
    assert!(all_equal(&revoked));
}

#[test]
fn an_object_has_one_owner_through_registration_archive_and_transfer() {
    let (owner, heir, worker) = (Key::new(42), Key::new(43), worker(7));
    let (base, policy) = fixture(&owner);
    let object = file("ledger");
    let mut states = Vec::new();
    for written in 0..4 {
        let (mut acp, mut vera) = (base.clone(), VeraModule::new());
        let mut command = |acp: &mut AcpModule, key: &Key, spelling: usize, command: PolicyCmd| {
            let issuer = &key.spellings()[spelling % 4];
            acp.bearer_policy_cmd(
                &mut vera,
                &context(100),
                &worker,
                &key.token(issuer, &worker, DelegationScope::PolicyCommands),
                &policy,
                command,
            )
        };
        let registered = command(
            &mut acp,
            &owner,
            written,
            PolicyCmd::RegisterObject(object.clone()),
        )
        .unwrap();
        let PolicyCmdResult::RegisterObject { record } = registered else {
            panic!("registration returns the owner record");
        };
        assert_eq!(record.metadata.owner_did, owner.canonical());
        assert_eq!(
            record.relationship.subject,
            Subject::Entity(owner.dids()[0].clone())
        );
        assert!(
            command(
                &mut acp,
                &owner,
                written + 1,
                PolicyCmd::RegisterObject(object.clone())
            )
            .is_err(),
            "another spelling cannot register the object again"
        );
        for other in owner.dids() {
            assert!(
                acp.check_management_authority(&other, &policy, &object, "reader")
                    .unwrap()
            );
        }
        command(
            &mut acp,
            &owner,
            written + 1,
            PolicyCmd::ArchiveObject(object.clone()),
        )
        .unwrap();
        assert!(!acp.query_object_owner(&policy, &object).unwrap().0);
        command(
            &mut acp,
            &owner,
            written + 2,
            PolicyCmd::UnarchiveObject(object.clone()),
        )
        .unwrap();
        let transferred = command(
            &mut acp,
            &owner,
            written + 3,
            PolicyCmd::TransferObject {
                object: object.clone(),
                new_owner: Actor(heir.dids()[written].clone()),
            },
        )
        .unwrap();
        let PolicyCmdResult::TransferObject { record } = transferred else {
            panic!("transfer returns the owner record");
        };
        assert_eq!(record.metadata.owner_did, heir.canonical());

        let (registered, current) = acp.query_object_owner(&policy, &object).unwrap();
        assert!(registered);
        assert_eq!(
            current.unwrap().relationship.subject,
            Subject::Entity(heir.dids()[0].clone())
        );
        for (former, current) in owner.dids().into_iter().zip(heir.dids()) {
            assert!(
                !acp.check_management_authority(&former, &policy, &object, "reader")
                    .unwrap()
            );
            assert!(
                acp.check_management_authority(&current, &policy, &object, "reader")
                    .unwrap()
            );
        }
        command(
            &mut acp,
            &heir,
            written + 1,
            PolicyCmd::ArchiveObject(object.clone()),
        )
        .unwrap();
        states.push(acp.store().serialize());
    }
    assert!(all_equal(&states));
}

#[test]
fn direct_calls_record_the_canonical_actor() {
    let (owner, heir, worker) = (Key::new(42), Key::new(43), worker(7));
    let object = file("ledger");
    let mut states = Vec::new();
    for written in 0..4 {
        let mut acp = AcpModule::new();
        let created = acp
            .create_policy(&owner.dids()[written], POLICY, FORMAT)
            .unwrap();
        assert_eq!(created.metadata.owner_did, owner.canonical());
        let policy = created.policy.id;
        let registered = acp
            .execute_policy_cmd(
                &owner.dids()[(written + 1) % 4],
                &policy,
                PolicyCmd::RegisterObject(object.clone()),
                &context(100),
                &worker,
            )
            .unwrap();
        let PolicyCmdResult::RegisterObject { record } = registered else {
            panic!("registration returns the owner record");
        };
        assert_eq!(record.metadata.owner_did, owner.canonical());
        assert_eq!(record.metadata.tx_signer, worker.signer);
        let direct = acp
            .direct_policy_cmd(
                &owner.dids()[(written + 3) % 4],
                &policy,
                PolicyCmd::RegisterObject(file("notes")),
            )
            .unwrap();
        let PolicyCmdResult::RegisterObject { record } = direct else {
            panic!("registration returns the owner record");
        };
        assert_eq!(record.metadata.owner_did, owner.canonical());

        let transferred = acp
            .transfer_object(
                &owner.dids()[(written + 2) % 4],
                &policy,
                &object,
                &heir.dids()[written],
            )
            .unwrap();
        assert_eq!(transferred.metadata.owner_did, heir.canonical());
        let page = acp
            .query_relationships_page(
                &policy,
                &RelationshipPageRequest {
                    selector: RelationshipSelector {
                        object_selector: None,
                        relation_selector: None,
                        subject_selector: Some(SubjectSelector::Exact(Subject::Entity(
                            heir.dids()[(written + 3) % 4].clone(),
                        ))),
                    },
                    after: None,
                },
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].relationship, transferred.relationship);
        states.push(acp.store().serialize());
    }
    assert!(all_equal(&states));
}
