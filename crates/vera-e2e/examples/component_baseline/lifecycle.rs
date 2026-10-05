//! Policy mutation costs; fixtures and invariant checks run outside measurement.

use acp::{Relationship, Subject};
use identity::Did;
use vera_modules::{
    acp::{
        AcpModule, keys,
        types::{
            AccessRequest, Actor, AmendmentEvent, Object, Operation, PolicyCmd, PolicyCmdResult,
            PolicyMarshalingType, PolicyRecord, RegistrationsCommitment, RelationshipRecord,
        },
    },
    kv_store::InMemoryKvStore,
    types::{BlockExecCtx, Timestamp, TxExecCtx},
};

const POLICY: &str = "name: lifecycle
resources:
  - name: file
    relations:
      - name: reader
        types: [actor]
      - name: admin
        types: [group->member]
        manages: [reader, owner]
    permissions:
      - name: read
        expr: reader
  - name: group
    relations:
      - name: member
        types: [actor]
";
const EDITED: &str = "name: lifecycle
resources:
  - name: file
    relations:
      - name: admin
        types: [actor]
        manages: [owner]
    permissions:
      - name: read
        expr: owner
  - name: group
";

type Registration = (RegistrationsCommitment, AmendmentEvent);

struct Fixture {
    module: AcpModule,
    policy: String,
    creator: Did,
    reader: Did,
    registrations: Vec<Registration>,
    unrelated: Vec<(Vec<u8>, Vec<u8>)>,
}

const fn revision(height: u64) -> Timestamp {
    Timestamp {
        seconds: 100 + height,
        block_height: height,
    }
}

fn command(
    module: &mut AcpModule,
    actor: &Did,
    policy: &str,
    command: PolicyCmd,
    height: u64,
) -> PolicyCmdResult {
    let encoded = serde_json::to_vec(&(policy, actor.as_str(), &command, height)).unwrap();
    module
        .execute_policy_cmd(
            actor,
            policy,
            command,
            &BlockExecCtx {
                timestamp: revision(height),
                ..Default::default()
            },
            &TxExecCtx {
                sequence: 0,
                tx_hash: alloy_primitives::keccak256(encoded).to_vec(),
                signer: actor.to_string(),
            },
        )
        .unwrap()
}

fn populate(
    module: &mut AcpModule,
    policy: &str,
    objects: usize,
    creator: &Did,
    claimant: &Did,
    reader: &Did,
) -> Vec<Registration> {
    if objects == 0 {
        return Vec::new();
    }
    command(
        module,
        claimant,
        policy,
        PolicyCmd::RegisterObject(Object {
            resource: "group".into(),
            id: "members".into(),
        }),
        2,
    );
    command(
        module,
        claimant,
        policy,
        PolicyCmd::SetRelationship(Relationship::with_entity(
            "group",
            "members",
            "member",
            reader.clone(),
        )),
        2,
    );
    (0..objects)
        .map(|index| {
            let object = Object {
                resource: "file".into(),
                id: index.to_string(),
            };
            let generated = module
                .query_generate_commitment(
                    policy,
                    std::slice::from_ref(&object),
                    &Actor(claimant.clone()),
                )
                .unwrap();
            let PolicyCmdResult::CommitRegistrations {
                registrations_commitment,
            } = command(
                module,
                claimant,
                policy,
                PolicyCmd::CommitRegistrations {
                    commitment: generated.commitment,
                },
                2,
            )
            else {
                panic!("expected commitment");
            };
            command(
                module,
                creator,
                policy,
                PolicyCmd::RegisterObject(object.clone()),
                3,
            );
            let PolicyCmdResult::RevealRegistration {
                event: Some(event), ..
            } = command(
                module,
                claimant,
                policy,
                PolicyCmd::RevealRegistration {
                    registrations_commitment_id: registrations_commitment.id,
                    proof: generated.proofs[0].clone(),
                },
                4,
            )
            else {
                panic!("expected ownership amendment");
            };
            for relationship in [
                Relationship::with_entity("file", &object.id, "reader", reader.clone()),
                Relationship::new(
                    "file",
                    &object.id,
                    "admin",
                    Subject::entity_set("group", "members", "member"),
                ),
            ] {
                command(
                    module,
                    claimant,
                    policy,
                    PolicyCmd::SetRelationship(relationship),
                    5,
                );
            }
            (registrations_commitment, event)
        })
        .collect()
}

impl Fixture {
    fn new(objects: usize, unrelated: usize) -> Self {
        let creator = Did::new("did:key:lifecycle-creator").unwrap();
        let claimant = Did::new("did:key:lifecycle-claimant").unwrap();
        let reader = Did::new("did:key:lifecycle-reader").unwrap();
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(&creator, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        let registrations = populate(&mut module, &policy, objects, &creator, &claimant, &reader);
        let before_unrelated = module.clone();
        let other = module
            .create_policy(&creator, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        populate(&mut module, &other, unrelated, &creator, &claimant, &reader);
        let unrelated = module
            .store()
            .diff_from(before_unrelated.store())
            .into_iter()
            .map(|(key, value)| (key, value.expect("fixture only adds records")))
            .collect();
        Self {
            module,
            policy,
            creator,
            reader,
            registrations,
            unrelated,
        }
    }

    fn edit(&self, module: &mut AcpModule) -> (u64, PolicyRecord) {
        module
            .edit_policy_at(
                &self.creator,
                &self.policy,
                EDITED,
                PolicyMarshalingType::ShortYaml,
                &revision(6),
            )
            .unwrap()
    }

    fn delete(&self, module: &mut AcpModule) -> bool {
        let deleted = module.delete_policy(&self.creator, &self.policy).unwrap();
        // Include physical cleanup so this metric retains its full-teardown scope.
        while module.policy_cleanup_pending(&self.policy).unwrap() {
            module
                .end_blocker(&BlockExecCtx {
                    timestamp: revision(6),
                    ..Default::default()
                })
                .unwrap();
        }
        deleted
    }

    fn restore_and_check_unrelated(&self, module: &AcpModule) -> AcpModule {
        for (key, value) in &self.unrelated {
            assert_eq!(module.store().get_ref(key), Some(value.as_slice()));
        }
        let bytes = module.store().serialize();
        let restored = AcpModule::from_store(InMemoryKvStore::deserialize(&bytes).unwrap());
        restored.validate_restored_state().unwrap();
        assert_eq!(restored.store().serialize(), bytes);
        restored
    }

    fn verify(&self) {
        self.module.validate_restored_state().unwrap();
        let before = self.module.store().serialize();
        let prefix = keys::relationship_policy_prefix(&self.policy);
        let count = self.registrations.len();
        assert_eq!(
            self.module.store().prefix_iter(&prefix).count(),
            3 * count + 2
        );
        let request = AccessRequest {
            actor: Actor(self.reader.clone()),
            operations: vec![Operation {
                object: Object {
                    resource: "file".into(),
                    id: "0".into(),
                },
                permission: "read".into(),
            }],
        };
        assert!(
            self.module
                .query_verify_access_request(&self.policy, &request)
                .unwrap()
        );
        let mut edited = self.module.clone();
        let (removed, record) = self.edit(&mut edited);
        assert_eq!(removed, (2 * count + 1) as u64);
        assert_eq!(record.policy.id, self.policy);
        assert_eq!(record.last_modified, Some(revision(6)));
        // Logical edits retire generations; physical rows remain until bounded cleanup.
        assert_eq!(edited.store().prefix_iter(&prefix).count(), 3 * count + 2);
        let mut current_owners = 0;
        for (key, bytes) in edited.store().prefix_iter(&prefix) {
            assert_eq!(self.module.store().get_ref(key), Some(bytes));
            let relationship: RelationshipRecord = serde_json::from_slice(bytes).unwrap();
            if record
                .relations
                .pair(&relationship.relationship)
                .is_ok_and(|pair| pair == relationship.generations)
            {
                assert_eq!(relationship.relationship.relation, "owner");
                current_owners += 1;
            }
        }
        assert_eq!(current_owners, count + 1);
        for (commitment, event) in &self.registrations {
            assert_eq!(
                edited
                    .query_registrations_commitment(commitment.id)
                    .unwrap(),
                *commitment
            );
            assert_eq!(
                edited.get_amendment_event_by_id(event.id).unwrap().as_ref(),
                Some(event)
            );
        }
        let mut edited = self.restore_and_check_unrelated(&edited);
        assert!(
            !edited
                .query_verify_access_request(&self.policy, &request)
                .unwrap()
        );
        assert_eq!(
            edited
                .edit_policy_at(
                    &self.creator,
                    &self.policy,
                    POLICY,
                    PolicyMarshalingType::ShortYaml,
                    &revision(7),
                )
                .unwrap()
                .0,
            0
        );
        let edited = self.restore_and_check_unrelated(&edited);
        assert!(
            !edited
                .query_verify_access_request(&self.policy, &request)
                .unwrap()
        );
        assert_eq!(edited.store().prefix_iter(&prefix).count(), 3 * count + 2);

        let mut deleted = self.module.clone();
        assert!(self.delete(&mut deleted));
        let mut deleted = self.restore_and_check_unrelated(&deleted);
        assert!(deleted.query_policy(&self.policy).is_err());
        assert_eq!(deleted.store().prefix_iter(&prefix).count(), 0);
        for (commitment, event) in &self.registrations {
            assert!(
                deleted
                    .query_registrations_commitment(commitment.id)
                    .is_err()
            );
            assert!(
                deleted
                    .query_registrations_commitment_by_commitment(&commitment.commitment)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                deleted
                    .get_amendment_event_by_id(event.id)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(!self.delete(&mut deleted));
        assert_eq!(self.module.store().serialize(), before);
    }
}

pub(super) fn run() {
    for (objects, unrelated, edit, delete) in [
        (32, 0, "acp_policy_edit_32", "acp_policy_delete_32"),
        (256, 0, "acp_policy_edit_256", "acp_policy_delete_256"),
        (2048, 0, "acp_policy_edit_2048", "acp_policy_delete_2048"),
        (
            32,
            2048,
            "acp_policy_edit_32_unrelated_2048",
            "acp_policy_delete_32_unrelated_2048",
        ),
    ] {
        let fixture = Fixture::new(objects, unrelated);
        fixture.verify();
        super::measure_prepared(
            edit,
            || fixture.module.clone(),
            |module| fixture.edit(module),
        );
        super::measure_prepared(
            delete,
            || fixture.module.clone(),
            |module| fixture.delete(module),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_fixture_preserves_isolation_and_restoration() {
        Fixture::new(129, 129).verify();
    }
}
