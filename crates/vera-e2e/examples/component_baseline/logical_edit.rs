//! Logical edit cost with fixed definitions and growing retained relationship counts.

use acp::Relationship;
use identity::Did;
use vera_modules::{
    acp::{
        AcpModule, keys,
        types::{
            AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType, PolicyRecord,
        },
    },
    kv_store::InMemoryKvStore,
};

const ORIGINAL: &str = "name: logical-edit
resources:
  - name: file
    relations:
      - name: reader
        types: [actor]
    permissions:
      - name: read
        expr: reader
";
const EDITED: &str = "name: logical-edit
resources:
  - name: file
    permissions:
      - name: read
        expr: owner
";

struct Fixture {
    module: AcpModule,
    policy: String,
    owner: Did,
    reader: Did,
    objects: usize,
}

impl Fixture {
    fn new(objects: usize) -> Self {
        let mut module = AcpModule::new();
        let owner = Did::new("did:key:logical-edit-owner").unwrap();
        let reader = Did::new("did:key:logical-edit-reader").unwrap();
        let policy = module
            .create_policy(&owner, ORIGINAL, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        for index in 0..objects {
            let object = Object {
                resource: "file".into(),
                id: index.to_string(),
            };
            module
                .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
                .unwrap();
            module
                .direct_policy_cmd(
                    &owner,
                    &policy,
                    PolicyCmd::SetRelationship(Relationship::with_entity(
                        "file",
                        &object.id,
                        "reader",
                        reader.clone(),
                    )),
                )
                .unwrap();
        }
        Self {
            module,
            policy,
            owner,
            reader,
            objects,
        }
    }

    fn edit(&self, module: &mut AcpModule) -> (u64, PolicyRecord) {
        module
            .edit_policy(
                &self.owner,
                &self.policy,
                EDITED,
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
    }

    fn check_access(&self, module: &AcpModule, expected: bool) {
        for index in 0..self.objects {
            let request = AccessRequest {
                actor: Actor(self.reader.clone()),
                operations: vec![Operation {
                    object: Object {
                        resource: "file".into(),
                        id: index.to_string(),
                    },
                    permission: "read".into(),
                }],
            };
            assert_eq!(
                module
                    .query_verify_access_request(&self.policy, &request)
                    .unwrap(),
                expected
            );
        }
    }

    fn restore(module: &AcpModule) -> AcpModule {
        let bytes = module.store().serialize();
        let restored = AcpModule::from_store(InMemoryKvStore::deserialize(&bytes).unwrap());
        restored.validate_restored_state().unwrap();
        assert_eq!(restored.store().serialize(), bytes);
        restored
    }

    fn verify(&self) {
        self.module.validate_restored_state().unwrap();
        self.check_access(&self.module, true);
        let before = self.module.store().serialize();
        let prefix = keys::relationship_policy_prefix(&self.policy);
        let retained: Vec<_> = self
            .module
            .store()
            .prefix_iter(&prefix)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(retained.len(), 2 * self.objects);
        let mut edited = self.module.clone();
        let (removed, record) = self.edit(&mut edited);
        assert_eq!(removed, self.objects as u64);
        assert_eq!(record.policy.id, self.policy);
        // No end_blocker call: logical revocation must work while old rows remain.
        for (key, value) in &retained {
            assert_eq!(edited.store().get_ref(key), Some(value.as_slice()));
        }
        assert_eq!(edited.store().prefix_iter(&prefix).count(), retained.len());
        let mut edited = Self::restore(&edited);
        self.check_access(&edited, false);
        assert_eq!(
            edited
                .edit_policy(
                    &self.owner,
                    &self.policy,
                    ORIGINAL,
                    PolicyMarshalingType::ShortYaml
                )
                .unwrap()
                .0,
            0
        );
        let edited = Self::restore(&edited);
        self.check_access(&edited, false);
        assert_eq!(edited.store().prefix_iter(&prefix).count(), retained.len());
        assert_eq!(self.module.store().serialize(), before);
    }
}

pub(super) fn run() {
    for (objects, name) in [
        (32, "acp_policy_logical_edit_32"),
        (2048, "acp_policy_logical_edit_2048"),
    ] {
        let fixture = Fixture::new(objects);
        fixture.verify();
        super::measure_prepared(
            name,
            || fixture.module.clone(),
            |module| fixture.edit(module),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_edit_fixture_checks_revocation_without_cleanup() {
        Fixture::new(129).verify();
    }
}
