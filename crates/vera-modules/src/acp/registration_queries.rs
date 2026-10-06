use super::*;

/// Maximum registrations in one generated commitment.
pub const MAX_REGISTRATION_OBJECTS: usize = 256;
/// Maximum aggregate encoded leaf bytes in one generated commitment.
pub const MAX_REGISTRATION_LEAF_BYTES: usize = 64 * 1024;

impl AcpModule {
    /// Generate bounded commitment material without reading policy or registration state.
    /// The caller keeps object identifiers private until submitting a reveal.
    pub fn generate_registration_commitment(
        policy_id: &str,
        objects: &[Object],
        actor: &Actor,
    ) -> Result<GenerateCommitmentResult> {
        Self::validate_commitment_input(policy_id, objects, actor.0.as_str())?;
        let actor_did = actor.0.to_string();

        // Build leaf hashes.
        let leaf_hashes: Vec<[u8; 32]> = objects
            .iter()
            .map(|obj| {
                Self::registration_leaf(policy_id, obj, &actor_did)
                    .map(|data| Self::compute_leaf_hash(&data))
            })
            .collect::<Result<_>>()?;

        let levels = Self::build_merkle_levels(&leaf_hashes);
        let root = levels.last().unwrap()[0];

        let proofs: Vec<RegistrationProof> = objects
            .iter()
            .enumerate()
            .map(|(i, obj)| {
                let siblings = Self::generate_merkle_proof(i, &levels);
                RegistrationProof {
                    object: obj.clone(),
                    merkle_proof: siblings,
                    leaf_count: objects.len() as u64,
                    leaf_index: i as u64,
                }
            })
            .collect();

        let commitment = root.to_vec();
        let commitment_hex = hex::encode(&commitment);

        let proofs_json = proofs
            .iter()
            .map(|p| serde_json::to_string(p).unwrap_or_default())
            .collect();

        Ok(GenerateCommitmentResult {
            commitment,
            commitment_hex,
            proofs,
            proofs_json,
        })
    }
    pub(super) fn validate_commitment_input(
        policy: &str,
        objects: &[Object],
        actor: &str,
    ) -> Result<()> {
        if objects.is_empty() || objects.len() > MAX_REGISTRATION_OBJECTS {
            return Err(AcpError::InvalidAccessRequest {
                reason: "registration object count must be between 1 and 256".into(),
            });
        }
        let base = policy
            .len()
            .saturating_add(actor.len())
            .saturating_add(b"vera/registration-leaf/v1\0".len() + 16);
        let mut bytes = 0usize;
        for object in objects {
            if object.id.is_empty() {
                return Err(AcpError::InvalidAccessRequest {
                    reason: "object ID must not be empty".into(),
                });
            }
            bytes = bytes
                .saturating_add(base)
                .saturating_add(object.resource.len())
                .saturating_add(object.id.len());
            if bytes > MAX_REGISTRATION_LEAF_BYTES {
                return Err(AcpError::InvalidAccessRequest {
                    reason: "registration leaf byte budget exceeded".into(),
                });
            }
        }
        Ok(())
    }

    pub(super) fn registration_owner_record(
        &self,
        policy: &str,
        object: &Object,
    ) -> Result<Option<RelationshipRecord>> {
        self.registration_owner_record_with_budget(policy, object, None)
    }

    pub(super) fn registration_owner_record_with_budget(
        &self,
        policy: &str,
        object: &Object,
        budget: Option<&CommandBudget>,
    ) -> Result<Option<RelationshipRecord>> {
        let prefix = keys::relationship_storage_prefix(
            policy,
            &keys::relation_prefix(&object.resource, &object.id, "owner", 0),
        );
        if let Some(budget) = budget {
            budget.permissions.records.read(&prefix, None)?;
        }
        let mut entries = self.store.prefix_iter(&prefix);
        let Some((key, value)) = entries.next() else {
            return Ok(None);
        };
        if let Some(budget) = budget {
            budget.permissions.records.read(key, Some(value))?;
        }
        if let Some((key, value)) = entries.next() {
            if let Some(budget) = budget {
                budget.permissions.records.read(key, Some(value))?;
            }
            return Err(AcpError::State("multiple object owner records".into()));
        }
        let record: RelationshipRecord = serde_json::from_slice(value)
            .map_err(|error| AcpError::State(format!("invalid object owner record: {error}")))?;
        let acp::Subject::Entity(actor) = &record.relationship.subject else {
            return Err(AcpError::State("object owner must be an actor".into()));
        };
        if record.generations
            != (RelationPair {
                target: 0,
                subject: 0,
            })
            || record.incarnation != 0
            || record.policy_id != policy
            || record.relationship.resource != object.resource
            || record.relationship.object_id != object.id
            || record.relationship.relation != "owner"
            || record.metadata.owner_did != actor.as_str()
            || keys::relationship_storage_prefix(
                policy,
                &keys::relationship_storage_key(&record.relationship, record.incarnation),
            ) != key
        {
            return Err(AcpError::State(
                "object owner record does not match its key".into(),
            ));
        }
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (AcpModule, Did, String, Object) {
        let mut module = AcpModule::new();
        let actor = Did::new("did:key:owner").unwrap();
        let policy = module
            .create_policy(
                &actor,
                "name: bounded\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        (
            module,
            actor,
            policy,
            Object {
                resource: "file".into(),
                id: "report".into(),
            },
        )
    }

    #[test]
    fn generation_enforces_count_and_encoded_leaf_budget() {
        let (module, actor, policy, object) = fixture();
        let objects = vec![object; MAX_REGISTRATION_OBJECTS];
        assert_eq!(
            module
                .query_generate_commitment(&policy, &objects, &Actor(actor.clone()))
                .unwrap()
                .proofs
                .len(),
            MAX_REGISTRATION_OBJECTS
        );
        let mut excessive = objects.clone();
        excessive.push(objects[0].clone());
        assert!(
            module
                .query_generate_commitment(&policy, &excessive, &Actor(actor.clone()))
                .is_err()
        );
        let mut boundary = Object {
            resource: "file".into(),
            id: String::new(),
        };
        let overhead = AcpModule::registration_leaf(&policy, &boundary, actor.as_str())
            .unwrap()
            .len();
        boundary.id = "x".repeat(MAX_REGISTRATION_LEAF_BYTES - overhead);
        assert!(
            module
                .query_generate_commitment(&policy, &[boundary.clone()], &Actor(actor.clone()))
                .is_ok()
        );
        boundary.id.push('x');
        assert!(
            module
                .query_generate_commitment(&policy, &[boundary], &Actor(actor))
                .is_err()
        );
    }

    #[test]
    fn generation_rejects_missing_policies_and_malformed_objects_without_effects() {
        let (mut module, actor, policy, object) = fixture();
        let reserved = module
            .create_policy(
                &actor,
                "name: reserved\nactor:\n  relations:\n    - name: member\n      types: [actor]\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        let before = module.store.serialize();
        for (target, objects, expected) in [
            ("missing-policy", vec![object.clone()], "policy not found"),
            (&policy, Vec::new(), "object count"),
            (
                &policy,
                vec![Object {
                    resource: "file".into(),
                    id: String::new(),
                }],
                "object ID must not be empty",
            ),
            (
                &policy,
                vec![Object {
                    resource: "unknown".into(),
                    id: "report".into(),
                }],
                "not defined in policy",
            ),
            (
                &reserved,
                vec![Object {
                    resource: "actor".into(),
                    id: "member".into(),
                }],
                "cannot be registered as objects",
            ),
        ] {
            let error = module
                .query_generate_commitment(target, &objects, &Actor(actor.clone()))
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{target}: {error}");
            assert_eq!(module.store.serialize(), before);
        }
        for target in [&policy, &reserved] {
            assert!(
                module
                    .query_generate_commitment(
                        target,
                        std::slice::from_ref(&object),
                        &Actor(actor.clone())
                    )
                    .is_ok()
            );
        }
        assert_eq!(module.store.serialize(), before);
    }

    #[test]
    fn owner_queries_reject_corrupt_mismatched_and_duplicate_records() {
        let (mut module, actor, policy, object) = fixture();
        let PolicyCmdResult::RegisterObject { record } = module
            .direct_policy_cmd(&actor, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap()
        else {
            panic!("expected registration")
        };
        let key = keys::relationship_storage_prefix(
            &policy,
            &keys::relationship_storage_key(&record.relationship, record.incarnation),
        );
        let original = module.store.serialize();
        for case in 0..4 {
            module.store = InMemoryKvStore::deserialize(&original).unwrap();
            let mut malformed = record.clone();
            match case {
                0 => module.store.put(&key, vec![0]),
                1 => {
                    malformed.metadata.owner_did = "did:key:other".into();
                    module
                        .store
                        .put(&key, serde_json::to_vec(&malformed).unwrap());
                }
                2 => {
                    malformed.policy_id = "other-policy".into();
                    module
                        .store
                        .put(&key, serde_json::to_vec(&malformed).unwrap());
                }
                _ => {
                    let other = Relationship::with_entity(
                        "file",
                        "report",
                        "owner",
                        Did::new("did:key:other").unwrap(),
                    );
                    module.store.put(
                        &keys::relationship_key(
                            &policy,
                            &keys::relationship_storage_key(&other, 0),
                        ),
                        serde_json::to_vec(&record).unwrap(),
                    );
                }
            }
            let before = module.store.serialize();
            assert!(module.query_object_owner(&policy, &object).is_err());
            assert!(
                module
                    .direct_policy_cmd(&actor, &policy, PolicyCmd::UnarchiveObject(object.clone()))
                    .is_err()
            );
            assert_eq!(module.store.serialize(), before);
        }
    }

    #[test]
    fn malformed_parameters_cannot_fall_back_to_default_commitment_lifetime() {
        let (mut module, actor, policy, _) = fixture();
        assert_eq!(module.query_params().unwrap(), AcpParams::default());
        let valid = borsh::to_vec(&AcpParams::default()).unwrap();
        for length in 0..valid.len() {
            module.store.put(keys::PARAMS_KEY, valid[..length].to_vec());
            let before = module.store.serialize();
            assert!(module.query_params().is_err());
            assert!(
                module
                    .direct_policy_cmd(
                        &actor,
                        &policy,
                        PolicyCmd::CommitRegistrations {
                            commitment: vec![1; 32]
                        }
                    )
                    .is_err()
            );
            assert_eq!(module.store.serialize(), before);
        }
        let mut trailing = valid;
        trailing.push(0);
        module.store.put(keys::PARAMS_KEY, trailing);
        assert!(module.query_params().is_err());
    }
}
