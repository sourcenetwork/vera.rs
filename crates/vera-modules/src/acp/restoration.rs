use super::*;

impl AcpModule {
    /// Validate retained ACP records before publishing native recovery state.
    pub fn validate_restored_state(&self) -> Result<()> {
        if self
            .store
            .prefix_iter(b"relationship/")
            .any(|(key, _)| !key.starts_with(keys::RELATIONSHIP_PREFIX))
        {
            return Err(AcpError::State(
                "unsupported relationship namespace; fresh deployment required".into(),
            ));
        }
        let retired_count = self.validate_retirement_state()?;
        for (key, _) in self.store.prefix_iter(keys::POLICY_PREFIX) {
            let id = std::str::from_utf8(&key[keys::POLICY_PREFIX.len()..])
                .map_err(|_| AcpError::State("invalid policy key".into()))?;
            let record = self
                .get_policy_record(id)?
                .ok_or_else(|| AcpError::State("restored policy record is missing".into()))?;
            let mut compiled = Self::compile_policy(
                &record.raw_policy,
                &record.marshal_type,
                0,
                Some(record.policy.specification),
            )
            .map_err(|error| AcpError::State(format!("invalid restored policy: {error}")))?;
            compiled.id = id.to_owned();
            let encode = |policy: &Policy| {
                serde_json::to_vec(policy).map_err(|error| AcpError::State(error.to_string()))
            };
            if encode(&compiled)? != encode(&record.policy)? {
                return Err(AcpError::State(
                    "restored policy differs from its definition".into(),
                ));
            }
        }
        for (key, bytes) in self.store.prefix_iter(keys::RELATIONSHIP_PREFIX) {
            let record: RelationshipRecord = serde_json::from_slice(bytes)
                .map_err(|e| AcpError::State(format!("invalid relationship record: {e}")))?;
            if keys::relationship_key(
                &record.policy_id,
                &keys::relationship_storage_key(&record.relationship),
            ) != key
                || !self
                    .retained_policy_allows(&record.policy_id, retirement::Phase::Relationships)?
            {
                return Err(AcpError::State(
                    "relationship key or policy mismatch; legacy keys require explicit migration"
                        .into(),
                ));
            }
        }
        for (key, _) in self.store.prefix_iter(keys::ACCESS_DECISION_PREFIX) {
            let id = std::str::from_utf8(&key[keys::ACCESS_DECISION_PREFIX.len()..])
                .map_err(|_| AcpError::State("invalid access decision key".into()))?;
            self.get_access_decision(id)?;
        }
        self.get_params()?;
        self.validate_counter(
            keys::POLICY_COUNTER_KEY,
            (self.zanzibar_policies.len() as u64)
                .checked_add(retired_count)
                .ok_or_else(|| AcpError::State("policy count overflow".into()))?,
        )?;
        for (prefix, counter_key) in [
            (
                [keys::COMMITMENT_PREFIX, keys::OBJS_SUBPREFIX].concat(),
                keys::commitment_counter_key(),
            ),
            (
                Self::amendment_event_objs_prefix(),
                keys::amendment_event_counter_key(),
            ),
        ] {
            let mut maximum = 0;
            for (key, _) in self.store.prefix_iter(&prefix) {
                let id =
                    u64::from_be_bytes(key[prefix.len()..].try_into().map_err(|_| {
                        AcpError::State("invalid indexed record identifier".into())
                    })?);
                if id == 0 {
                    return Err(AcpError::State("zero indexed record identifier".into()));
                }
                maximum = maximum.max(id);
            }
            self.validate_counter(&counter_key, maximum)?;
        }
        self.validate_amendment_indexes()?;
        self.validate_record_indexes()
    }

    fn validate_counter(&self, key: &[u8], minimum: u64) -> Result<()> {
        let counter = self
            .store
            .get_ref(key)
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid restored record counter".into()))
            })
            .transpose()?
            .unwrap_or(0);
        if counter < minimum {
            return Err(AcpError::State(
                "restored record counter precedes retained records".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_policy_must_match_its_definition_after_edit() {
        let owner = Did::new("did:key:owner").unwrap();
        let resources = "resources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n      - name: write\n        expr: owner\n";
        for specification in ["", "spec: defra\n"] {
            let mut module = AcpModule::new();
            let record = module
                .create_policy(
                    &owner,
                    &format!("name: original\n{specification}{resources}"),
                    PolicyMarshalingType::ShortYaml,
                )
                .unwrap();
            let id = record.policy.id;
            module
                .edit_policy(
                    &owner,
                    &id,
                    &format!("name: edited\n{resources}"),
                    PolicyMarshalingType::ShortYaml,
                )
                .unwrap();
            let restored = AcpModule::from_store(module.store.clone());
            restored.validate_restored_state().unwrap();
            let record = restored.query_policy(&id).unwrap();
            let mut changed_graph = record.clone();
            changed_graph.policy.resources.clear();
            let mut changed_source = record.clone();
            changed_source.raw_policy = format!("name: another\n{resources}");
            let mut invalid_source = record.clone();
            invalid_source.raw_policy = "not a policy".into();
            let mut unknown_encoding = record;
            unknown_encoding.marshal_type = PolicyMarshalingType::Unknown;
            for invalid in [
                changed_graph,
                changed_source,
                invalid_source,
                unknown_encoding,
            ] {
                let mut store = module.store.clone();
                store.put(
                    &keys::policy_key(&id),
                    serde_json::to_vec(&invalid).unwrap(),
                );
                let restored = AcpModule::from_store(store);
                let before = restored.store.serialize();
                assert!(matches!(
                    restored.validate_restored_state(),
                    Err(AcpError::State(_))
                ));
                assert_eq!(restored.store.serialize(), before);
            }
        }
    }

    fn check_record_indexes(
        module: &AcpModule,
        commitment: &RegistrationsCommitment,
        event: &AmendmentEvent,
    ) {
        let root = keys::commitment_by_commitment_index_key(&commitment.commitment, commitment.id);
        let expiry = AcpModule::commitment_expiry_key(commitment);
        let amendment = keys::amendment_event_policy_index_key(&event.policy_id, event.id);
        for key in [
            keys::commitment_key(commitment.id),
            keys::commitment_policy_index_key(&commitment.policy_id, commitment.id),
            root,
            expiry.clone(),
            keys::amendment_event_key(event.id),
            amendment,
        ] {
            for value in [None, Some(vec![0])] {
                let mut store = module.store.clone();
                match value {
                    None => store.delete(&key),
                    Some(bytes) => store.put(&key, bytes),
                }
                assert!(
                    AcpModule::from_store(store)
                        .validate_restored_state()
                        .is_err(),
                    "{key:?}"
                );
            }
        }
        for key in [
            keys::commitment_policy_index_key("wrong", commitment.id),
            keys::commitment_policy_index_key(&commitment.policy_id, 99),
            keys::commitment_policy_index_key(&commitment.policy_id, 0),
            {
                let mut key =
                    keys::commitment_policy_index_key(&commitment.policy_id, commitment.id);
                key.push(0);
                key
            },
            keys::commitment_by_commitment_index_key(&[8; 32], commitment.id),
            keys::commitment_by_commitment_index_key(&commitment.commitment, 99),
            keys::amendment_event_policy_index_key("wrong", event.id),
            keys::amendment_event_policy_index_key(&event.policy_id, 99),
            {
                let mut key = expiry.clone();
                key.push(0);
                key
            },
        ] {
            let mut store = module.store.clone();
            store.put(&key, vec![]);
            assert!(
                AcpModule::from_store(store)
                    .validate_restored_state()
                    .is_err()
            );
        }
        let mut expired = AcpModule::from_store(module.store.clone());
        let mut record = commitment.clone();
        record.expired = true;
        expired.update_commitment(&record).unwrap();
        expired.validate_restored_state().unwrap();
        expired.store.put(&expiry, vec![]);
        assert!(expired.validate_restored_state().is_err());
        for bad in [
            {
                let mut r = commitment.clone();
                r.id += 1;
                r
            },
            {
                let mut r = commitment.clone();
                r.commitment.pop();
                r
            },
        ] {
            let mut restored = AcpModule::from_store(module.store.clone());
            restored.store.put(
                &keys::commitment_key(commitment.id),
                borsh::to_vec(&bad).unwrap(),
            );
            assert!(
                restored
                    .query_registrations_commitment(commitment.id)
                    .is_err()
            );
            assert!(restored.validate_restored_state().is_err());
        }
    }

    #[test]
    fn stale_counters_cannot_reuse_retained_identifiers() {
        let mut module = AcpModule::new();
        let actor = Did::new("did:key:owner").unwrap();
        let definition = "name: counter\nresources:\n  - name: file\n";
        let policy = module
            .create_policy(&actor, definition, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        let PolicyCmdResult::CommitRegistrations {
            registrations_commitment: mut commitment,
        } = module
            .direct_policy_cmd(
                &actor,
                &policy,
                PolicyCmd::CommitRegistrations {
                    commitment: vec![7; 32],
                },
            )
            .unwrap()
        else {
            panic!("expected commitment")
        };
        let mut event = AmendmentEvent {
            id: 0,
            policy_id: policy,
            object: Object {
                resource: "file".into(),
                id: "report".into(),
            },
            new_owner: Actor(actor.clone()),
            previous_owner: Actor(Did::new("did:key:previous").unwrap()),
            commitment_id: commitment.id,
            hijack_flag: false,
            metadata: commitment.metadata.clone(),
        };
        module.create_amendment_event(&mut event).unwrap();
        module.validate_restored_state().unwrap();
        check_record_indexes(&module, &commitment, &event);
        let original = module.store.clone();
        for key in [
            keys::POLICY_COUNTER_KEY.to_vec(),
            keys::commitment_counter_key(),
            keys::amendment_event_counter_key(),
        ] {
            for invalid in [None, Some(vec![0; 8]), Some(vec![1; 7])] {
                let mut store = original.clone();
                match invalid {
                    None => store.delete(&key),
                    Some(bytes) => store.put(&key, bytes),
                }
                assert!(
                    AcpModule::from_store(store)
                        .validate_restored_state()
                        .is_err()
                );
            }
            module.store.delete(&key);
        }
        let before = module.store.serialize();
        assert!(
            module
                .create_policy(&actor, definition, PolicyMarshalingType::ShortYaml)
                .is_err()
        );
        assert_eq!(module.store.serialize(), before);
        assert!(module.create_commitment(&mut commitment).is_err());
        assert_eq!(module.store.serialize(), before);
        assert!(module.create_amendment_event(&mut event).is_err());
        assert_eq!(module.store.serialize(), before);
    }

    #[test]
    fn restoration_rejects_invalid_policy_relationship_decision_and_parameter_records() {
        let mut module = AcpModule::new();
        let owner = Did::new("did:key:owner").unwrap();
        let policy = module
            .create_policy(
                &owner,
                "name: restored\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: "report".into(),
                }),
            )
            .unwrap();
        let original = module.store.clone();
        let owner_relation = Relationship::with_entity("file", "report", "owner", owner.clone());
        let canonical =
            keys::relationship_key(&policy, &keys::relationship_storage_key(&owner_relation));
        let legacy = keys::relationship_key(&policy, &owner_relation.storage_key());
        let mut legacy_store = original.clone();
        legacy_store.put(&legacy, legacy_store.get(&canonical).unwrap());
        legacy_store.delete(&canonical);
        assert!(
            AcpModule::from_store(legacy_store)
                .validate_restored_state()
                .is_err()
        );
        AcpModule::from_store(original.clone())
            .validate_restored_state()
            .unwrap();
        let policy_key = keys::policy_key(&policy);
        let owner_key = keys::relationship_key(
            &policy,
            &keys::relationship_storage_key(&Relationship::with_entity(
                "file", "report", "owner", owner,
            )),
        );
        for key in [&policy_key, &owner_key] {
            let bytes = original.get(key).unwrap();
            for length in 0..bytes.len() {
                let mut store = original.clone();
                store.put(key, bytes[..length].to_vec());
                assert!(
                    AcpModule::from_store(store)
                        .validate_restored_state()
                        .is_err()
                );
            }
            let mut store = original.clone();
            let mut alias = key.to_vec();
            alias.push(b'x');
            store.put(&alias, bytes);
            assert!(
                AcpModule::from_store(store)
                    .validate_restored_state()
                    .is_err()
            );
        }
        let mut orphan = original.clone();
        orphan.delete(&policy_key);
        assert!(
            AcpModule::from_store(orphan)
                .validate_restored_state()
                .is_err()
        );
        for key in [
            keys::PARAMS_KEY.to_vec(),
            keys::access_decision_key("invalid"),
        ] {
            let mut store = original.clone();
            store.put(&key, vec![0]);
            assert!(
                AcpModule::from_store(store)
                    .validate_restored_state()
                    .is_err()
            );
        }
        AcpModule::new().validate_restored_state().unwrap();
    }
}
