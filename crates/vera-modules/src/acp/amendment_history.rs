use super::*;

const MAX_EVENTS: usize = 128;
const MAX_BYTES: usize = 1 << 20;

fn decode(bytes: &[u8], id: u64) -> Result<AmendmentEvent> {
    let event: AmendmentEvent = borsh::from_slice(bytes)
        .map_err(|e| AcpError::State(format!("invalid amendment event: {e}")))?;
    if id == 0 || event.id != id {
        return Err(AcpError::State("amendment event identity mismatch".into()));
    }
    Ok(event)
}

impl AcpModule {
    /// Read an amendment by its global identifier, validating the stored identity.
    pub fn get_amendment_event_by_id(&self, id: u64) -> Result<Option<AmendmentEvent>> {
        self.get_amendment_event_by_id_with_budget(id, &CommandBudget::new(u64::MAX))
    }

    /// Reserve amendment and policy-liveness reads before decoding command state.
    pub fn get_amendment_event_by_id_with_budget(
        &self,
        id: u64,
        budget: &CommandBudget,
    ) -> Result<Option<AmendmentEvent>> {
        budget.finish(self.amendment_for_command(id, budget))
    }

    fn amendment_for_command(
        &self,
        id: u64,
        budget: &CommandBudget,
    ) -> Result<Option<AmendmentEvent>> {
        let key = keys::amendment_event_key(id);
        budget
            .permissions
            .records
            .read(&key, self.store.get_ref(&key))?;
        let Some(record) = self.retained_amendment_by_id(id)? else {
            return Ok(None);
        };
        let policy_key = keys::policy_key(&record.policy_id);
        budget
            .permissions
            .records
            .read(&policy_key, self.store.get_ref(&policy_key))?;
        if self.get_policy_record(&record.policy_id)?.is_none() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    pub(super) fn retained_amendment_by_id(&self, id: u64) -> Result<Option<AmendmentEvent>> {
        self.store
            .get_ref(&keys::amendment_event_key(id))
            .map(|bytes| decode(bytes, id))
            .transpose()
    }

    /// Reject restored amendments without their matching policy index.
    pub fn validate_amendment_indexes(&self) -> Result<()> {
        let prefix = Self::amendment_event_objs_prefix();
        for (key, bytes) in self.store.prefix_iter(&prefix) {
            let id = key
                .strip_prefix(prefix.as_slice())
                .and_then(|suffix| suffix.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or_else(|| AcpError::State("invalid amendment event key".into()))?;
            let event = decode(bytes, id)?;
            if self.store.get_ref(&keys::amendment_event_policy_index_key(
                &event.policy_id,
                id,
            )) != Some(&[])
            {
                return Err(AcpError::State(
                    "amendment policy index missing or corrupt; explicit migration required".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn list_hijack_events_by_policy(&self, policy: &str) -> Result<Vec<AmendmentEvent>> {
        if policy.len() > 64 << 10 {
            return Err(AcpError::InvalidAccessRequest {
                reason: "policy identifier exceeds lookup limit".into(),
            });
        }
        let prefix = keys::amendment_event_policy_index_prefix(policy);
        let mut events = Vec::new();
        let mut bytes = 0usize;
        for (count, (index, value)) in self
            .store
            .prefix_iter(&prefix)
            .take(MAX_EVENTS + 1)
            .enumerate()
        {
            if count == MAX_EVENTS {
                return Err(AcpError::InvalidAccessRequest {
                    reason: "amendment lookup exceeds limit; use certified prefix pages".into(),
                });
            }
            if index.len() != prefix.len() + 8 || !value.is_empty() {
                return Err(AcpError::State("invalid amendment policy index".into()));
            }
            let id = u64::from_be_bytes(
                index[prefix.len()..]
                    .try_into()
                    .map_err(|_| AcpError::State("invalid amendment identifier".into()))?,
            );
            let key = keys::amendment_event_key(id);
            let value = self
                .store
                .get_ref(&key)
                .ok_or_else(|| AcpError::State("indexed amendment missing".into()))?;
            bytes = bytes
                .saturating_add(index.len())
                .saturating_add(key.len())
                .saturating_add(value.len());
            if bytes > MAX_BYTES {
                return Err(AcpError::InvalidAccessRequest {
                    reason: "amendment lookup byte limit exceeded; use certified prefix pages"
                        .into(),
                });
            }
            let event = decode(value, id)?;
            if event.policy_id != policy {
                return Err(AcpError::State("amendment policy index mismatch".into()));
            }
            if event.hijack_flag {
                events.push(event);
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(module: &mut AcpModule, policy: &str, flagged: bool) -> AmendmentEvent {
        let mut event = AmendmentEvent {
            id: 0,
            policy_id: policy.into(),
            object: Object {
                resource: "file".into(),
                id: "report".into(),
            },
            new_owner: Actor(Did::new("did:key:new").unwrap()),
            previous_owner: Actor(Did::new("did:key:old").unwrap()),
            commitment_id: 1,
            hijack_flag: flagged,
            metadata: RecordMetadata {
                creation_ts: Timestamp::default(),
                tx_hash: vec![],
                tx_signer: "worker".into(),
                owner_did: "did:key:new".into(),
            },
        };
        module.create_amendment_event(&mut event).unwrap();
        event
    }

    #[test]
    fn hijack_reports_bind_policy_and_preserve_event_metadata() {
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(
                &Did::new("did:key:owner").unwrap(),
                "name: amendments\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        let event = insert(&mut module, &policy, false);
        for restored in [false, true] {
            if restored {
                module = AcpModule::from_store(
                    InMemoryKvStore::deserialize(&module.store.serialize()).unwrap(),
                );
            }
            let before = module.store.serialize();
            for (actor, policy, id) in [
                (&event.new_owner.0, "other", event.id),
                (&event.previous_owner.0, policy.as_str(), event.id),
                (&event.new_owner.0, policy.as_str(), 0),
                (&event.new_owner.0, policy.as_str(), u64::MAX),
            ] {
                assert!(
                    module
                        .direct_policy_cmd(
                            actor,
                            policy,
                            PolicyCmd::FlagHijackAttempt { event_id: id }
                        )
                        .is_err()
                );
                assert_eq!(module.store.serialize(), before);
            }
            let PolicyCmdResult::FlagHijackAttempt { event: actual } = module
                .direct_policy_cmd(
                    &event.new_owner.0,
                    policy.as_str(),
                    PolicyCmd::FlagHijackAttempt { event_id: event.id },
                )
                .unwrap()
            else {
                panic!("expected hijack report");
            };
            let mut expected = event.clone();
            expected.hijack_flag = true;
            assert_eq!(
                borsh::to_vec(&actual).unwrap(),
                borsh::to_vec(&expected).unwrap()
            );
            if restored {
                assert_eq!(
                    module.store.serialize(),
                    before,
                    "repeated flag changed state"
                );
            }
            module.validate_amendment_indexes().unwrap();
        }
    }

    #[test]
    fn policy_lookup_is_indexed_bounded_and_survives_restore() {
        let mut module = AcpModule::new();
        for _ in 0..1000 {
            insert(&mut module, "other", true);
        }
        let event = insert(&mut module, "selected", true);
        for _ in 1..MAX_EVENTS {
            insert(&mut module, "selected", false);
        }
        let mut restored =
            AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
        restored.validate_amendment_indexes().unwrap();
        let records = restored.list_hijack_events_by_policy("selected").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, event.id);
        insert(&mut restored, "selected", false);
        assert!(restored.list_hijack_events_by_policy("selected").is_err());
    }

    #[test]
    fn corrupt_records_and_missing_indexes_are_errors() {
        let mut module = AcpModule::new();
        let event = insert(&mut module, "policy", true);
        let original = module.store.serialize();
        for value in [vec![0], {
            let wrong = AmendmentEvent {
                id: event.id + 1,
                ..event
            };
            borsh::to_vec(&wrong).unwrap()
        }] {
            module
                .store
                .put(&keys::amendment_event_key(event.id), value);
            assert!(module.get_amendment_event_by_id(event.id).is_err());
            assert!(module.list_hijack_events_by_policy("policy").is_err());
            assert!(module.validate_amendment_indexes().is_err());
        }
        module.store = InMemoryKvStore::deserialize(&original).unwrap();
        module
            .store
            .delete(&keys::amendment_event_policy_index_key("policy", event.id));
        assert!(module.validate_amendment_indexes().is_err());
        module.store = InMemoryKvStore::deserialize(&original).unwrap();
        module.store.delete(&keys::amendment_event_key(event.id));
        assert!(module.list_hijack_events_by_policy("policy").is_err());
    }

    #[test]
    fn lookup_limits_bytes_even_when_events_are_not_flagged() {
        let mut module = AcpModule::new();
        let mut event = insert(&mut module, "policy", false);
        event.metadata.tx_hash = vec![0; MAX_BYTES];
        module.update_amendment_event(&event).unwrap();
        assert!(matches!(
            module.list_hijack_events_by_policy("policy"),
            Err(AcpError::InvalidAccessRequest { .. })
        ));
    }
}
