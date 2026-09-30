use super::*;

const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;

impl AcpModule {
    /// Filter a bounded policy prefix; invalid records and incomplete results are errors.
    pub fn query_filter_relationships(
        &self,
        policy_id: &str,
        selector: &RelationshipSelector,
    ) -> Result<Vec<RelationshipRecord>> {
        self.query_policy(policy_id)?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for (count, (key, value)) in self
            .store
            .prefix_iter(&Self::relationship_query_prefix(policy_id, selector))
            .enumerate()
        {
            bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if count >= MAX_RECORDS || bytes > MAX_BYTES {
                return Err(AcpError::State("relationship query budget exceeded".into()));
            }
            let record: RelationshipRecord = serde_json::from_slice(value)
                .map_err(|e| AcpError::State(format!("invalid relationship record: {e}")))?;
            if record.policy_id != policy_id
                || keys::relationship_key(
                    policy_id,
                    &keys::relationship_storage_key(&record.relationship),
                ) != key
            {
                return Err(AcpError::State(
                    "relationship record identity mismatch".into(),
                ));
            }
            // Archived objects are absent to evaluation and ownership
            // queries; relationship listings must agree with them.
            if !record.archived && self.matches_selector(&record, selector) {
                records.push(record);
            }
        }
        Ok(records)
    }
    pub(super) fn relationship_query_prefix(
        policy: &str,
        selector: &RelationshipSelector,
    ) -> Vec<u8> {
        let suffix = match &selector.object_selector {
            Some(ObjectSelector::Exact(object)) => match &selector.relation_selector {
                Some(RelationSelector::Exact(relation)) => {
                    keys::relation_prefix(&object.resource, &object.id, relation)
                }
                _ => keys::object_prefix(&object.resource, &object.id),
            },
            Some(ObjectSelector::ResourcePredicate(resource)) => keys::resource_prefix(resource),
            _ => return keys::relationship_policy_prefix(policy),
        };
        keys::relationship_storage_prefix(policy, &suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector() -> RelationshipSelector {
        RelationshipSelector {
            object_selector: None,
            relation_selector: None,
            subject_selector: None,
        }
    }

    fn insert(module: &mut AcpModule, policy: &str, id: &str) -> Vec<u8> {
        let owner = Did::new("did:key:owner").unwrap();
        let record = RelationshipRecord {
            supplied_metadata: Default::default(),
            policy_id: policy.into(),
            relationship: Relationship::with_entity("file", id, "owner", owner),
            archived: false,
            metadata: RecordMetadata {
                creation_ts: Timestamp::default(),
                tx_hash: vec![],
                tx_signer: "worker".into(),
                owner_did: "did:key:owner".into(),
            },
        };
        let key = keys::relationship_key(
            policy,
            &keys::relationship_storage_key(&record.relationship),
        );
        module.store.put(&key, serde_json::to_vec(&record).unwrap());
        key
    }

    #[test]
    fn relationship_query_bounds_inspected_records_before_filtering() {
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(
                &Did::new("did:key:owner").unwrap(),
                "name: query\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        for i in 0..1000 {
            insert(&mut module, "other", &i.to_string());
        }
        for i in 0..MAX_RECORDS {
            insert(&mut module, &policy, &i.to_string());
        }
        assert_eq!(
            module
                .query_filter_relationships(&policy, &selector())
                .unwrap()
                .len(),
            MAX_RECORDS
        );
        let mut excluded = selector();
        excluded.relation_selector = Some(RelationSelector::Exact("reader".into()));
        assert!(
            module
                .query_filter_relationships(&policy, &excluded)
                .unwrap()
                .is_empty()
        );
        insert(&mut module, &policy, "overflow");
        assert!(
            module
                .query_filter_relationships(&policy, &excluded)
                .is_err()
        );
    }

    #[test]
    fn relationship_query_rejects_corruption_and_oversized_records() {
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(
                &Did::new("did:key:owner").unwrap(),
                "name: query\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        let key = insert(&mut module, &policy, "report");
        let valid = module.store.get(&key).unwrap();
        let mut excluded = selector();
        excluded.relation_selector = Some(RelationSelector::Exact("reader".into()));
        module.store.put(&key, valid[..valid.len() - 1].to_vec());
        assert!(
            module
                .query_filter_relationships(&policy, &excluded)
                .is_err()
        );
        let mut record: RelationshipRecord = serde_json::from_slice(&valid).unwrap();
        record.policy_id = "other".into();
        module.store.put(&key, serde_json::to_vec(&record).unwrap());
        assert!(
            module
                .query_filter_relationships(&policy, &excluded)
                .is_err()
        );
        record.policy_id = policy.clone();
        record.relationship.object_id = "another".into();
        module.store.put(&key, serde_json::to_vec(&record).unwrap());
        assert!(
            module
                .query_filter_relationships(&policy, &excluded)
                .is_err()
        );
        module.store.put(&key, vec![b' '; MAX_BYTES]);
        assert!(
            module
                .query_filter_relationships(&policy, &excluded)
                .is_err()
        );
    }
}
