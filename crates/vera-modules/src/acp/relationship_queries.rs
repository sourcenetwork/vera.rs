use super::*;

const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;
const MAX_BUCKETS: usize = 256;
const MAX_DIRECTORY_READS: usize = 256;

impl AcpModule {
    /// Filter current generation buckets with bounded planning and row inspection.
    /// Planning permits 256 directory reads, 256 buckets and 1 MiB of directory/prefix bytes.
    /// Row inspection separately permits 128 records and 1 MiB.
    pub fn query_filter_relationships(
        &self,
        policy_id: &str,
        selector: &RelationshipSelector,
    ) -> Result<Vec<RelationshipRecord>> {
        let policy = self.query_policy(policy_id)?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let mut count = 0usize;
        for prefix in self.relationship_query_prefixes(&policy, selector)? {
            for (key, value) in self.store.prefix_iter(&prefix) {
                bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
                if count >= MAX_RECORDS || bytes > MAX_BYTES {
                    return Err(AcpError::State("relationship query budget exceeded".into()));
                }
                count += 1;
                let record = Self::decode_current_relationship(&policy, key, value)?;
                if !record.archived && self.matches_selector(&record, selector) {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    pub(super) fn relationship_query_prefixes(
        &self,
        policy: &PolicyRecord,
        selector: &RelationshipSelector,
    ) -> Result<Vec<Vec<u8>>> {
        let suffix = query_suffix(policy, selector)?;
        let mut targets = std::collections::BTreeSet::new();
        let selected_resource = match &selector.object_selector {
            Some(ObjectSelector::Exact(object)) => Some(object.resource.as_str()),
            Some(ObjectSelector::ResourcePredicate(resource)) => Some(resource.as_str()),
            _ => None,
        };
        if let (Some(resource), Some(RelationSelector::Exact(relation))) =
            (selected_resource, &selector.relation_selector)
        {
            if let Some(generation) = policy.relations.generation(resource, relation) {
                targets.insert(generation);
            }
        } else {
            for (resource, relations) in &policy.relations.active {
                if selected_resource.is_some_and(|selected| selected != resource) {
                    continue;
                }
                for (relation, generation) in relations {
                    if matches!(&selector.relation_selector, Some(RelationSelector::Exact(expected)) if expected != relation)
                    {
                        continue;
                    }
                    targets.insert(*generation);
                }
            }
        }
        let active = policy.relations.active_ids();
        let mut limits = read_capture::ReadLimits {
            reads: MAX_DIRECTORY_READS,
            records: MAX_DIRECTORY_READS,
            bytes: MAX_BYTES,
        };
        let mut prefixes = Vec::new();
        let prefix_size = generation_prefix_size(policy).saturating_add(suffix.len());
        for target in targets {
            // Carry the remaining budget into each bounded directory read before decoding it.
            let capture = read_capture::ReadCapture::new(self.store.clone(), limits);
            let subjects = relationship_index::live_pairs_for_active(
                &capture,
                &policy.policy.id,
                target,
                &active,
            )
            .map_err(relation_state_error)?;
            limits = capture.remaining_limits().ok_or_else(planning_limit)?;
            for subject in subjects {
                if prefixes.len() == MAX_BUCKETS {
                    return Err(planning_limit());
                }
                limits.bytes = limits
                    .bytes
                    .checked_sub(prefix_size)
                    .ok_or_else(planning_limit)?;
                prefixes.push(keys::relationship_generation_prefix(
                    &policy.policy.id,
                    RelationPair { target, subject },
                    &suffix,
                ));
            }
        }
        Ok(prefixes)
    }

    pub(super) fn decode_current_relationship(
        policy: &PolicyRecord,
        key: &[u8],
        value: &[u8],
    ) -> Result<RelationshipRecord> {
        let record: RelationshipRecord = serde_json::from_slice(value)
            .map_err(|e| AcpError::State(format!("invalid relationship record: {e}")))?;
        if record.policy_id != policy.policy.id
            || policy
                .relations
                .pair(&record.relationship)
                .map_err(relation_state_error)?
                != record.generations
            || keys::relationship_generation_key(
                &record.policy_id,
                record.generations,
                &keys::relationship_storage_key(&record.relationship),
            ) != key
        {
            return Err(AcpError::State(
                "relationship record identity mismatch".into(),
            ));
        }
        Ok(record)
    }
}

fn planning_limit() -> AcpError {
    AcpError::State("relationship query planning budget exceeded".into())
}

const fn generation_prefix_size(policy: &PolicyRecord) -> usize {
    keys::RELATIONSHIP_PREFIX.len() + policy.policy.id.len() + 1 + 17 + 17
}

fn query_suffix(policy: &PolicyRecord, selector: &RelationshipSelector) -> Result<String> {
    let encoded = |value: &str| value.len().saturating_mul(2);
    let suffix_size = match &selector.object_selector {
        Some(ObjectSelector::Exact(object)) => 5usize
            .saturating_add(encoded(&object.resource))
            .saturating_add(encoded(&object.id))
            .saturating_add(match &selector.relation_selector {
                Some(RelationSelector::Exact(relation)) => 1usize.saturating_add(encoded(relation)),
                _ => 0,
            }),
        Some(ObjectSelector::ResourcePredicate(resource)) => {
            4usize.saturating_add(encoded(resource))
        }
        _ => 0,
    };
    if generation_prefix_size(policy).saturating_add(suffix_size)
        > crate::kv_store::NATIVE_MAX_KEY_BYTES
    {
        return Err(AcpError::InvalidAccessRequest {
            reason: "relationship query prefix exceeds native key bounds".into(),
        });
    }
    Ok(match &selector.object_selector {
        Some(ObjectSelector::Exact(object)) => match &selector.relation_selector {
            Some(RelationSelector::Exact(relation)) => {
                keys::relation_prefix(&object.resource, &object.id, relation)
            }
            _ => keys::object_prefix(&object.resource, &object.id),
        },
        Some(ObjectSelector::ResourcePredicate(resource)) => keys::resource_prefix(resource),
        _ => String::new(),
    })
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
            generations: RelationPair {
                target: 0,
                subject: 0,
            },
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
        if module.query_policy(policy).is_ok() {
            module.set_relationship(&record).unwrap();
        } else {
            module.store.put(&key, serde_json::to_vec(&record).unwrap());
        }
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
                .unwrap()
                .is_empty()
        );
        assert!(
            module
                .query_filter_relationships(&policy, &selector())
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
        let excluded = selector();
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

    fn pair_policy(module: &mut AcpModule, names: usize) -> String {
        let mut source = String::from(
            "name: query_pairs\nresources:\n  - name: file\n    relations:\n      - name: reader\n",
        );
        for index in 0..names {
            source.push_str(&format!("      - name: g{index}\n"));
        }
        module
            .create_policy(
                &Did::new("did:key:owner").unwrap(),
                &source,
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id
    }

    fn insert_pair(module: &mut AcpModule, policy: &str, subject: usize) {
        let definition = module.query_policy(policy).unwrap();
        let relationship = Relationship::new(
            "file",
            "elsewhere",
            "reader",
            acp::Subject::entity_set("file", "source", format!("g{subject}")),
        );
        let record = RelationshipRecord {
            generations: definition.relations.pair(&relationship).unwrap(),
            policy_id: policy.into(),
            relationship,
            archived: false,
            supplied_metadata: Default::default(),
            metadata: definition.metadata,
        };
        module.set_relationship(&record).unwrap();
    }

    fn empty_object_selector(id: &str, relation: Option<&str>) -> RelationshipSelector {
        RelationshipSelector {
            object_selector: Some(ObjectSelector::Exact(Object {
                resource: "file".into(),
                id: id.into(),
            })),
            relation_selector: relation.map(|relation| RelationSelector::Exact(relation.into())),
            subject_selector: None,
        }
    }

    fn page_request(selector: RelationshipSelector) -> pages::RelationshipPageRequest {
        pages::RelationshipPageRequest {
            selector,
            after: None,
        }
    }

    #[test]
    fn empty_object_queries_bound_pairs_before_allocating_prefixes() {
        let mut module = AcpModule::new();
        let policy = pair_policy(&mut module, MAX_BUCKETS + 1);
        for subject in 0..MAX_BUCKETS {
            insert_pair(&mut module, &policy, subject);
        }
        let selector = empty_object_selector("missing", Some("reader"));
        assert!(
            module
                .query_filter_relationships(&policy, &selector)
                .unwrap()
                .is_empty()
        );
        assert!(
            module
                .query_relationships_page(&policy, &page_request(selector.clone()))
                .unwrap()
                .records
                .is_empty()
        );
        insert_pair(&mut module, &policy, MAX_BUCKETS);
        assert!(
            module
                .query_filter_relationships(&policy, &selector)
                .is_err()
        );
        assert!(
            module
                .query_relationships_page(&policy, &page_request(selector))
                .is_err()
        );

        let owner = Did::new("did:key:owner").unwrap();
        let object = Object {
            resource: "file".into(),
            id: "victim".into(),
        };
        module
            .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap();
        assert!(matches!(
            module
                .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(object.clone()))
                .unwrap(),
            PolicyCmdResult::ArchiveObject {
                found: true,
                relationships_removed: 1
            }
        ));
        assert!(
            module
                .registration_owner_record(&policy, &object)
                .unwrap()
                .unwrap()
                .archived
        );
        module.validate_restored_state().unwrap();
    }

    #[test]
    fn planning_caps_empty_directory_reads_but_keeps_exact_relation_targeted() {
        let mut module = AcpModule::new();
        let policy = pair_policy(&mut module, MAX_DIRECTORY_READS);
        let broad = empty_object_selector("missing", None);
        assert!(module.query_filter_relationships(&policy, &broad).is_err());
        assert!(
            module
                .query_relationships_page(&policy, &page_request(broad))
                .is_err()
        );
        let narrow = empty_object_selector("missing", Some("reader"));
        assert!(
            module
                .query_filter_relationships(&policy, &narrow)
                .unwrap()
                .is_empty()
        );
        assert!(
            module
                .query_relationships_page(&policy, &page_request(narrow))
                .unwrap()
                .records
                .is_empty()
        );
    }

    #[test]
    fn planning_charges_generated_prefix_bytes_and_rejects_oversized_suffixes() {
        let mut module = AcpModule::new();
        let policy = pair_policy(&mut module, 17);
        for subject in 0..17 {
            insert_pair(&mut module, &policy, subject);
        }
        let selector = empty_object_selector(&"x".repeat(31 << 10), Some("reader"));
        assert!(
            module
                .query_filter_relationships(&policy, &selector)
                .is_err()
        );
        assert!(
            module
                .query_relationships_page(&policy, &page_request(selector))
                .is_err()
        );
        let oversized = empty_object_selector(&"x".repeat(64 << 10), Some("reader"));
        assert!(matches!(
            module.query_filter_relationships(&policy, &oversized),
            Err(AcpError::InvalidAccessRequest { .. })
        ));
    }
}
