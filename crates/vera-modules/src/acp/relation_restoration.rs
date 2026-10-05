//! Recovery validation of generation-qualified rows and their physical indexes.

use super::relation_cleanup::{
    decode_job, generation_suffix, relation_counter, sequence, validate_descriptor,
    validate_directory,
};
use super::relation_edits::{self as edits, RetiredRelation};
use super::retirement_cleanup::record_size;
use super::*;
use acp::Subject;
use std::collections::{BTreeMap, BTreeSet};

type Catalogs = BTreeMap<String, (RelationGenerations, bool)>;
type Descriptors = BTreeMap<(String, u64), RetiredRelation>;

impl AcpModule {
    pub(super) fn validate_relation_state(&self) -> Result<()> {
        let mut catalogs = Catalogs::new();
        for (key, _) in self.store.prefix_iter(keys::POLICY_PREFIX) {
            let policy = retirement::policy_id(&key[keys::POLICY_PREFIX.len()..])?;
            let record = self
                .get_policy_record(policy)?
                .ok_or_else(|| AcpError::State("restored relation policy missing".into()))?;
            record
                .relations
                .validate(&record.policy)
                .map_err(relation_state_error)?;
            catalogs.insert(policy.into(), (record.relations, true));
        }
        for (key, _) in self.store.prefix_iter(retirement::RETIRED_PREFIX) {
            let policy = retirement::policy_id(&key[retirement::RETIRED_PREFIX.len()..])?;
            let record = self
                .retired_policy(policy)?
                .ok_or_else(|| AcpError::State("restored relation retirement missing".into()))?;
            if catalogs
                .insert(policy.into(), (record.relations, false))
                .is_some()
            {
                return Err(AcpError::State("policy is both active and retired".into()));
            }
        }
        let mut known = BTreeSet::new();
        let descriptors = self.validate_relation_jobs(&catalogs, &mut known)?;
        let mut counts = BTreeMap::<(String, RelationPair), u64>::new();
        for (key, bytes) in self.store.prefix_iter(keys::RELATIONSHIP_PREFIX) {
            record_size(key, bytes)?;
            let record: RelationshipRecord = serde_json::from_slice(bytes).map_err(|error| {
                AcpError::State(format!("invalid retained relationship: {error}"))
            })?;
            let expected = keys::relationship_generation_key(
                &record.policy_id,
                record.generations,
                &keys::relationship_storage_key(&record.relationship),
            );
            if expected != key
                || !self
                    .retained_policy_allows(&record.policy_id, retirement::Phase::Relationships)?
            {
                return Err(AcpError::State(
                    "relationship key or retained policy mismatch".into(),
                ));
            }
            let (catalog, _) = catalogs
                .get(&record.policy_id)
                .ok_or_else(|| AcpError::State("relationship generation catalog missing".into()))?;
            validate_binding(
                catalog,
                &descriptors,
                &record.policy_id,
                record.generations.target,
                &record.relationship.resource,
                &record.relationship.relation,
            )?;
            match &record.relationship.subject {
                Subject::EntitySet {
                    resource, relation, ..
                } if !relation.is_empty() => {
                    validate_binding(
                        catalog,
                        &descriptors,
                        &record.policy_id,
                        record.generations.subject,
                        resource,
                        relation,
                    )?;
                }
                subject => {
                    if record.generations.subject != 0
                        || matches!(subject, Subject::EntitySet { resource, .. } if !catalog.active.contains_key(resource))
                    {
                        return Err(AcpError::State(
                            "relationship subject generation mismatch".into(),
                        ));
                    }
                }
            }
            let count = counts
                .entry((record.policy_id, record.generations))
                .or_default();
            *count = count
                .checked_add(1)
                .ok_or_else(|| AcpError::State("physical relationship count overflow".into()))?;
        }
        for ((policy, pair), count) in &counts {
            for key in [
                relationship_index::outgoing_key(policy, *pair),
                relationship_index::incoming_key(policy, *pair),
            ] {
                if self.store.get_ref(&key) != Some(count.to_be_bytes().as_slice()) {
                    return Err(AcpError::State(
                        "restored physical relationship count mismatch".into(),
                    ));
                }
                known.insert(key);
            }
        }
        for (policy, (catalog, active)) in &catalogs {
            if *active {
                let mut directories = BTreeMap::<u64, BTreeSet<u64>>::new();
                for ((owner, pair), _) in counts.range(
                    (
                        policy.clone(),
                        RelationPair {
                            target: 0,
                            subject: 0,
                        },
                    )..,
                ) {
                    if owner != policy {
                        break;
                    }
                    if catalog.contains(pair.target) && catalog.contains(pair.subject) {
                        directories
                            .entry(pair.target)
                            .or_default()
                            .insert(pair.subject);
                    }
                }
                for (target, subjects) in directories {
                    let key = relationship_index::active_key(policy, target);
                    let actual =
                        relationship_index::live_pairs(&self.store, policy, target, catalog)
                            .map_err(relation_state_error)?;
                    if actual != subjects.into_iter().collect::<Vec<_>>() {
                        return Err(AcpError::State(
                            "restored live relationship directory is incomplete".into(),
                        ));
                    }
                    known.insert(key);
                }
            } else {
                for (key, bytes) in self
                    .store
                    .prefix_iter(&relationship_index::active_prefix(policy))
                {
                    record_size(key, bytes)?;
                    validate_directory(key, bytes, policy, catalog)?;
                    known.insert(key.to_vec());
                }
            }
        }
        for (key, bytes) in self.store.prefix_iter(relationship_index::PREFIX) {
            record_size(key, bytes)?;
            if !known.contains(key) {
                return Err(AcpError::State(
                    "unexpected or orphan relationship index".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_relation_jobs(
        &self,
        catalogs: &Catalogs,
        known: &mut BTreeSet<Vec<u8>>,
    ) -> Result<Descriptors> {
        let counter = relation_counter(self)?;
        let mut descriptors = Descriptors::new();
        let mut sequences = BTreeSet::new();
        for (policy, (catalog, active)) in catalogs {
            let prefix = edits::retired_relation_prefix(policy);
            for (key, bytes) in self.store.prefix_iter(&prefix) {
                record_size(key, bytes)?;
                let generation = generation_suffix(&prefix, key)?;
                let descriptor = edits::load_retired_relation(&self.store, policy, generation)?
                    .ok_or_else(|| AcpError::State("retired relation descriptor missing".into()))?;
                validate_descriptor(&descriptor, catalog, counter)?;
                if !sequences.insert(descriptor.sequence) {
                    return Err(AcpError::State(
                        "duplicate relation cleanup sequence".into(),
                    ));
                }
                match self.store.get_ref(&edits::queue_key(descriptor.sequence)) {
                    Some(bytes) => {
                        let job = decode_job(bytes)?;
                        if job.policy != *policy || job.generation != generation {
                            return Err(AcpError::State(
                                "relation cleanup job differs from descriptor".into(),
                            ));
                        }
                    }
                    None if *active => {
                        return Err(AcpError::State(
                            "active policy relation cleanup job missing".into(),
                        ));
                    }
                    None => {}
                }
                descriptors.insert((policy.clone(), generation), descriptor);
                known.insert(key.to_vec());
            }
        }
        for (key, bytes) in self.store.prefix_iter(b"relation_cleanup/") {
            record_size(key, bytes)?;
            if key == edits::COUNTER_KEY {
                continue;
            }
            let sequence = sequence(key)?;
            let job = decode_job(bytes)?;
            let descriptor = descriptors
                .get(&(job.policy, job.generation))
                .ok_or_else(|| AcpError::State("orphan relation cleanup job".into()))?;
            if sequence != descriptor.sequence || sequence > counter {
                return Err(AcpError::State("relation cleanup sequence mismatch".into()));
            }
        }
        Ok(descriptors)
    }
}

fn validate_binding(
    catalog: &RelationGenerations,
    descriptors: &Descriptors,
    policy: &str,
    generation: u64,
    resource: &str,
    relation: &str,
) -> Result<()> {
    if generation >= catalog.next {
        return Err(AcpError::State(
            "relationship generation exceeds allocation counter".into(),
        ));
    }
    if catalog.generation(resource, relation) == Some(generation) {
        return Ok(());
    }
    if let Some(descriptor) = descriptors.get(&(policy.into(), generation))
        && descriptor.resource == resource
        && descriptor.relation == relation
    {
        return Ok(());
    }
    Err(AcpError::State(
        "relationship generation has no matching name descriptor".into(),
    ))
}
