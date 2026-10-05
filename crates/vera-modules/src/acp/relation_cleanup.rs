//! Bounded cleanup of rows whose target or userset identity was retired.

use super::relation_edits::{self as edits, RelationJob, RetiredRelation};
use super::retirement_cleanup::{Budget, JOB_ITEMS, record_size};
use super::*;
use std::collections::BTreeSet;

enum NextRow {
    Complete,
    Row(Vec<u8>),
    BudgetExhausted,
}

pub(super) fn generation_suffix(prefix: &[u8], key: &[u8]) -> Result<u64> {
    let suffix = key
        .strip_prefix(prefix)
        .ok_or_else(|| AcpError::State("invalid relation index prefix".into()))?;
    if suffix.len() != 16
        || !suffix
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(AcpError::State("invalid relation generation key".into()));
    }
    u64::from_str_radix(std::str::from_utf8(suffix).unwrap(), 16)
        .map_err(|_| AcpError::State("invalid relation generation identifier".into()))
}

pub(super) fn relation_counter(module: &AcpModule) -> Result<u64> {
    module
        .store
        .get_ref(edits::COUNTER_KEY)
        .map(|bytes| {
            bytes
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| AcpError::State("invalid relation cleanup counter".into()))
        })
        .transpose()
        .map(|counter| counter.unwrap_or(0))
}

pub(super) fn sequence(key: &[u8]) -> Result<u64> {
    key.strip_prefix(edits::QUEUE_PREFIX)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .filter(|value| *value != 0)
        .ok_or_else(|| AcpError::State("invalid relation cleanup queue key".into()))
}

pub(super) fn canonical_internal_json<T: serde::Serialize>(bytes: &[u8], record: &T) -> Result<()> {
    let canonical =
        serde_json::to_vec(record).map_err(|error| AcpError::State(error.to_string()))?;
    if canonical != bytes {
        return Err(AcpError::State(
            "noncanonical relation cleanup metadata".into(),
        ));
    }
    Ok(())
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(super) fn decode_job(bytes: &[u8]) -> Result<RelationJob> {
    let job: RelationJob = serde_json::from_slice(bytes)
        .map_err(|error| AcpError::State(format!("invalid relation cleanup job: {error}")))?;
    canonical_internal_json(bytes, &job)?;
    retirement::policy_id(job.policy.as_bytes())?;
    if job.generation == 0 {
        return Err(AcpError::State("zero retired generation".into()));
    }
    Ok(job)
}

pub(super) fn validate_catalog(relations: &RelationGenerations) -> Result<()> {
    if relations.next == 0 {
        return Err(AcpError::State("zero next relation generation".into()));
    }
    let mut seen = BTreeSet::new();
    for (resource, names) in &relations.active {
        if !identifier(resource) {
            return Err(AcpError::State("empty generation resource".into()));
        }
        for (relation, generation) in names {
            if !identifier(relation)
                || (relation == "owner" && *generation != 0)
                || (relation != "owner"
                    && (*generation == 0
                        || *generation >= relations.next
                        || !seen.insert(*generation)))
            {
                return Err(AcpError::State("invalid retained relation catalog".into()));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_descriptor(
    descriptor: &RetiredRelation,
    relations: &RelationGenerations,
    counter: u64,
) -> Result<()> {
    if descriptor.sequence == 0
        || descriptor.sequence > counter
        || descriptor.generation == 0
        || descriptor.generation >= relations.next
        || relations.contains(descriptor.generation)
        || !relations.active.contains_key(&descriptor.resource)
        || !identifier(&descriptor.resource)
        || !identifier(&descriptor.relation)
        || descriptor.relation == "owner"
    {
        return Err(AcpError::State(
            "invalid retired relation descriptor".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_directory(
    key: &[u8],
    bytes: &[u8],
    policy: &str,
    catalog: &RelationGenerations,
) -> Result<()> {
    let target = generation_suffix(&relationship_index::active_prefix(policy), key)?;
    let subjects: Vec<u64> = serde_json::from_slice(bytes).map_err(|error| {
        AcpError::State(format!("invalid retained relation directory: {error}"))
    })?;
    if !catalog.contains(target)
        || subjects.is_empty()
        || subjects.windows(2).any(|ids| ids[0] >= ids[1])
        || subjects.iter().any(|id| !catalog.contains(*id))
    {
        return Err(AcpError::State(
            "invalid retained relation directory".into(),
        ));
    }
    Ok(())
}

impl AcpModule {
    pub(super) fn collect_retired_relations(&mut self, budget: &mut Budget) -> Result<()> {
        relation_counter(self)?;
        loop {
            let Some((key, value)) = self.store.prefix_iter(edits::QUEUE_PREFIX).next() else {
                break;
            };
            let job = decode_job(value)?;
            let marker_key = edits::retired_relation_key(&job.policy, job.generation);
            let marker_bytes = self
                .store
                .get_ref(&marker_key)
                .ok_or_else(|| AcpError::State("relation cleanup marker missing".into()))?;
            let policy_key = keys::policy_key(&job.policy);
            let policy_bytes = self.store.get_ref(&policy_key);
            let metadata = 2 * record_size(&marker_key, marker_bytes)?
                + 2 * record_size(key, value)?
                + policy_bytes
                    .map(|bytes| record_size(&policy_key, bytes))
                    .transpose()?
                    .unwrap_or(policy_key.len())
                + 1024;
            if !budget.start_job(metadata, 4)? {
                break;
            }
            let sequence = sequence(key)?;
            let mut descriptor =
                edits::load_retired_relation(&self.store, &job.policy, job.generation)?
                    .ok_or_else(|| AcpError::State("relation cleanup marker missing".into()))?;
            if descriptor.sequence != sequence || sequence > relation_counter(self)? {
                return Err(AcpError::State("relation cleanup queue mismatch".into()));
            }
            if policy_bytes.is_none() {
                let retired_key = retirement::retired_key(&job.policy);
                let bytes = self
                    .store
                    .get_ref(&retired_key)
                    .ok_or_else(|| AcpError::State("relation cleanup policy missing".into()))?;
                if !budget.reserve(0, record_size(&retired_key, bytes)?, 0) {
                    break;
                }
                let retired = self.retired_policy(&job.policy)?.unwrap();
                validate_descriptor(&descriptor, &retired.relations, relation_counter(self)?)?;
                self.store.delete(&edits::queue_key(sequence));
                continue;
            }
            let policy = self.get_policy_record(&job.policy)?.unwrap();
            policy
                .relations
                .validate(&policy.policy)
                .map_err(relation_state_error)?;
            validate_descriptor(&descriptor, &policy.relations, relation_counter(self)?)?;
            let mut removed = 0;
            let complete = loop {
                if removed == JOB_ITEMS {
                    break false;
                }
                let row =
                    match self.next_retired_relationship(&job.policy, job.generation, budget)? {
                        NextRow::Complete => break true,
                        NextRow::BudgetExhausted => break false,
                        NextRow::Row(row) => row,
                    };
                let Some((items, changes)) = self.prepare_cleanup_relationships(
                    &job.policy,
                    retirement_cleanup::RelationshipCleanup::Relation(job.generation),
                    &row,
                    JOB_ITEMS - removed,
                    budget,
                )?
                else {
                    break false;
                };
                record_store::RecordStore::apply_records(&mut self.store, changes)
                    .map_err(relation_state_error)?;
                removed += items;
            };
            if complete {
                self.store.delete(&edits::queue_key(sequence));
                self.store.delete(&marker_key);
            } else if removed > 0 {
                let next = relation_counter(self)?
                    .checked_add(1)
                    .ok_or_else(|| AcpError::State("relation cleanup counter exhausted".into()))?;
                if self.store.has(&edits::queue_key(next)) {
                    return Err(AcpError::State(
                        "relation cleanup sequence already exists".into(),
                    ));
                }
                descriptor.sequence = next;
                let encoded =
                    serde_json::to_vec(&descriptor).map_err(|e| AcpError::State(e.to_string()))?;
                let job = serde_json::to_vec(&job).map_err(|e| AcpError::State(e.to_string()))?;
                self.store.put(&marker_key, encoded);
                self.store.put(&edits::queue_key(next), job);
                self.store
                    .put(edits::COUNTER_KEY, next.to_be_bytes().to_vec());
                self.store.delete(&edits::queue_key(sequence));
            }
            if !complete && removed < JOB_ITEMS || budget.items == 0 {
                break;
            }
        }
        Ok(())
    }

    fn next_retired_relationship(
        &self,
        policy: &str,
        generation: u64,
        budget: &mut Budget,
    ) -> Result<NextRow> {
        if !budget.reserve(0, 1024, 0) {
            return Ok(NextRow::BudgetExhausted);
        }
        let target_prefix = keys::relationship_target_prefix(policy, generation);
        if let Some((key, _)) = self.store.prefix_iter(&target_prefix).next() {
            return Ok(NextRow::Row(key.to_vec()));
        }
        if self
            .store
            .prefix_iter(&relationship_index::outgoing_prefix(policy, generation))
            .next()
            .is_some()
        {
            return Err(AcpError::State(
                "retired target counter has no physical rows".into(),
            ));
        }
        let incoming = relationship_index::incoming_prefix(policy, generation);
        let Some((key, value)) = self.store.prefix_iter(&incoming).next() else {
            return Ok(NextRow::Complete);
        };
        // The fixed counter probe is reserved independently of the subsequent row read.
        if !budget.reserve(0, record_size(key, value)?, 0) {
            return Ok(NextRow::BudgetExhausted);
        }
        let target = generation_suffix(&incoming, key)?;
        let pair = RelationPair {
            target,
            subject: generation,
        };
        let prefix = keys::relationship_generation_prefix(policy, pair, "");
        let (key, _) = self.store.prefix_iter(&prefix).next().ok_or_else(|| {
            AcpError::State("retired subject counter has no physical rows".into())
        })?;
        Ok(NextRow::Row(key.to_vec()))
    }

    pub(super) fn cleanup_relationship_metadata(
        &self,
        policy: &str,
        catalog: &RelationGenerations,
        key: &[u8],
        value: &[u8],
        budget: &mut Budget,
    ) -> Result<Option<Vec<Vec<u8>>>> {
        if key.starts_with(&relationship_index::active_prefix(policy)) {
            validate_directory(key, value, policy, catalog)?;
            return Ok(Some(vec![key.to_vec()]));
        }
        let prefix = edits::retired_relation_prefix(policy);
        if key.starts_with(&prefix) {
            let generation = generation_suffix(&prefix, key)?;
            let descriptor: RetiredRelation = serde_json::from_slice(value)
                .map_err(|error| AcpError::State(format!("invalid retired relation: {error}")))?;
            canonical_internal_json(value, &descriptor)?;
            if descriptor.generation != generation {
                return Err(AcpError::State("retired relation identity mismatch".into()));
            }
            validate_descriptor(&descriptor, catalog, relation_counter(self)?)?;
            let queue = edits::queue_key(descriptor.sequence);
            if !budget.reserve(0, queue.len() + 128, 0) {
                return Ok(None);
            }
            if let Some(bytes) = self.store.get_ref(&queue) {
                if !budget.reserve(0, record_size(&queue, bytes)?, 0) {
                    return Ok(None);
                }
                let job = decode_job(bytes)?;
                if job.policy != policy || job.generation != generation {
                    return Err(AcpError::State("retired relation queue mismatch".into()));
                }
            }
            return Ok(Some(vec![key.to_vec(), queue]));
        }
        Err(AcpError::State(
            "unexpected relationship index after physical cleanup".into(),
        ))
    }
}

#[cfg(test)]
#[path = "relation_cleanup_tests.rs"]
mod tests;
