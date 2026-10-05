//! Fair bounded cleanup of archived object incarnations.

use super::*;
use record_store::{RecordChange, RecordStore};
use retirement_cleanup::{Budget, JOB_ITEMS, RelationshipCleanup, record_size};
use serde::{Deserialize, Serialize};

pub(super) const QUEUE_PREFIX: &[u8] = b"object_cleanup/queue/";
pub(super) const COUNTER_KEY: &[u8] = b"object_cleanup/counter";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectJob {
    pub(super) policy: String,
    pub(super) object: Object,
    pub(super) incarnation: u64,
    pub(super) sequence: u64,
}

pub(super) fn marker_prefix(policy: &str) -> Vec<u8> {
    [
        relationship_index::policy_prefix(policy),
        b"retired_object/".to_vec(),
    ]
    .concat()
}

pub(super) fn marker_key(policy: &str, object: &Object, incarnation: u64) -> Vec<u8> {
    let mut key = marker_prefix(policy);
    key.extend_from_slice(keys::object_prefix(&object.resource, &object.id).as_bytes());
    key.extend_from_slice(format!("{incarnation:016x}").as_bytes());
    key
}

pub(super) fn queue_key(sequence: u64) -> Vec<u8> {
    [QUEUE_PREFIX, &sequence.to_be_bytes()].concat()
}

pub(super) fn counter<S: RecordStore>(store: &S) -> zanzibar::error::Result<u64> {
    store
        .read_record(COUNTER_KEY)?
        .as_deref()
        .map(|bytes| {
            bytes
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| relationship_index::invalid("invalid object cleanup counter"))
        })
        .transpose()
        .map(|count| count.unwrap_or(0))
}

pub(super) fn decode(bytes: &[u8]) -> Result<ObjectJob> {
    let job: ObjectJob = serde_json::from_slice(bytes)
        .map_err(|error| AcpError::State(format!("invalid object cleanup job: {error}")))?;
    relation_cleanup::canonical_internal_json(bytes, &job)?;
    retirement::policy_id(job.policy.as_bytes())?;
    if job.sequence == 0 {
        return Err(AcpError::State("zero object cleanup sequence".into()));
    }
    record_size(
        &marker_key(&job.policy, &job.object, job.incarnation),
        bytes,
    )?;
    Ok(job)
}

pub(super) fn prepare_job<S: RecordStore>(
    store: &S,
    policy: &str,
    object: &Object,
    incarnation: u64,
) -> zanzibar::error::Result<Vec<RecordChange>> {
    let marker = marker_key(policy, object, incarnation);
    if store.read_record(&marker)?.is_some() {
        return Err(relationship_index::invalid(
            "object incarnation already retired",
        ));
    }
    let sequence = counter(store)?
        .checked_add(1)
        .ok_or_else(|| relationship_index::invalid("object cleanup counter exhausted"))?;
    if store.read_record(&queue_key(sequence))?.is_some() {
        return Err(relationship_index::invalid(
            "object cleanup sequence already exists",
        ));
    }
    let job = ObjectJob {
        policy: policy.into(),
        object: object.clone(),
        incarnation,
        sequence,
    };
    Ok(vec![
        store.prepare_json(&marker, &job)?,
        store.prepare_json(&queue_key(sequence), &job)?,
        store.prepare_write(COUNTER_KEY, Some(&sequence.to_be_bytes()))?,
    ])
}

impl AcpModule {
    pub(super) fn collect_retired_objects(&mut self, budget: &mut Budget) -> Result<()> {
        let mut last_sequence = self
            .store
            .get_ref(COUNTER_KEY)
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid object cleanup counter".into()))
            })
            .transpose()?
            .unwrap_or(0);
        loop {
            let Some((key, value)) = self.store.prefix_iter(QUEUE_PREFIX).next() else {
                break;
            };
            let sequence = key
                .strip_prefix(QUEUE_PREFIX)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .filter(|seq| *seq > 0 && *seq <= last_sequence)
                .ok_or_else(|| AcpError::State("invalid object cleanup queue key".into()))?;
            // Queue/marker reads and rewrites, counter and fixed prefix probes.
            let minimum = 4 * record_size(key, value)? + 1024;
            if !budget.start_job(minimum, 4)? {
                break;
            }
            let mut job = decode(value)?;
            let marker = marker_key(&job.policy, &job.object, job.incarnation);
            let stored = self
                .store
                .get_ref(&marker)
                .ok_or_else(|| AcpError::State("object cleanup marker missing".into()))?;
            // Marker keys include the object identifier and may exceed the queue key.
            if !budget.reserve(0, 2 * marker.len(), 0) {
                break;
            }
            if job.sequence != sequence || stored != value {
                return Err(AcpError::State(
                    "object cleanup queue differs from marker".into(),
                ));
            }
            let state_key = object_state::key(&job.policy, &job.object.resource, &job.object.id);
            if !budget.reserve(
                0,
                record_size(
                    &state_key,
                    self.store.get_ref(&state_key).unwrap_or_default(),
                )?,
                0,
            ) {
                break;
            }
            let current = object_state::read(
                &self.store,
                &job.policy,
                &job.object.resource,
                &job.object.id,
            )
            .map_err(relation_state_error)?;
            if job.incarnation >= current {
                return Err(AcpError::State(
                    "object cleanup incarnation is not retired".into(),
                ));
            }
            let policy_key = keys::policy_key(&job.policy);
            let policy_bytes = self.store.get_ref(&policy_key);
            if !budget.reserve(
                0,
                record_size(&policy_key, policy_bytes.unwrap_or_default())?,
                0,
            ) {
                break;
            }
            if policy_bytes.is_none() {
                let retired_key = retirement::retired_key(&job.policy);
                let bytes = self
                    .store
                    .get_ref(&retired_key)
                    .ok_or_else(|| AcpError::State("object cleanup policy missing".into()))?;
                if !budget.reserve(0, record_size(&retired_key, bytes)?, 0) {
                    break;
                }
                let retired = self.retired_policy(&job.policy)?.unwrap();
                if !retired.relations.active.contains_key(&job.object.resource) {
                    return Err(AcpError::State("object cleanup resource missing".into()));
                }
                self.store.delete(&queue_key(sequence));
                continue;
            }
            let policy = self.get_policy_record(&job.policy)?.unwrap();
            if !policy.relations.active.contains_key(&job.object.resource) {
                return Err(AcpError::State("object cleanup resource missing".into()));
            }
            let mut removed = 0;
            let mut complete = false;
            while removed < JOB_ITEMS {
                let prefix = object_pairs::incarnation_prefix(
                    &job.policy,
                    &job.object.resource,
                    &job.object.id,
                    job.incarnation,
                );
                if !budget.reserve(0, prefix.len(), 0) {
                    break;
                }
                let mut pairs = self.store.prefix_iter(&prefix);
                let mut next = pairs.next();
                if let Some((key, value)) = next {
                    if !budget.reserve(0, record_size(key, value)?, 0) {
                        break;
                    }
                    let pair =
                        object_pairs::parse_pair(&prefix, key).map_err(relation_state_error)?;
                    relationship_index::decode_count(value).map_err(relation_state_error)?;
                    if pair.target == 0 {
                        if pair.subject != 0 || job.incarnation != 0 {
                            return Err(AcpError::State("invalid archived owner counter".into()));
                        }
                        next = pairs.next();
                        if let Some((key, value)) = next
                            && !budget.reserve(0, record_size(key, value)?, 0)
                        {
                            break;
                        }
                    }
                }
                let Some((key, value)) = next else {
                    complete = true;
                    break;
                };
                let pair = object_pairs::parse_pair(&prefix, key).map_err(relation_state_error)?;
                relationship_index::decode_count(value).map_err(relation_state_error)?;
                if pair.target == 0 {
                    return Err(AcpError::State("object cleanup selected owner".into()));
                }
                let suffix = keys::object_incarnation_prefix(
                    &job.object.resource,
                    &job.object.id,
                    job.incarnation,
                );
                let primary = keys::relationship_generation_prefix(&job.policy, pair, &suffix);
                if !budget.reserve(0, primary.len(), 0) {
                    break;
                }
                let first = self
                    .store
                    .prefix_iter(&primary)
                    .next()
                    .ok_or_else(|| AcpError::State("object cleanup counter has no rows".into()))?
                    .0;
                let Some((count, changes)) = self.prepare_cleanup_relationships(
                    &job.policy,
                    RelationshipCleanup::Object {
                        object: &job.object,
                        incarnation: job.incarnation,
                    },
                    first,
                    JOB_ITEMS - removed,
                    budget,
                )?
                else {
                    break;
                };
                drop(pairs);
                self.store
                    .apply_records(changes)
                    .map_err(relation_state_error)?;
                removed += count;
            }
            if complete {
                self.store.delete(&queue_key(sequence));
                self.store.delete(&marker);
            } else if removed > 0 {
                let next = last_sequence
                    .checked_add(1)
                    .ok_or_else(|| AcpError::State("object cleanup counter exhausted".into()))?;
                if self.store.has(&queue_key(next)) {
                    return Err(AcpError::State(
                        "object cleanup sequence already exists".into(),
                    ));
                }
                job.sequence = next;
                let bytes =
                    serde_json::to_vec(&job).map_err(|error| AcpError::State(error.to_string()))?;
                self.store.put(&marker, bytes.clone());
                self.store.put(&queue_key(next), bytes);
                self.store.put(COUNTER_KEY, next.to_be_bytes().to_vec());
                self.store.delete(&queue_key(sequence));
                last_sequence = next;
            } else {
                break;
            }
            if budget.items == 0 {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "object_cleanup_tests.rs"]
mod tests;
