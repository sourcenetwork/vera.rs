//! Policy edits invalidate immutable relation identities without scanning objects.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::record_store::{RecordChange, RecordStore};
use super::*;

pub(super) const QUEUE_PREFIX: &[u8] = b"relation_cleanup/queue/";
pub(super) const COUNTER_KEY: &[u8] = b"relation_cleanup/counter";

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetiredRelation {
    pub(super) sequence: u64,
    pub(super) generation: u64,
    pub(super) resource: String,
    pub(super) relation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RelationJob {
    pub(super) policy: String,
    pub(super) generation: u64,
}

pub(super) fn retired_relation_prefix(policy: &str) -> Vec<u8> {
    format!("relation_state/{policy}/retired/").into_bytes()
}

pub(super) fn retired_relation_key(policy: &str, generation: u64) -> Vec<u8> {
    format!("relation_state/{policy}/retired/{generation:016x}").into_bytes()
}

pub(super) fn queue_key(sequence: u64) -> Vec<u8> {
    [QUEUE_PREFIX, &sequence.to_be_bytes()].concat()
}

pub(super) fn load_retired_relation<S: RecordStore>(
    store: &S,
    policy: &str,
    generation: u64,
) -> Result<Option<RetiredRelation>> {
    store
        .read_record(&retired_relation_key(policy, generation))
        .map_err(relation_state_error)?
        .map(|bytes| {
            let record: RetiredRelation = serde_json::from_slice(&bytes)
                .map_err(|e| AcpError::State(format!("invalid retired relation: {e}")))?;
            relation_cleanup::canonical_internal_json(&bytes, &record)?;
            if generation == 0 || record.generation != generation || record.sequence == 0 {
                return Err(AcpError::State("retired relation identity mismatch".into()));
            }
            Ok(record)
        })
        .transpose()
}

impl AcpModule {
    pub(super) fn prepare_relation_edit(
        &self,
        policy: &str,
        old: &RelationGenerations,
        new: &RelationGenerations,
        retired: &BTreeSet<u64>,
    ) -> Result<(u64, Vec<RecordChange>)> {
        if retired.is_empty() {
            return Ok((0, Vec::new()));
        }
        let mut removed = 0u64;
        let mut changes = Vec::new();
        for target in old.active_ids() {
            let subjects = relationship_index::live_pairs(&self.store, policy, target, old)
                .map_err(relation_state_error)?;
            let mut remaining = Vec::new();
            for subject in &subjects {
                if retired.contains(&target) || retired.contains(subject) {
                    let count = relationship_index::read_pair_count(
                        &self.store,
                        policy,
                        RelationPair {
                            target,
                            subject: *subject,
                        },
                    )
                    .map_err(relation_state_error)?;
                    if count == 0 {
                        return Err(AcpError::State(
                            "live relation directory has no physical records".into(),
                        ));
                    }
                    removed = removed.checked_add(count).ok_or_else(|| {
                        AcpError::State("removed relationship count overflow".into())
                    })?;
                } else {
                    remaining.push(*subject);
                }
            }
            if remaining != subjects {
                let value = if remaining.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::to_vec(&remaining)
                            .map_err(|e| AcpError::State(e.to_string()))?,
                    )
                };
                changes.push((relationship_index::active_key(policy, target), value));
            }
        }
        let mut sequence = self
            .store
            .get_ref(COUNTER_KEY)
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid relation cleanup counter".into()))
            })
            .transpose()?
            .unwrap_or(0);
        let previous_sequence = sequence;
        for generation in retired {
            if new.contains(*generation) || *generation == 0 || *generation >= old.next {
                return Err(AcpError::State(
                    "invalid removed relation generation".into(),
                ));
            }
            if self.store.has(&retired_relation_key(policy, *generation)) {
                return Err(AcpError::State(
                    "relation generation is already retired".into(),
                ));
            }
            let physical = self
                .store
                .prefix_iter(&relationship_index::outgoing_prefix(policy, *generation))
                .next()
                .is_some()
                || self
                    .store
                    .prefix_iter(&relationship_index::incoming_prefix(policy, *generation))
                    .next()
                    .is_some();
            if !physical {
                continue;
            }
            let (resource, relation) = old
                .active
                .iter()
                .find_map(|(resource, relations)| {
                    relations
                        .iter()
                        .find(|(_, id)| **id == *generation)
                        .map(|(relation, _)| (resource.clone(), relation.clone()))
                })
                .ok_or_else(|| AcpError::State("removed relation name missing".into()))?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| AcpError::State("relation cleanup counter exhausted".into()))?;
            if self.store.has(&queue_key(sequence)) {
                return Err(AcpError::State(
                    "relation cleanup sequence already exists".into(),
                ));
            }
            let descriptor = RetiredRelation {
                sequence,
                generation: *generation,
                resource,
                relation,
            };
            let job = RelationJob {
                policy: policy.into(),
                generation: *generation,
            };
            changes.push((
                retired_relation_key(policy, *generation),
                Some(serde_json::to_vec(&descriptor).map_err(|e| AcpError::State(e.to_string()))?),
            ));
            changes.push((
                queue_key(sequence),
                Some(serde_json::to_vec(&job).map_err(|e| AcpError::State(e.to_string()))?),
            ));
        }
        if sequence != previous_sequence {
            changes.push((COUNTER_KEY.to_vec(), Some(sequence.to_be_bytes().to_vec())));
        }
        Ok((removed, changes))
    }
}
