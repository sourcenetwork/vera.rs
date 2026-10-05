//! Policy edits invalidate immutable relation identities without scanning objects.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
        budget: &PolicyEditBudget,
    ) -> Result<(u64, Vec<RecordChange>)> {
        if retired.is_empty() {
            return Ok((0, Vec::new()));
        }
        let records = policy_edit_budget::EditRecords {
            store: &self.store,
            budget,
        };
        let mut removed = 0u64;
        let mut changes = Vec::new();
        let old_active = old.active_ids();
        let new_active = new.active_ids();
        let retired_names: BTreeMap<_, _> = old
            .active
            .iter()
            .flat_map(|(resource, relations)| {
                relations.iter().map(move |(relation, generation)| {
                    (*generation, (resource.as_str(), relation.as_str()))
                })
            })
            .filter(|(generation, _)| retired.contains(generation))
            .collect();
        for &target in &old_active {
            let subjects =
                relationship_index::live_pairs_for_active(&records, policy, target, &old_active)
                    .map_err(relation_state_error)?;
            let mut remaining = Vec::new();
            for subject in &subjects {
                budget.pair()?;
                if retired.contains(&target) || retired.contains(subject) {
                    let pair = RelationPair {
                        target,
                        subject: *subject,
                    };
                    let physical = relationship_index::read_pair_count(&records, policy, pair)
                        .map_err(relation_state_error)?;
                    if physical == 0 {
                        return Err(AcpError::State(
                            "live relation directory has no physical records".into(),
                        ));
                    }
                    let count = relationship_index::read_logical_count(&records, policy, pair)
                        .map_err(relation_state_error)?;
                    if count != physical {
                        return Err(AcpError::State(
                            "logical relationship count differs from current rows".into(),
                        ));
                    }
                    let key = relationship_index::logical_key(policy, pair);
                    budget.write(&key, None)?;
                    changes.push((key, None));
                    removed = removed.checked_add(count).ok_or_else(|| {
                        AcpError::State("removed relationship count overflow".into())
                    })?;
                } else {
                    remaining.push(*subject);
                }
            }
            if remaining != subjects {
                let value = if remaining.is_empty() {
                    budget.write(&relationship_index::active_key(policy, target), None)?;
                    None
                } else {
                    Some(
                        budget
                            .encode(&relationship_index::active_key(policy, target), &remaining)?,
                    )
                };
                changes.push((relationship_index::active_key(policy, target), value));
            }
        }
        let mut sequence = records
            .read_record(COUNTER_KEY)
            .map_err(relation_state_error)?
            .as_deref()
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
            if new_active.contains(generation) || *generation == 0 || *generation >= old.next {
                return Err(AcpError::State(
                    "invalid removed relation generation".into(),
                ));
            }
            if records
                .read_record(&retired_relation_key(policy, *generation))
                .map_err(relation_state_error)?
                .is_some()
            {
                return Err(AcpError::State(
                    "relation generation is already retired".into(),
                ));
            }
            let physical = records
                .first_exists(&relationship_index::outgoing_prefix(policy, *generation))?
                || records
                    .first_exists(&relationship_index::incoming_prefix(policy, *generation))?;
            if !physical {
                continue;
            }
            let (resource, relation) = retired_names
                .get(generation)
                .copied()
                .ok_or_else(|| AcpError::State("removed relation name missing".into()))?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| AcpError::State("relation cleanup counter exhausted".into()))?;
            if records
                .read_record(&queue_key(sequence))
                .map_err(relation_state_error)?
                .is_some()
            {
                return Err(AcpError::State(
                    "relation cleanup sequence already exists".into(),
                ));
            }
            let descriptor = RetiredRelation {
                sequence,
                generation: *generation,
                resource: resource.to_owned(),
                relation: relation.to_owned(),
            };
            let job = RelationJob {
                policy: policy.into(),
                generation: *generation,
            };
            changes.push((
                retired_relation_key(policy, *generation),
                Some(budget.encode(&retired_relation_key(policy, *generation), &descriptor)?),
            ));
            changes.push((
                queue_key(sequence),
                Some(budget.encode(&queue_key(sequence), &job)?),
            ));
        }
        if sequence != previous_sequence {
            budget.write(COUNTER_KEY, Some(&sequence.to_be_bytes()))?;
            changes.push((COUNTER_KEY.to_vec(), Some(sequence.to_be_bytes().to_vec())));
        }
        Ok((removed, changes))
    }
}
