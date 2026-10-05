//! Atomic physical relationship and pair-index mutations after caller authorization.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    keys, object_pairs,
    record_store::{RecordChange, RecordStore},
    relationship_index::{self, invalid},
    types::{PolicyRecord, RelationPair, RelationshipRecord},
};
use zanzibar::error::{Error, Result};

pub(super) fn put<S: RecordStore>(store: &mut S, record: &RelationshipRecord) -> Result<()> {
    let policy = current_policy(store, &record.policy_id)?
        .ok_or_else(|| Error::PolicyNotFound(record.policy_id.clone()))?;
    if policy.relations.pair(&record.relationship)? != record.generations {
        return Err(invalid(
            "relationship generations differ from current policy",
        ));
    }
    let key = record_key(record);
    let existing = store.read_record(&key)?;
    if let Some(existing) = &existing {
        let previous = decode_record(&key, existing)?;
        if previous.policy_id != record.policy_id || previous.relationship != record.relationship {
            return Err(invalid("relationship key collision"));
        }
    }
    let encoded = serde_json::to_vec(record)?;
    let mut changes = relationship_index::prepare_counts(
        store,
        &record.policy_id,
        &[(record.generations, true, u64::from(existing.is_none()))],
        Some(&policy.relations),
    )?;
    if let Some(change) = object_pairs::prepare_change(
        store,
        object_pairs::key(record),
        true,
        u64::from(existing.is_none()),
    )? {
        changes.push(change);
    }
    changes.push((key, Some(encoded)));
    store.apply_records(changes)
}

pub(super) fn remove<S: RecordStore>(store: &mut S, key: &[u8]) -> Result<()> {
    let changes = prepare_removals(store, &[key.to_vec()])?;
    if changes.is_empty() {
        return Ok(());
    }
    store.apply_records(changes)
}

/// Prepare all removals and combined pair deltas before the caller's atomic apply.
/// The caller may append other prepared records to the same atomic change set.
pub(super) fn prepare_removals<S: RecordStore>(
    store: &S,
    keys: &[Vec<u8>],
) -> Result<Vec<RecordChange>> {
    let mut seen = BTreeSet::new();
    let mut policies = BTreeMap::new();
    let mut counts: BTreeMap<String, BTreeMap<RelationPair, u64>> = BTreeMap::new();
    let mut object_counts = BTreeMap::<Vec<u8>, u64>::new();
    let mut changes = Vec::new();
    for key in keys {
        if !seen.insert(key) {
            return Err(invalid("duplicate relationship removal"));
        }
        let Some(bytes) = store.read_record(key)? else {
            continue;
        };
        let record = decode_record(key, &bytes)?;
        if let std::collections::btree_map::Entry::Vacant(entry) =
            policies.entry(record.policy_id.clone())
        {
            entry.insert(current_policy(store, &record.policy_id)?);
        }
        if let Some(policy) = &policies[&record.policy_id] {
            if record.generations.target >= policy.relations.next
                || record.generations.subject >= policy.relations.next
            {
                return Err(invalid("relationship generation was never allocated"));
            }
            if policy.relations.contains(record.generations.target)
                && policy.relations.contains(record.generations.subject)
                && policy.relations.pair(&record.relationship)? != record.generations
            {
                return Err(invalid(
                    "relationship generations differ from current policy",
                ));
            }
        }
        let count = counts
            .entry(record.policy_id.clone())
            .or_default()
            .entry(record.generations)
            .or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| invalid("relationship removal count overflow"))?;
        let count = object_counts.entry(object_pairs::key(&record)).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| invalid("object relationship removal count overflow"))?;
        changes.push((key.clone(), None));
    }
    for (policy, pairs) in counts {
        let deltas: Vec<_> = pairs
            .into_iter()
            .map(|(pair, count)| (pair, false, count))
            .collect();
        changes.extend(relationship_index::prepare_counts(
            store,
            &policy,
            &deltas,
            policies[&policy].as_ref().map(|record| &record.relations),
        )?);
    }
    for (key, count) in object_counts {
        if let Some(change) = object_pairs::prepare_change(store, key, false, count)? {
            changes.push(change);
        }
    }
    Ok(changes)
}

fn current_policy<S: RecordStore>(store: &S, id: &str) -> Result<Option<PolicyRecord>> {
    store
        .read_record(&keys::policy_key(id))?
        .map(|bytes| {
            let policy: PolicyRecord = serde_json::from_slice(&bytes)?;
            if policy.policy.id != id {
                return Err(invalid("policy record identity mismatch"));
            }
            policy.relations.validate(&policy.policy)?;
            Ok(policy)
        })
        .transpose()
}

fn record_key(record: &RelationshipRecord) -> Vec<u8> {
    keys::relationship_generation_key(
        &record.policy_id,
        record.generations,
        &keys::relationship_storage_key(&record.relationship),
    )
}

fn decode_record(key: &[u8], bytes: &[u8]) -> Result<RelationshipRecord> {
    let record: RelationshipRecord = serde_json::from_slice(bytes)?;
    if record_key(&record) != key {
        return Err(invalid(
            "relationship record differs from its generation key",
        ));
    }
    Ok(record)
}

#[cfg(test)]
#[path = "relationship_index_tests.rs"]
mod tests;
