//! Atomic physical relationship and pair-index mutations after caller authorization.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    keys, object_pairs, object_state,
    record_store::{RecordChange, RecordStore},
    relationship_index::{self, invalid},
    types::{PolicyRecord, RelationPair, RelationshipRecord},
};
use zanzibar::error::{Error, Result};

pub(super) fn put<S: RecordStore>(store: &mut S, record: &RelationshipRecord) -> Result<()> {
    let changes = prepare_put(store, record)?;
    store.apply_records(changes)
}

pub(super) fn prepare_put<S: RecordStore>(
    store: &S,
    record: &RelationshipRecord,
) -> Result<Vec<RecordChange>> {
    let policy = current_policy(store, &record.policy_id)?
        .ok_or_else(|| Error::PolicyNotFound(record.policy_id.clone()))?;
    if policy.relations.pair(&record.relationship)? != record.generations {
        return Err(invalid(
            "relationship generations differ from current policy",
        ));
    }
    if object_state::for_relationship(store, &record.policy_id, &record.relationship)?
        != record.incarnation
    {
        return Err(invalid("relationship incarnation is not current"));
    }
    let key = record_key(record);
    let existing = store.read_record(&key)?;
    if let Some(existing) = &existing {
        let previous = decode_record(&key, existing)?;
        if previous.policy_id != record.policy_id || previous.relationship != record.relationship {
            return Err(invalid("relationship key collision"));
        }
    }
    let primary = store.prepare_json(&key, record)?;
    let mut changes = relationship_index::prepare_counts(
        store,
        &record.policy_id,
        &[(
            record.generations,
            true,
            u64::from(existing.is_none()),
            u64::from(existing.is_none()),
        )],
        Some(&policy.relations),
        true,
    )?;
    if let Some(change) = object_pairs::prepare_change(
        store,
        object_pairs::key(record),
        true,
        u64::from(existing.is_none()),
    )? {
        changes.push(change);
    }
    changes.push(primary);
    Ok(changes)
}

pub(super) fn remove<S: RecordStore>(store: &mut S, key: &[u8]) -> Result<()> {
    let changes = prepare_removal_keys(store, std::iter::once(key), None)?;
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
    prepare_removal_keys(store, keys.iter().map(Vec::as_slice), None)
}

pub(super) fn prepare_removals_with_catalog<S: RecordStore>(
    store: &S,
    keys: &[Vec<u8>],
    retired: Option<(&str, &super::RelationGenerations)>,
) -> Result<Vec<RecordChange>> {
    prepare_removal_keys(store, keys.iter().map(Vec::as_slice), retired)
}

fn prepare_removal_keys<'a, S: RecordStore>(
    store: &S,
    keys: impl IntoIterator<Item = &'a [u8]>,
    retired: Option<(&str, &super::RelationGenerations)>,
) -> Result<Vec<RecordChange>> {
    let mut seen = BTreeSet::new();
    let mut policies = BTreeMap::new();
    let mut counts: BTreeMap<String, BTreeMap<RelationPair, (u64, u64)>> = BTreeMap::new();
    let mut object_counts = BTreeMap::<Vec<u8>, u64>::new();
    let mut incarnations = BTreeMap::new();
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
        let current_incarnation = if record.relationship.relation == "owner" {
            0
        } else {
            let state_key = object_state::key(
                &record.policy_id,
                &record.relationship.resource,
                &record.relationship.object_id,
            );
            *match incarnations.entry(state_key) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                    object_state::for_relationship(store, &record.policy_id, &record.relationship)?,
                ),
            }
        };
        if record.incarnation > current_incarnation {
            return Err(invalid("relationship incarnation was never allocated"));
        }
        let catalog = policies[&record.policy_id]
            .as_ref()
            .map(|policy| &policy.relations)
            .or_else(|| {
                retired
                    .filter(|(id, _)| *id == record.policy_id)
                    .map(|(_, catalog)| catalog)
            });
        let current_pair = catalog.is_none_or(|catalog| {
            catalog.contains(record.generations.target)
                && catalog.contains(record.generations.subject)
        });
        let current = current_pair && record.incarnation == current_incarnation;
        let count = counts
            .entry(record.policy_id.clone())
            .or_default()
            .entry(record.generations)
            .or_default();
        count.0 = count
            .0
            .checked_add(1)
            .ok_or_else(|| invalid("relationship removal count overflow"))?;
        count.1 = count
            .1
            .checked_add(u64::from(current))
            .ok_or_else(|| invalid("logical relationship removal count overflow"))?;
        let count = object_counts.entry(object_pairs::key(&record)).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| invalid("object relationship removal count overflow"))?;
        changes.push(store.prepare_write(key, None)?);
    }
    for (policy, pairs) in counts {
        let deltas: Vec<_> = pairs
            .into_iter()
            .map(|(pair, (physical, logical))| (pair, false, physical, logical))
            .collect();
        changes.extend(relationship_index::prepare_counts(
            store,
            &policy,
            &deltas,
            policies[&policy]
                .as_ref()
                .map(|record| &record.relations)
                .or_else(|| {
                    retired
                        .filter(|(id, _)| *id == policy)
                        .map(|(_, catalog)| catalog)
                }),
            policies[&policy].is_some(),
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
        &keys::relationship_storage_key(&record.relationship, record.incarnation),
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
