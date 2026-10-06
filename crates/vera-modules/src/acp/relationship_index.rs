//! Physical pair counts, current logical counts and authenticated subject directories.

use std::collections::{BTreeMap, BTreeSet};

use zanzibar::error::{Error, Result};

use super::{
    record_store::{RecordChange, RecordStore},
    types::{RelationGenerations, RelationPair},
};

/// Namespace containing relationship counts and current pair directories.
pub const PREFIX: &[u8] = b"relation_state/";

/// All relationship index records belonging to a policy.
pub fn policy_prefix(policy: &str) -> Vec<u8> {
    format!("relation_state/{policy}/").into_bytes()
}

/// All physical outgoing pair counters for a policy.
pub fn outgoing_policy_prefix(policy: &str) -> Vec<u8> {
    format!("relation_state/{policy}/out/").into_bytes()
}

/// All physical incoming pair counters for a policy.
pub fn incoming_policy_prefix(policy: &str) -> Vec<u8> {
    format!("relation_state/{policy}/in/").into_bytes()
}

/// Physical pair counters selected by their target generation.
pub fn outgoing_prefix(policy: &str, target: u64) -> Vec<u8> {
    format!("relation_state/{policy}/out/{target:016x}/").into_bytes()
}

/// Physical pair counters selected by their subject generation.
pub fn incoming_prefix(policy: &str, subject: u64) -> Vec<u8> {
    format!("relation_state/{policy}/in/{subject:016x}/").into_bytes()
}

/// Outgoing physical count for one generation pair.
pub fn outgoing_key(policy: &str, pair: RelationPair) -> Vec<u8> {
    format!(
        "relation_state/{policy}/out/{:016x}/{:016x}",
        pair.target, pair.subject
    )
    .into_bytes()
}

/// Mirrored incoming physical count for one generation pair.
pub fn incoming_key(policy: &str, pair: RelationPair) -> Vec<u8> {
    format!(
        "relation_state/{policy}/in/{:016x}/{:016x}",
        pair.subject, pair.target
    )
    .into_bytes()
}

/// Logical counts for relation pairs still current in the policy catalogue.
/// Retired policies retain these counters until their physical rows are removed.
pub fn logical_policy_prefix(policy: &str) -> Vec<u8> {
    format!("relation_state/{policy}/logical/").into_bytes()
}

/// Current logical count, independent of the physical cleanup counters.
pub fn logical_key(policy: &str, pair: RelationPair) -> Vec<u8> {
    format!(
        "relation_state/{policy}/logical/{:016x}/{:016x}",
        pair.target, pair.subject
    )
    .into_bytes()
}

/// Read a logical count. Current pairs retain zero while physical rows remain.
pub fn read_logical_count<S: RecordStore>(
    store: &S,
    policy: &str,
    pair: RelationPair,
) -> Result<u64> {
    read_logical_record(store, policy, pair).map(|count| count.unwrap_or(0))
}

pub(super) fn decode_logical_count(bytes: &[u8]) -> Result<u64> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| invalid("logical relationship count must contain eight bytes"))
}

pub(super) fn read_logical_record<S: RecordStore>(
    store: &S,
    policy: &str,
    pair: RelationPair,
) -> Result<Option<u64>> {
    store
        .read_record(&logical_key(policy, pair))?
        .as_deref()
        .map(decode_logical_count)
        .transpose()
}

/// All current subject directories for a policy.
pub fn active_prefix(policy: &str) -> Vec<u8> {
    format!("relation_state/{policy}/active/").into_bytes()
}

/// Sorted unique JSON subject generations currently retained under one target.
pub fn active_key(policy: &str, target: u64) -> Vec<u8> {
    format!("relation_state/{policy}/active/{target:016x}").into_bytes()
}

/// Read a physical count, requiring both mirrors and omitting zero-valued rows.
pub fn read_pair_count<S: RecordStore>(store: &S, policy: &str, pair: RelationPair) -> Result<u64> {
    let outgoing = store.read_record(&outgoing_key(policy, pair))?;
    let incoming = store.read_record(&incoming_key(policy, pair))?;
    match (outgoing, incoming) {
        (None, None) => Ok(0),
        (Some(outgoing), Some(incoming)) => {
            let count = decode_count(&outgoing)?;
            if decode_count(&incoming)? != count {
                return Err(invalid("relationship pair count mirrors differ"));
            }
            Ok(count)
        }
        _ => Err(invalid("relationship pair count mirror missing")),
    }
}

pub(super) fn decode_count(bytes: &[u8]) -> Result<u64> {
    let count = bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| invalid("relationship pair count must contain eight bytes"))?;
    if count == 0 {
        return Err(invalid("zero relationship pair count must be omitted"));
    }
    Ok(count)
}

/// Read current subjects without scanning physical counters of retired generations.
///
/// Restoration and indexed mutation guarantee directory completeness and positive
/// mirrored counts. Queries authenticate only this directory and current identities;
/// they do not require a separate counter proof for every returned subject.
pub fn live_pairs<S: RecordStore>(
    store: &S,
    policy: &str,
    target: u64,
    relations: &RelationGenerations,
) -> Result<Vec<u64>> {
    live_pairs_for_active(store, policy, target, &relations.active_ids())
}

pub(crate) fn live_pairs_for_active<S: RecordStore>(
    store: &S,
    policy: &str,
    target: u64,
    active: &BTreeSet<u64>,
) -> Result<Vec<u64>> {
    if !active.contains(&target) {
        return Err(invalid("relationship directory target is inactive"));
    }
    let Some(bytes) = store.read_record(&active_key(policy, target))? else {
        return Ok(Vec::new());
    };
    if bytes.len() > crate::kv_store::NATIVE_MAX_VALUE_BYTES {
        return Err(invalid("relationship directory exceeds record bounds"));
    }
    let subjects: Vec<u64> = serde_json::from_slice(&bytes)?;
    if subjects.is_empty() || subjects.windows(2).any(|ids| ids[0] >= ids[1]) {
        return Err(invalid(
            "relationship directory must be nonempty, sorted and unique",
        ));
    }
    for subject in &subjects {
        if !active.contains(subject) {
            return Err(invalid(
                "relationship directory contains an inactive subject",
            ));
        }
    }
    Ok(subjects)
}

/// Prepare count changes for distinct pairs without mutating storage.
/// Each delta carries physical and current-logical amounts. Zero-amount plans
/// still validate existing counters for metadata rewrites.
pub(super) fn prepare_counts<S: RecordStore>(
    store: &S,
    policy: &str,
    deltas: &[(RelationPair, bool, u64, u64)],
    relations: Option<&RelationGenerations>,
    update_directories: bool,
) -> Result<Vec<RecordChange>> {
    let mut changes = Vec::new();
    let mut directories = BTreeMap::new();
    let active = relations.map(RelationGenerations::active_ids);
    for (pair, increase, amount, logical_amount) in deltas {
        let previous = read_pair_count(store, policy, *pair)?;
        if *amount == 0 && previous == 0 {
            return Err(invalid("stored relationship has no physical pair count"));
        }
        let next = if *increase {
            previous.checked_add(*amount)
        } else {
            previous.checked_sub(*amount)
        }
        .ok_or_else(|| invalid("relationship pair count overflow or underflow"))?;
        let current = active
            .as_ref()
            .map(|ids| ids.contains(&pair.target) && ids.contains(&pair.subject));
        if let Some(change) = prepare_logical_count(
            store,
            policy,
            *pair,
            (previous, next),
            current,
            (*increase, *logical_amount),
            *amount == 0,
        )? {
            changes.push(change);
        }
        if update_directories
            && let Some(active) = &active
            && active.contains(&pair.target)
            && active.contains(&pair.subject)
        {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                directories.entry(pair.target)
            {
                entry.insert((
                    live_pairs_for_active(store, policy, pair.target, active)?,
                    false,
                ));
            }
            let (subjects, changed) = directories.get_mut(&pair.target).expect("directory loaded");
            let present = subjects.binary_search(&pair.subject);
            if present.is_ok() != (previous > 0) {
                return Err(invalid(
                    "relationship directory differs from physical pair count",
                ));
            }
            match (present, next > 0) {
                (Ok(index), false) => {
                    subjects.remove(index);
                    *changed = true;
                }
                (Err(index), true) => {
                    subjects.insert(index, pair.subject);
                    *changed = true;
                }
                _ => {}
            }
        }
        if previous != next {
            let encoded = next.to_be_bytes();
            let value = (next > 0).then_some(encoded.as_slice());
            changes.push(store.prepare_write(&outgoing_key(policy, *pair), value)?);
            changes.push(store.prepare_write(&incoming_key(policy, *pair), value)?);
        }
    }
    for (target, (subjects, changed)) in directories {
        if !changed {
            continue;
        }
        let key = active_key(policy, target);
        changes.push(if subjects.is_empty() {
            store.prepare_write(&key, None)?
        } else {
            store.prepare_json(&key, &subjects)?
        });
    }
    Ok(changes)
}

/// Prepare logical deltas independently of the physical cleanup count.
fn prepare_logical_count<S: RecordStore>(
    store: &S,
    policy: &str,
    pair: RelationPair,
    physical: (u64, u64),
    current: Option<bool>,
    delta: (bool, u64),
    metadata_rewrite: bool,
) -> Result<Option<RecordChange>> {
    let stored = read_logical_record(store, policy, pair)?;
    let previous = stored.unwrap_or(0);
    if previous > physical.0
        || (current == Some(false) && stored.is_some())
        || (current == Some(true) && stored.is_some() != (physical.0 > 0))
    {
        return Err(invalid(
            "logical relationship count differs from current rows",
        ));
    }
    if current == Some(false) || (current.is_none() && stored.is_none()) {
        return Ok(None);
    }
    if metadata_rewrite && previous == 0 {
        return Err(invalid("current relationship has no logical pair count"));
    }
    let next = if delta.0 {
        previous.checked_add(delta.1)
    } else {
        previous.checked_sub(delta.1)
    }
    .filter(|next| *next <= physical.1)
    .ok_or_else(|| invalid("logical relationship count overflow or underflow"))?;
    if previous == next && physical.1 > 0 {
        return Ok(None);
    }
    let encoded = next.to_be_bytes();
    store
        .prepare_write(
            &logical_key(policy, pair),
            (physical.1 > 0).then_some(encoded.as_slice()),
        )
        .map(Some)
}

/// Subtract a current object's grants while retaining its physical rows.
pub(super) fn prepare_archive_count<S: RecordStore>(
    store: &S,
    policy: &str,
    pair: RelationPair,
    amount: u64,
) -> Result<RecordChange> {
    let physical = read_pair_count(store, policy, pair)?;
    prepare_logical_count(
        store,
        policy,
        pair,
        (physical, physical),
        Some(true),
        (false, amount),
        false,
    )?
    .ok_or_else(|| invalid("archive must remove a positive logical count"))
}

pub(super) fn invalid(message: &str) -> Error {
    Error::Serialization(message.into())
}
