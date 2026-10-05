//! Mirrored physical pair counts and authenticated current subject directories.

use std::collections::BTreeMap;

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

fn decode_count(bytes: &[u8]) -> Result<u64> {
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
    let active = relations.active_ids();
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
/// `(pair, increase, amount)` includes zero-amount validation for metadata rewrites.
pub(super) fn prepare_counts<S: RecordStore>(
    store: &S,
    policy: &str,
    deltas: &[(RelationPair, bool, u64)],
    relations: Option<&RelationGenerations>,
) -> Result<Vec<RecordChange>> {
    let mut changes = Vec::new();
    let mut directories = BTreeMap::new();
    for (pair, increase, amount) in deltas {
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
        if let Some(relations) = relations
            && relations.contains(pair.target)
            && relations.contains(pair.subject)
        {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                directories.entry(pair.target)
            {
                entry.insert((live_pairs(store, policy, pair.target, relations)?, false));
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
            let value = (next > 0).then(|| next.to_be_bytes().to_vec());
            changes.push((outgoing_key(policy, *pair), value.clone()));
            changes.push((incoming_key(policy, *pair), value));
        }
    }
    for (target, (subjects, changed)) in directories {
        if !changed {
            continue;
        }
        let value = if subjects.is_empty() {
            None
        } else {
            Some(serde_json::to_vec(&subjects)?)
        };
        changes.push((active_key(policy, target), value));
    }
    Ok(changes)
}

pub(super) fn invalid(message: &str) -> Error {
    Error::Serialization(message.into())
}
