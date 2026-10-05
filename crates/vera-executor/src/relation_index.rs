use std::collections::{BTreeMap, BTreeSet};

use vera_domain::relation_index::{
    RELATION_INDEX_VERSION, RELATION_INDEX_VERSION_KEY, relation_count_key, relation_prefixes,
};
use vera_modules::kv_store::InMemoryKvStore;
use vera_state::TreeSnapshot;

use crate::ExecutionError;

type Entries = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// Add derived index changes to the same branch-local update as the ACP records.
pub(crate) fn index_relationships(
    parent: &TreeSnapshot,
    current: &InMemoryKvStore,
    entries: &mut Entries,
) -> Result<(), ExecutionError> {
    let mut seen = BTreeSet::new();
    for (key, _) in entries.iter() {
        if key.first() == Some(&0) || !seen.insert(key.as_slice()) {
            return Err(invalid("reserved or repeated ACP record key"));
        }
    }
    let version = parent
        .get(RELATION_INDEX_VERSION_KEY)
        .map_err(storage_error)?;
    let initializing = match version.as_deref() {
        None => true,
        Some(RELATION_INDEX_VERSION) => false,
        Some(_) => return Err(invalid("unsupported relationship index version")),
    };
    let mut deltas = BTreeMap::<Vec<u8>, i128>::new();
    if initializing {
        // Activation is part of the selected revision, never an out-of-band disk rewrite.
        for (key, _) in current.prefix_iter(vera_modules::acp::keys::RELATIONSHIP_PREFIX) {
            for prefix in relation_prefixes(key) {
                *deltas.entry(relation_count_key(prefix)).or_default() += 1;
            }
        }
    } else {
        for (key, value) in entries.iter() {
            if !key.starts_with(vera_modules::acp::keys::RELATIONSHIP_PREFIX) {
                continue;
            }
            let existed = parent.get(key).map_err(storage_error)?.is_some();
            let delta = i128::from(value.is_some()) - i128::from(existed);
            if delta == 0 {
                continue;
            }
            for prefix in relation_prefixes(key) {
                *deltas.entry(relation_count_key(prefix)).or_default() += delta;
            }
        }
    }
    let mut derived = Vec::with_capacity(deltas.len() + usize::from(initializing));
    for (key, delta) in deltas {
        if delta == 0 {
            continue;
        }
        let old = if initializing {
            0
        } else {
            parent
                .get(&key)
                .map_err(storage_error)?
                .map(|bytes| {
                    bytes
                        .try_into()
                        .map(u64::from_be_bytes)
                        .map_err(|_| invalid("invalid relationship count"))
                })
                .transpose()?
                .unwrap_or(0)
        };
        let count = u64::try_from(i128::from(old) + delta)
            .map_err(|_| invalid("relationship count overflow or underflow"))?;
        derived.push((key, (count != 0).then(|| count.to_be_bytes().to_vec())));
    }
    if initializing {
        derived.push((
            RELATION_INDEX_VERSION_KEY.to_vec(),
            Some(RELATION_INDEX_VERSION.to_vec()),
        ));
    }
    entries.extend(derived);
    Ok(())
}

fn invalid(message: &str) -> ExecutionError {
    ExecutionError::ModuleTree(message.into())
}

fn storage_error(error: impl std::fmt::Display) -> ExecutionError {
    ExecutionError::ModuleTree(error.to_string())
}

#[cfg(test)]
mod tests;
