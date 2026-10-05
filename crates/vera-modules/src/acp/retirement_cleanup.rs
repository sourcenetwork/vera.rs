//! Deterministic cleanup quanta for logically deleted policies.

use super::*;
use crate::kv_store::{NATIVE_MAX_KEY_BYTES, NATIVE_MAX_VALUE_BYTES};
use retirement::{Phase, QUEUE_PREFIX, RetiredPolicy, queue_key, retired_key};
use std::collections::BTreeSet;

pub(super) const MAX_ITEMS: usize = 128;
pub(super) const MAX_BYTES: usize = 4 << 20;
pub(super) const MAX_WRITES: usize = 640;
pub(super) const MAX_JOBS: usize = 8;
pub(super) const JOB_ITEMS: usize = 16;

enum CleanupResult {
    Complete,
    QuantumComplete,
    BudgetExhausted { made_progress: bool },
}

pub(super) struct Budget {
    pub(super) items: usize,
    pub(super) bytes: usize,
    pub(super) writes: usize,
    jobs: usize,
}

impl Budget {
    pub(super) const fn new() -> Self {
        Self {
            items: MAX_ITEMS,
            bytes: MAX_BYTES,
            writes: MAX_WRITES,
            jobs: MAX_JOBS,
        }
    }

    pub(super) const fn reserve(&mut self, items: usize, bytes: usize, writes: usize) -> bool {
        if self.items < items || self.bytes < bytes || self.writes < writes {
            return false;
        }
        self.items -= items;
        self.bytes -= bytes;
        self.writes -= writes;
        true
    }

    pub(super) fn start_job(&mut self, bytes: usize, writes: usize) -> Result<bool> {
        if bytes > MAX_BYTES || writes > MAX_WRITES {
            return Err(AcpError::State(
                "cleanup job exceeds the per-block budget".into(),
            ));
        }
        if self.jobs == 0 || !self.reserve(0, bytes, writes) {
            return Ok(false);
        }
        self.jobs -= 1;
        Ok(true)
    }

    pub(super) fn changes(
        &mut self,
        items: usize,
        changes: &[record_store::RecordChange],
    ) -> Result<bool> {
        let bytes = changes.iter().try_fold(0usize, |total, (key, value)| {
            total
                .checked_add(record_size(key, value.as_deref().unwrap_or_default())?)
                .ok_or_else(|| AcpError::State("cleanup write size overflow".into()))
        })?;
        Ok(self.reserve(items, bytes, changes.len()))
    }
}

pub(super) fn record_size(key: &[u8], value: &[u8]) -> Result<usize> {
    if key.len() > NATIVE_MAX_KEY_BYTES || value.len() > NATIVE_MAX_VALUE_BYTES {
        return Err(AcpError::State(
            "policy cleanup record exceeds native storage bounds".into(),
        ));
    }
    Ok(key.len() + value.len())
}

fn indexed_id(prefix: &[u8], key: &[u8], value: &[u8]) -> Result<u64> {
    key.strip_prefix(prefix)
        .and_then(|suffix| suffix.try_into().ok())
        .map(u64::from_be_bytes)
        .filter(|id| *id != 0 && value.is_empty())
        .ok_or_else(|| AcpError::State("invalid policy cleanup record index".into()))
}

impl AcpModule {
    pub(super) fn collect_retired_policies(&mut self, budget: &mut Budget) -> Result<()> {
        self.cleanup_counter()?;
        loop {
            let Some((key, value)) = self.store.prefix_iter(QUEUE_PREFIX).next() else {
                break;
            };
            let policy = retirement::policy_id(value)?;
            let marker_key = retired_key(policy);
            let marker = self
                .store
                .get_ref(&marker_key)
                .ok_or_else(|| AcpError::State("policy cleanup marker missing".into()))?;
            // Marker read and possible rewrite, queue read/requeue, counter and phase probes.
            let bytes = 2 * record_size(&marker_key, marker)? + 2 * record_size(key, value)? + 1024;
            if !budget.start_job(bytes, 4)? {
                break;
            }
            let (policy, mut retired) = self.cleanup_job(key, value)?;
            match self.cleanup_quantum(&policy, &mut retired, budget)? {
                CleanupResult::Complete => {
                    self.store.delete(&queue_key(retired.sequence));
                    self.store.delete(&retired_key(&policy));
                }
                CleanupResult::QuantumComplete => self.requeue_retirement(&policy, retired)?,
                CleanupResult::BudgetExhausted { made_progress } => {
                    if made_progress {
                        self.requeue_retirement(&policy, retired)?;
                    }
                    break;
                }
            }
            if budget.items == 0 {
                break;
            }
        }
        Ok(())
    }

    fn cleanup_quantum(
        &mut self,
        policy: &str,
        retired: &mut RetiredPolicy,
        budget: &mut Budget,
    ) -> Result<CleanupResult> {
        let mut removed = 0;
        while removed < JOB_ITEMS {
            loop {
                let prefix = retired.phase.prefix(policy);
                let Some((key, value)) = self.store.prefix_iter(&prefix).next() else {
                    match retired.phase.next() {
                        Some(phase) => {
                            retired.phase = phase;
                            continue;
                        }
                        None => return Ok(CleanupResult::Complete),
                    }
                };
                let batch = if retired.phase == Phase::Relationships {
                    self.prepare_cleanup_relationships(
                        policy,
                        None,
                        key,
                        JOB_ITEMS - removed,
                        budget,
                    )?
                } else {
                    self.cleanup_item(policy, retired, &prefix, key, value, budget)?
                        .map(|changes| (1, changes))
                };
                let Some((items, changes)) = batch else {
                    return Ok(CleanupResult::BudgetExhausted {
                        made_progress: removed > 0,
                    });
                };
                record_store::RecordStore::apply_records(&mut self.store, changes)
                    .map_err(relation_state_error)?;
                removed += items;
                break;
            }
        }
        Ok(CleanupResult::QuantumComplete)
    }

    fn cleanup_item(
        &self,
        policy: &str,
        retired: &RetiredPolicy,
        prefix: &[u8],
        key: &[u8],
        value: &[u8],
        budget: &mut Budget,
    ) -> Result<Option<Vec<record_store::RecordChange>>> {
        let phase = retired.phase;
        if !budget.reserve(0, record_size(key, value)?, 0) {
            return Ok(None);
        }
        let deletions = match phase {
            Phase::Relationships => unreachable!(),
            Phase::RelationshipsMetadata => match self.cleanup_relationship_metadata(
                policy,
                &retired.relations,
                key,
                value,
                budget,
            )? {
                Some(deletions) => deletions,
                None => return Ok(None),
            },
            Phase::Commitments => {
                let id = indexed_id(prefix, key, value)?;
                let record_key = keys::commitment_key(id);
                let bytes = self
                    .store
                    .get_ref(&record_key)
                    .ok_or_else(|| AcpError::State("cleanup commitment missing".into()))?;
                if !budget.reserve(0, record_size(&record_key, bytes)?, 0) {
                    return Ok(None);
                }
                let record = self
                    .get_commitment_by_id(id)?
                    .ok_or_else(|| AcpError::State("cleanup commitment missing".into()))?;
                if record.policy_id != policy {
                    return Err(AcpError::State("cleanup commitment policy mismatch".into()));
                }
                let keys = self.commitment_cleanup_keys(&record)?;
                if !budget.reserve(0, keys[2].len() + keys[3].len(), 0) {
                    return Ok(None);
                }
                keys
            }
            Phase::Amendments => {
                let id = indexed_id(prefix, key, value)?;
                let record_key = keys::amendment_event_key(id);
                let bytes = self
                    .store
                    .get_ref(&record_key)
                    .ok_or_else(|| AcpError::State("cleanup amendment missing".into()))?;
                if !budget.reserve(0, record_size(&record_key, bytes)?, 0) {
                    return Ok(None);
                }
                let event = self
                    .retained_amendment_by_id(id)?
                    .ok_or_else(|| AcpError::State("cleanup amendment missing".into()))?;
                if event.policy_id != policy {
                    return Err(AcpError::State("cleanup amendment policy mismatch".into()));
                }
                vec![key.to_vec(), record_key]
            }
        };
        let changes: Vec<_> = deletions.into_iter().map(|key| (key, None)).collect();
        if !budget.changes(1, &changes)? {
            return Ok(None);
        }
        Ok(Some(changes))
    }

    /// Prepare a byte-fitting prefix of one physical pair without crossing a job quantum.
    /// `generation` is absent only for a logically deleted policy; otherwise the caller
    /// has validated that this generation is retired in the current policy catalogue.
    pub(super) fn prepare_cleanup_relationships(
        &self,
        policy: &str,
        generation: Option<u64>,
        first_key: &[u8],
        limit: usize,
        budget: &mut Budget,
    ) -> Result<Option<(usize, Vec<record_store::RecordChange>)>> {
        let pair = cleanup_pair(policy, first_key)?;
        if generation.is_some_and(|id| pair.target != id && pair.subject != id) {
            return Err(AcpError::State(
                "cleanup relationship is not retired".into(),
            ));
        }
        let policy_key = keys::policy_key(policy);
        let policy_bytes = self.store.get_ref(&policy_key);
        if policy_bytes.is_some() != generation.is_some() {
            return Err(AcpError::State("cleanup policy state mismatch".into()));
        }
        let counters = [
            relationship_index::outgoing_key(policy, pair),
            relationship_index::incoming_key(policy, pair),
        ];
        let mut read_bytes = record_size(&policy_key, policy_bytes.unwrap_or_default())?;
        let mut write_bytes = 0;
        for key in &counters {
            let value = self.store.get_ref(key).unwrap_or_default();
            if value.len() != 8 {
                return Err(AcpError::State(
                    "cleanup pair counter missing or invalid".into(),
                ));
            }
            read_bytes += record_size(key, value)?;
            // A surviving pair writes eight bytes; an exhausted pair writes only its key.
            write_bytes += key.len() + 8;
        }
        let Some(mut available) = budget.bytes.checked_sub(read_bytes + write_bytes) else {
            return Ok(None);
        };
        let limit = limit
            .min(JOB_ITEMS)
            .min(budget.items)
            .min(budget.writes.saturating_sub(2));
        let prefix = keys::relationship_generation_prefix(policy, pair, "");
        let mut selected = Vec::new();
        let mut object_counters = BTreeSet::new();
        for (key, value) in self.store.prefix_iter(&prefix).take(limit) {
            let mut cost = record_size(key, value)? + key.len();
            let counter = object_pairs::key_from_relationship(policy, pair, key)
                .map_err(relation_state_error)?;
            let distinct = !object_counters.contains(&counter);
            if selected.len() + 1 + 2 + object_counters.len() + usize::from(distinct)
                > budget.writes
            {
                break;
            }
            if distinct {
                let value = self
                    .store
                    .get_ref(&counter)
                    .ok_or_else(|| AcpError::State("cleanup object counter missing".into()))?;
                relationship_index::decode_count(value).map_err(relation_state_error)?;
                cost += record_size(&counter, value)? + counter.len() + 8;
            }
            let Some(remaining) = available.checked_sub(cost) else {
                break;
            };
            selected.push(key.to_vec());
            object_counters.insert(counter);
            available = remaining;
        }
        if selected.is_empty() {
            return Ok(None);
        }
        if selected[0] != first_key {
            return Err(AcpError::State("cleanup skipped a relationship".into()));
        }
        let capture = read_capture::ReadCapture::new(
            self.store.clone(),
            read_capture::ReadLimits {
                reads: selected.len() + 3 + object_counters.len(),
                records: selected.len() + 3 + object_counters.len(),
                bytes: budget.bytes,
            },
        );
        let changes = relationship_mutations::prepare_removals(&capture, &selected)
            .map_err(relation_state_error)?;
        budget.bytes = capture
            .remaining_limits()
            .ok_or_else(|| AcpError::State("cleanup batch exceeded its read allowance".into()))?
            .bytes;
        if !budget.changes(selected.len(), &changes)? {
            return Err(AcpError::State(
                "cleanup batch exceeded its write allowance".into(),
            ));
        }
        Ok(Some((selected.len(), changes)))
    }

    pub(super) fn commitment_cleanup_keys(
        &self,
        record: &RegistrationsCommitment,
    ) -> Result<Vec<Vec<u8>>> {
        let keys = vec![
            keys::commitment_policy_index_key(&record.policy_id, record.id),
            keys::commitment_key(record.id),
            keys::commitment_by_commitment_index_key(&record.commitment, record.id),
            Self::commitment_expiry_key(record),
        ];
        for key in [&keys[0], &keys[2]] {
            if self.store.get_ref(key) != Some(&[]) {
                return Err(AcpError::State("cleanup commitment index mismatch".into()));
            }
        }
        if self.store.get_ref(&keys[3]) != if record.expired { None } else { Some(&[]) } {
            return Err(AcpError::State("cleanup commitment expiry mismatch".into()));
        }
        Ok(keys)
    }
}

fn cleanup_pair(policy: &str, key: &[u8]) -> Result<RelationPair> {
    let prefix = keys::relationship_policy_prefix(policy);
    let suffix = key
        .strip_prefix(prefix.as_slice())
        .filter(|suffix| suffix.len() >= 34 && suffix[16] == b'/' && suffix[33] == b'/')
        .ok_or_else(|| AcpError::State("invalid cleanup relationship key".into()))?;
    Ok(RelationPair {
        target: relation_cleanup::generation_suffix(&[], &suffix[..16])?,
        subject: relation_cleanup::generation_suffix(&[], &suffix[17..33])?,
    })
}

#[cfg(test)]
#[path = "retirement_cleanup_tests.rs"]
mod tests;
