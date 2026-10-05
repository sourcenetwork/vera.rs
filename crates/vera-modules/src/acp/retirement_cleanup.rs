//! Deterministic cleanup quanta for logically deleted policies.

use super::*;
use crate::kv_store::{NATIVE_MAX_KEY_BYTES, NATIVE_MAX_VALUE_BYTES};
use retirement::{Phase, QUEUE_PREFIX, RetiredPolicy, queue_key, retired_key};

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

    pub(super) fn changes(&mut self, changes: &[record_store::RecordChange]) -> Result<bool> {
        let bytes = changes.iter().try_fold(0usize, |total, (key, value)| {
            total
                .checked_add(record_size(key, value.as_deref().unwrap_or_default())?)
                .ok_or_else(|| AcpError::State("cleanup write size overflow".into()))
        })?;
        Ok(self.reserve(1, bytes, changes.len()))
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
        for removed in 0..JOB_ITEMS {
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
                let Some(changes) =
                    self.cleanup_item(policy, retired, &prefix, key, value, budget)?
                else {
                    return Ok(CleanupResult::BudgetExhausted {
                        made_progress: removed > 0,
                    });
                };
                record_store::RecordStore::apply_records(&mut self.store, changes)
                    .map_err(relation_state_error)?;
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
        if phase == Phase::Relationships {
            return self.prepare_cleanup_relationship(key, budget);
        }
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
        if !budget.changes(&changes)? {
            return Ok(None);
        }
        Ok(Some(changes))
    }

    pub(super) fn prepare_cleanup_relationship(
        &self,
        key: &[u8],
        budget: &mut Budget,
    ) -> Result<Option<Vec<record_store::RecordChange>>> {
        let bytes = self
            .store
            .get_ref(key)
            .ok_or_else(|| AcpError::State("cleanup relationship missing".into()))?;
        record_size(key, bytes)?;
        let capture = read_capture::ReadCapture::new(
            self.store.clone(),
            read_capture::ReadLimits {
                reads: 16,
                records: 16,
                bytes: budget.bytes,
            },
        );
        let prepared = relationship_mutations::prepare_removals(&capture, &[key.to_vec()]);
        let Some(remaining) = capture.remaining_limits() else {
            budget.bytes = 0;
            return Ok(None);
        };
        budget.bytes = remaining.bytes;
        let changes = prepared.map_err(relation_state_error)?;
        if !budget.changes(&changes)? {
            return Ok(None);
        }
        Ok(Some(changes))
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
