//! Deterministic cleanup quanta for logically deleted policies.

use super::*;
use retirement::{Phase, QUEUE_PREFIX, RetiredPolicy, queue_key, retired_key};

pub(super) const MAX_ITEMS: usize = 128;
pub(super) const MAX_BYTES: usize = 4 << 20;
pub(super) const MAX_WRITES: usize = 640;
pub(super) const MAX_JOBS: usize = 8;
pub(super) const JOB_ITEMS: usize = 16;
// The native QMDB codecs and application already enforce these record bounds.
const MAX_KEY_BYTES: usize = 64 << 10;
const MAX_RECORD_BYTES: usize = 1 << 20;
// Queue/marker/counter reads, writes and three empty-prefix probes for a 64-byte ID.
const JOB_METADATA_BYTES: usize = 1024;

enum CleanupResult {
    Complete,
    QuantumComplete,
    BudgetExhausted { made_progress: bool },
}

struct Budget {
    items: usize,
    bytes: usize,
    writes: usize,
}

impl Budget {
    const fn reserve(&mut self, items: usize, bytes: usize, writes: usize) -> bool {
        if self.items < items || self.bytes < bytes || self.writes < writes {
            return false;
        }
        self.items -= items;
        self.bytes -= bytes;
        self.writes -= writes;
        true
    }
}

fn record_size(key: &[u8], value: &[u8]) -> Result<usize> {
    if key.len() > MAX_KEY_BYTES || value.len() > MAX_RECORD_BYTES {
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
    pub(super) fn collect_retired_policies(&mut self) -> Result<()> {
        self.cleanup_counter()?;
        let mut budget = Budget {
            items: MAX_ITEMS,
            bytes: MAX_BYTES,
            writes: MAX_WRITES,
        };
        for _ in 0..MAX_JOBS {
            let Some((key, value)) = self.store.prefix_iter(QUEUE_PREFIX).next() else {
                break;
            };
            if !budget.reserve(0, JOB_METADATA_BYTES, 4) {
                break;
            }
            let (policy, mut retired) = self.cleanup_job(key, value)?;
            match self.cleanup_quantum(&policy, &mut retired, &mut budget)? {
                CleanupResult::Complete => {
                    self.store.delete(&queue_key(retired.sequence));
                    self.store.delete(&retired_key(&policy));
                }
                CleanupResult::QuantumComplete => self.requeue_retirement(&policy, retired)?,
                CleanupResult::BudgetExhausted { made_progress } => {
                    if made_progress {
                        self.requeue_retirement(&policy, retired)?;
                    }
                    // An unserved job keeps the front position for the next fresh budget.
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
                let Some(deletions) =
                    self.cleanup_item(policy, retired.phase, &prefix, key, value, budget)?
                else {
                    return Ok(CleanupResult::BudgetExhausted {
                        made_progress: removed > 0,
                    });
                };
                for key in deletions {
                    self.store.delete(&key);
                }
                break;
            }
        }
        Ok(CleanupResult::QuantumComplete)
    }

    fn cleanup_item(
        &self,
        policy: &str,
        phase: Phase,
        prefix: &[u8],
        key: &[u8],
        value: &[u8],
        budget: &mut Budget,
    ) -> Result<Option<Vec<Vec<u8>>>> {
        if !budget.reserve(1, record_size(key, value)?, 0) {
            return Ok(None);
        }
        let deletions = match phase {
            Phase::Relationships => {
                let record: RelationshipRecord =
                    serde_json::from_slice(value).map_err(|error| {
                        AcpError::State(format!("invalid cleanup relationship: {error}"))
                    })?;
                if record.policy_id != policy
                    || keys::relationship_key(
                        policy,
                        &keys::relationship_storage_key(&record.relationship),
                    ) != key
                {
                    return Err(AcpError::State(
                        "cleanup relationship identity mismatch".into(),
                    ));
                }
                vec![key.to_vec()]
            }
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
        let write_bytes = deletions.iter().try_fold(0usize, |bytes, key| {
            bytes
                .checked_add(record_size(key, &[])?)
                .ok_or_else(|| AcpError::State("policy cleanup byte overflow".into()))
        })?;
        if !budget.reserve(0, write_bytes, deletions.len()) {
            return Ok(None);
        }
        Ok(Some(deletions))
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
