//! Persistent policy retirement and fair, resumable cleanup scheduling.

use super::*;
use borsh::{BorshDeserialize, BorshSerialize};

pub(super) const RETIRED_PREFIX: &[u8] = b"policy/retired/";
pub(super) const QUEUE_PREFIX: &[u8] = b"policy/cleanup/queue/";
pub(super) const COUNTER_KEY: &[u8] = b"policy/cleanup/counter";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize)]
pub(super) enum Phase {
    Relationships,
    Commitments,
    Amendments,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub(super) struct RetiredPolicy {
    pub(super) sequence: u64,
    pub(super) phase: Phase,
}

pub(super) fn retired_key(policy: &str) -> Vec<u8> {
    [RETIRED_PREFIX, policy.as_bytes()].concat()
}

pub(super) fn queue_key(sequence: u64) -> Vec<u8> {
    [QUEUE_PREFIX, &sequence.to_be_bytes()].concat()
}

fn policy_id(bytes: &[u8]) -> Result<&str> {
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(AcpError::State("invalid retired policy identifier".into()));
    }
    std::str::from_utf8(bytes)
        .map_err(|_| AcpError::State("invalid retired policy identifier".into()))
}

pub(super) fn queue_sequence(key: &[u8]) -> Result<u64> {
    key.strip_prefix(QUEUE_PREFIX)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .filter(|sequence| *sequence != 0)
        .ok_or_else(|| AcpError::State("invalid policy cleanup queue key".into()))
}

impl Phase {
    pub(super) fn prefix(self, policy: &str) -> Vec<u8> {
        match self {
            Self::Relationships => keys::relationship_policy_prefix(policy),
            Self::Commitments => keys::commitment_policy_index_prefix(policy),
            Self::Amendments => keys::amendment_event_policy_index_prefix(policy),
        }
    }

    pub(super) const fn next(self) -> Option<Self> {
        match self {
            Self::Relationships => Some(Self::Commitments),
            Self::Commitments => Some(Self::Amendments),
            Self::Amendments => None,
        }
    }
}

impl AcpModule {
    /// Whether physical records remain scheduled for an already deleted policy.
    /// This is a local snapshot read, not independently certified evidence.
    pub fn policy_cleanup_pending(&self, policy: &str) -> Result<bool> {
        Ok(self.retired_policy(policy)?.is_some())
    }

    pub(super) fn retired_policy(&self, policy: &str) -> Result<Option<RetiredPolicy>> {
        self.store
            .get_ref(&retired_key(policy))
            .map(|bytes| {
                policy_id(policy.as_bytes())?;
                let retired: RetiredPolicy = borsh::from_slice(bytes)
                    .map_err(|error| AcpError::State(format!("invalid retired policy: {error}")))?;
                if retired.sequence == 0 {
                    return Err(AcpError::State("zero policy cleanup sequence".into()));
                }
                Ok(retired)
            })
            .transpose()
    }

    pub(super) fn cleanup_counter(&self) -> Result<u64> {
        self.store
            .get_ref(COUNTER_KEY)
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid policy cleanup counter".into()))
            })
            .transpose()
            .map(|counter| counter.unwrap_or(0))
    }

    fn next_cleanup_sequence(&self) -> Result<u64> {
        let next = self
            .cleanup_counter()?
            .checked_add(1)
            .ok_or_else(|| AcpError::State("policy cleanup counter exhausted".into()))?;
        if self.store.has(&queue_key(next)) {
            return Err(AcpError::State(
                "policy cleanup sequence already exists".into(),
            ));
        }
        Ok(next)
    }

    pub(super) fn retire_policy(&mut self, policy: &str) -> Result<()> {
        policy_id(policy.as_bytes())?;
        if self.retired_policy(policy)?.is_some() {
            return Err(AcpError::State("active policy is already retired".into()));
        }
        let retired = RetiredPolicy {
            sequence: self.next_cleanup_sequence()?,
            phase: Phase::Relationships,
        };
        self.store_retirement(policy, &retired)
    }

    fn store_retirement(&mut self, policy: &str, retired: &RetiredPolicy) -> Result<()> {
        let encoded = borsh::to_vec(retired)
            .map_err(|error| AcpError::State(format!("encode retired policy: {error}")))?;
        self.store.put(&retired_key(policy), encoded);
        self.store
            .put(&queue_key(retired.sequence), policy.as_bytes().to_vec());
        self.store
            .put(COUNTER_KEY, retired.sequence.to_be_bytes().to_vec());
        Ok(())
    }

    pub(super) fn requeue_retirement(
        &mut self,
        policy: &str,
        mut retired: RetiredPolicy,
    ) -> Result<()> {
        let previous = queue_key(retired.sequence);
        retired.sequence = self.next_cleanup_sequence()?;
        self.store_retirement(policy, &retired)?;
        self.store.delete(&previous);
        Ok(())
    }

    pub(super) fn cleanup_job(&self, key: &[u8], value: &[u8]) -> Result<(String, RetiredPolicy)> {
        let sequence = queue_sequence(key)?;
        let policy = policy_id(value)?;
        let retired = self
            .retired_policy(policy)?
            .ok_or_else(|| AcpError::State("policy cleanup marker missing".into()))?;
        if retired.sequence != sequence
            || sequence > self.cleanup_counter()?
            || self.store.has(&keys::policy_key(policy))
        {
            return Err(AcpError::State("policy cleanup queue mismatch".into()));
        }
        Ok((policy.into(), retired))
    }

    pub(super) fn retained_policy_allows(&self, policy: &str, phase: Phase) -> Result<bool> {
        if self.zanzibar_policies.contains_key(policy) {
            return Ok(true);
        }
        Ok(self
            .retired_policy(policy)?
            .is_some_and(|retired| retired.phase <= phase))
    }

    pub(super) fn validate_retirement_state(&self) -> Result<u64> {
        let counter = self.cleanup_counter()?;
        let mut count = 0u64;
        for (key, _) in self.store.prefix_iter(RETIRED_PREFIX) {
            let policy = policy_id(&key[RETIRED_PREFIX.len()..])?;
            let retired = self
                .retired_policy(policy)?
                .ok_or_else(|| AcpError::State("retired policy marker missing".into()))?;
            if retired.sequence > counter
                || self.store.has(&keys::policy_key(policy))
                || self.store.get_ref(&queue_key(retired.sequence)) != Some(policy.as_bytes())
            {
                return Err(AcpError::State(
                    "retired policy queue or counter mismatch".into(),
                ));
            }
            for phase in [Phase::Relationships, Phase::Commitments] {
                if phase < retired.phase
                    && self
                        .store
                        .prefix_iter(&phase.prefix(policy))
                        .next()
                        .is_some()
                {
                    return Err(AcpError::State(
                        "completed policy cleanup phase retains records".into(),
                    ));
                }
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| AcpError::State("retired policy count overflow".into()))?;
        }
        for (key, value) in self.store.prefix_iter(QUEUE_PREFIX) {
            let (_, retired) = self.cleanup_job(key, value)?;
            if retired.sequence > counter {
                return Err(AcpError::State(
                    "policy cleanup counter precedes queue".into(),
                ));
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
#[path = "retirement_tests.rs"]
mod tests;
