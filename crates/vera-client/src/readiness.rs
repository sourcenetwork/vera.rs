use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use vera_domain::{ConsensusPublicKey, LightBlock};

use crate::{ClientError, VeraClient};

/// Failures while checking certified read progress.
#[derive(Debug, thiserror::Error)]
pub enum ReadinessError {
    /// A required bound is zero or cannot form an observation deadline.
    #[error("checkpoint, maximum age and observation timeout must be positive")]
    InvalidOptions,
    /// The endpoint has not published the operator-required checkpoint.
    #[error("published revision is below the required checkpoint")]
    BehindCheckpoint,
    /// The reported revision moved backwards during observation.
    #[error("published revision regressed during observation")]
    Regressed,
    /// An authenticated revision exceeds the permitted clock/age bounds.
    #[error("certified revision timestamp is stale or too far in the future")]
    Timestamp,
    /// The entire observation exhausted its deadline.
    #[error("no certified advancement within the observation deadline")]
    Deadline,
    /// The bounded transport or independent certificate verification failed.
    #[error("readiness RPC or proof verification failed")]
    Client(#[from] ClientError),
    /// The local clock cannot supply a Unix timestamp.
    #[error("local clock is before the Unix epoch")]
    Clock(#[from] std::time::SystemTimeError),
}

/// Two fresh, authenticated revisions observed through one endpoint.
/// This establishes read progress, not an individual member's voting participation.
#[derive(Debug, Serialize)]
pub struct VerifiedReadiness {
    /// First authenticated published revision.
    pub initial_height: u64,
    /// Later authenticated revision observed before the deadline.
    pub height: u64,
    /// Certified Unix timestamp of the later revision.
    pub timestamp: u64,
    /// Verified hash of the later revision.
    pub block_hash: String,
}

const fn check_timestamp(
    timestamp: u64,
    now: u64,
    maximum_age: Duration,
) -> Result<(), ReadinessError> {
    if timestamp > now.saturating_add(5) || now.saturating_sub(timestamp) > maximum_age.as_secs() {
        return Err(ReadinessError::Timestamp);
    }
    Ok(())
}

fn check_revision(revision: &LightBlock, maximum_age: Duration) -> Result<(), ReadinessError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    check_timestamp(revision.timestamp, now, maximum_age)
}

impl VeraClient {
    /// Require fresh certified advancement above an operator-provided checkpoint.
    /// Provision `trusted_key` independently; neither RPC status nor response key
    /// material establishes trust. Five seconds of future clock skew are tolerated.
    /// Success requires finishing all RPC requests, proof verification and waits
    /// within the timeout. Bounded synchronous proof validation is not preempted.
    pub async fn verify_readiness(
        &self,
        trusted_key: &ConsensusPublicKey,
        minimum_height: u64,
        maximum_age: Duration,
        observation_timeout: Duration,
    ) -> Result<VerifiedReadiness, ReadinessError> {
        let started = std::time::Instant::now();
        if minimum_height == 0
            || maximum_age.as_secs() == 0
            || observation_timeout.is_zero()
            || started.checked_add(observation_timeout).is_none()
        {
            return Err(ReadinessError::InvalidOptions);
        }
        let result = tokio::time::timeout(observation_timeout, async {
            let initial_height = self.block_number().await?;
            if initial_height < minimum_height {
                return Err(ReadinessError::BehindCheckpoint);
            }
            let initial = self
                .read_finalized_revision(initial_height, trusted_key)
                .await?;
            check_revision(&initial, maximum_age)?;
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let height = self.block_number().await?;
                if height < initial.height {
                    return Err(ReadinessError::Regressed);
                }
                if height > initial.height {
                    let revision = self.read_finalized_revision(height, trusted_key).await?;
                    check_revision(&revision, maximum_age)?;
                    return Ok(VerifiedReadiness {
                        initial_height: initial.height,
                        height: revision.height,
                        timestamp: revision.timestamp,
                        block_hash: revision.block_hash,
                    });
                }
            }
        })
        .await
        .map_err(|_| ReadinessError::Deadline)?;
        if started.elapsed() >= observation_timeout {
            return Err(ReadinessError::Deadline);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_future_and_extreme_timestamps_fail_closed() {
        let age = Duration::from_secs(30);
        for timestamp in [0, 969, 1006, u64::MAX] {
            assert!(matches!(
                check_timestamp(timestamp, 1000, age),
                Err(ReadinessError::Timestamp)
            ));
        }
        for timestamp in [970, 1000, 1005] {
            check_timestamp(timestamp, 1000, age).unwrap();
        }
        check_timestamp(u64::MAX, u64::MAX, age).unwrap();
    }
}
