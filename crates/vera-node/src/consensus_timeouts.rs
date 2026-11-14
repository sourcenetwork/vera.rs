//! Ordering Simplex requires of the consensus timeouts.

use std::time::Duration;

/// A timeout combination Simplex refuses by aborting its engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TimeoutError {
    #[error("{}", self.reason())]
    LeaderZero,
    #[error("{}", self.reason())]
    CertificationNotAboveLeader,
    #[error("{}", self.reason())]
    RetryZero,
    #[error("{}", self.reason())]
    StallNotAboveCertification,
}

impl TimeoutError {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::LeaderZero => "leader timeout must be positive",
            Self::CertificationNotAboveLeader => {
                "notarization timeout must be longer than the leader timeout"
            }
            Self::RetryZero => "nullify retry interval must be positive",
            Self::StallNotAboveCertification => {
                "notarization timeout must be shorter than the genesis stall timeout"
            }
        }
    }
}

/// Check the timeouts before any actor starts.
///
/// `stall` is the genesis stall timeout of a deployment whose leaders hold terms.
pub(crate) fn validate(
    leader: Duration,
    certification: Duration,
    retry: Duration,
    stall: Option<Duration>,
) -> Result<(), TimeoutError> {
    if leader.is_zero() {
        return Err(TimeoutError::LeaderZero);
    }
    if certification <= leader {
        return Err(TimeoutError::CertificationNotAboveLeader);
    }
    if retry.is_zero() {
        return Err(TimeoutError::RetryZero);
    }
    if stall.is_some_and(|stall| stall <= certification) {
        return Err(TimeoutError::StallNotAboveCertification);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn daemon_defaults_pass_with_the_default_stall_timeout() {
        assert_eq!(
            validate(ms(1_000), ms(2_000), ms(500), Some(ms(5_000))),
            Ok(())
        );
        assert_eq!(validate(ms(1_000), ms(2_000), ms(500), None), Ok(()));
    }

    #[test]
    fn each_ordering_simplex_asserts_is_rejected() {
        for (leader, certification, retry, stall, expected) in [
            (0, 2_000, 500, None, TimeoutError::LeaderZero),
            (
                2_000,
                2_000,
                500,
                None,
                TimeoutError::CertificationNotAboveLeader,
            ),
            (1_000, 2_000, 0, None, TimeoutError::RetryZero),
            (
                1_000,
                5_000,
                500,
                Some(5_000),
                TimeoutError::StallNotAboveCertification,
            ),
        ] {
            assert_eq!(
                validate(ms(leader), ms(certification), ms(retry), stall.map(ms)),
                Err(expected)
            );
        }
    }
}
