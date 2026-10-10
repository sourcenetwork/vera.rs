//! Operator-selected checkpoint and age checks for a certified native policy read.

use std::{num::NonZeroU64, time::SystemTime};

use commonware_codec::Copying;
use serde::Serialize;
use vera_client::{ClientError, VeraClient};

#[derive(clap::Args, Debug)]
pub(crate) struct ReadCheckArgs {
    /// Existing policy selected independently of the endpoint.
    #[arg(long)]
    pub(crate) policy_id: String,
    /// Consensus public key from authenticated deployment configuration (hex).
    #[arg(long)]
    pub(crate) trusted_key: String,
    /// Positive finalized checkpoint obtained independently of the endpoint.
    #[arg(long)]
    pub(crate) minimum_revision: NonZeroU64,
    /// Maximum age of the certified revision in seconds, measured against local time.
    #[arg(long)]
    pub(crate) max_age_seconds: NonZeroU64,
    /// Accepted future timestamp skew in seconds.
    #[arg(long, default_value_t = 5)]
    pub(crate) max_future_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadCheckError {
    #[error("invalid trusted consensus key hex")]
    KeyHex(#[from] hex::FromHexError),
    #[error("invalid trusted consensus key encoding")]
    KeyEncoding(#[from] commonware_codec::Error),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("selected policy is absent at the certified revision")]
    MissingPolicy,
    #[error("certified revision exceeds the configured age limit")]
    StaleRevision,
    #[error("certified revision exceeds the configured future timestamp tolerance")]
    FutureRevision,
    #[error("local clock precedes the Unix epoch")]
    Clock(#[from] std::time::SystemTimeError),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadCheckReport {
    policy_id: String,
    revision: u64,
    timestamp: u64,
    checked_at: u64,
}

impl ReadCheckArgs {
    pub(crate) async fn run(&self, client: &VeraClient) -> Result<ReadCheckReport, ReadCheckError> {
        let policy = vera_client::parse_policy_id(&self.policy_id)?;
        let bytes = hex::decode(
            self.trusted_key
                .strip_prefix("0x")
                .unwrap_or(&self.trusted_key),
        )?;
        let trusted = commonware_codec::DecodeExt::decode(Copying(bytes.as_slice()))?;
        let record = client
            .read_policy(policy, self.minimum_revision.get(), &trusted)
            .await?;
        if record.value.is_none() {
            return Err(ReadCheckError::MissingPolicy);
        }
        let checked_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        check_age(
            record.timestamp,
            checked_at,
            self.max_age_seconds.get(),
            self.max_future_seconds,
        )?;
        Ok(ReadCheckReport {
            policy_id: format!("{policy:x}"),
            revision: record.revision,
            timestamp: record.timestamp,
            checked_at,
        })
    }
}

const fn check_age(
    timestamp: u64,
    now: u64,
    maximum_age: u64,
    maximum_future: u64,
) -> Result<(), ReadCheckError> {
    if timestamp.saturating_sub(now) > maximum_future {
        return Err(ReadCheckError::FutureRevision);
    }
    if now.saturating_sub(timestamp) > maximum_age {
        return Err(ReadCheckError::StaleRevision);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn certified_read_age_includes_boundaries_without_overflow() {
        assert!(check_age(100, 130, 30, 5).is_ok());
        assert!(matches!(
            check_age(100, 131, 30, 5),
            Err(ReadCheckError::StaleRevision)
        ));
        assert!(check_age(105, 100, 30, 5).is_ok());
        assert!(matches!(
            check_age(106, 100, 30, 5),
            Err(ReadCheckError::FutureRevision)
        ));
        assert!(check_age(u64::MAX, u64::MAX, 30, 5).is_ok());
        assert!(matches!(
            check_age(0, u64::MAX, 30, 5),
            Err(ReadCheckError::StaleRevision)
        ));
        assert!(matches!(
            check_age(u64::MAX, 0, 30, 5),
            Err(ReadCheckError::FutureRevision)
        ));
    }

    #[tokio::test]
    async fn invalid_read_check_trust_is_rejected_before_transport() {
        let client = VeraClient::new("http://127.0.0.1:1");
        let mut args = ReadCheckArgs {
            policy_id: "00".repeat(32),
            trusted_key: "invalid hex".into(),
            minimum_revision: NonZeroU64::MIN,
            max_age_seconds: NonZeroU64::MIN,
            max_future_seconds: 0,
        };
        assert!(matches!(
            args.run(&client).await,
            Err(ReadCheckError::KeyHex(_))
        ));
        args.trusted_key = "00".into();
        assert!(matches!(
            args.run(&client).await,
            Err(ReadCheckError::KeyEncoding(_))
        ));
    }

    #[test]
    fn certified_read_requires_independent_positive_checkpoint_and_age() {
        let prefix = [
            "verad",
            "client",
            "check-read",
            "--policy-id",
            "00",
            "--trusted-key",
            "00",
        ];
        assert!(crate::cli::Cli::try_parse_from(prefix).is_err());
        for (checkpoint, age) in [("0", "30"), ("1", "0")] {
            let mut args = prefix.to_vec();
            args.extend(["--minimum-revision", checkpoint, "--max-age-seconds", age]);
            assert!(crate::cli::Cli::try_parse_from(args).is_err());
        }
        let mut args = prefix.to_vec();
        args.extend(["--minimum-revision", "1", "--max-age-seconds", "30"]);
        assert!(crate::cli::Cli::try_parse_from(args).is_ok());
    }
}
