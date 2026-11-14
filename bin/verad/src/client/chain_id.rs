//! Chain ID a client command signs for.

pub(super) const ENVIRONMENT: &str = "VERA_CHAIN_ID";
const DEFAULT: u64 = 9001;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum ChainIdError {
    #[error("--client-chain-id {client} conflicts with --chain-id {global}")]
    Conflict { client: u64, global: u64 },
    #[error("invalid VERA_CHAIN_ID")]
    Environment(#[from] std::num::ParseIntError),
}

/// Either flag beats the environment, so an exported value cannot override an explicit one.
pub(super) fn resolve(
    client: Option<u64>,
    global: Option<u64>,
    environment: Option<&str>,
) -> Result<u64, ChainIdError> {
    match (client, global) {
        (Some(client), Some(global)) if client != global => {
            Err(ChainIdError::Conflict { client, global })
        }
        (Some(chain_id), _) | (None, Some(chain_id)) => Ok(chain_id),
        (None, None) => Ok(environment.map(str::parse).transpose()?.unwrap_or(DEFAULT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_beat_the_environment_and_must_agree() {
        assert_eq!(resolve(None, None, None), Ok(DEFAULT));
        assert_eq!(resolve(None, None, Some("7")), Ok(7));
        assert_eq!(resolve(None, Some(1234), Some("7")), Ok(1234));
        assert_eq!(resolve(Some(42), None, Some("7")), Ok(42));
        assert_eq!(resolve(Some(42), Some(42), None), Ok(42));
        assert_eq!(
            resolve(Some(42), Some(1234), None),
            Err(ChainIdError::Conflict {
                client: 42,
                global: 1234
            })
        );
        assert!(matches!(
            resolve(None, None, Some("mainnet")),
            Err(ChainIdError::Environment(_))
        ));
        assert_eq!(resolve(Some(42), None, Some("mainnet")), Ok(42));
    }
}
