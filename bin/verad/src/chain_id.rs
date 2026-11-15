//! Chain ID selection for locally generated networks.

use std::path::Path;

use vera_config::{ConfigError, NodeConfig};
use vera_genesis::VeraGenesis;

/// A chain ID the operator asked for, and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Requested {
    Flag(u64),
    ConfigFile(u64),
}

impl Requested {
    /// The flag wins over the configuration file, which counts only when it states a chain ID.
    pub(crate) fn from_inputs(
        flag: Option<u64>,
        config: Option<&Path>,
    ) -> Result<Option<Self>, ConfigError> {
        match (flag, config) {
            (Some(flag), _) => Ok(Some(Self::Flag(flag))),
            (None, Some(path)) => Ok(NodeConfig::stated_chain_id(path)?.map(Self::ConfigFile)),
            (None, None) => Ok(None),
        }
    }

    const fn value(self) -> u64 {
        match self {
            Self::Flag(value) | Self::ConfigFile(value) => value,
        }
    }
}

impl std::fmt::Display for Requested {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Flag(value) => write!(f, "--chain-id {value}"),
            Self::ConfigFile(value) => write!(f, "configuration file chain_id {value}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{requested} conflicts with chain ID {genesis} of the genesis file")]
pub(crate) struct ChainIdConflict {
    requested: Requested,
    genesis: u64,
}

/// Settle the chain ID a generated network's genesis and node configuration share.
///
/// A built-in genesis takes the requested value. A genesis read from a file
/// keeps its own, which a request may repeat but not change.
pub(crate) const fn reconcile(
    genesis: &mut VeraGenesis,
    from_file: bool,
    requested: Option<Requested>,
) -> Result<u64, ChainIdConflict> {
    match requested {
        Some(requested) if from_file && requested.value() != genesis.chain_id => {
            return Err(ChainIdConflict {
                requested,
                genesis: genesis.chain_id,
            });
        }
        Some(requested) => genesis.chain_id = requested.value(),
        None => {}
    }
    Ok(genesis.chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_genesis_takes_the_request_and_a_file_rejects_a_different_one() {
        let built_in = VeraGenesis::devnet().chain_id;

        for request in [Requested::Flag, Requested::ConfigFile] {
            let mut genesis = VeraGenesis::devnet();
            assert_eq!(reconcile(&mut genesis, false, None), Ok(built_in));
            assert_eq!(
                reconcile(&mut genesis, false, Some(request(1234))),
                Ok(1234)
            );
            assert_eq!(genesis.chain_id, 1234);

            assert_eq!(reconcile(&mut genesis, true, None), Ok(1234));
            assert_eq!(reconcile(&mut genesis, true, Some(request(1234))), Ok(1234));
            assert_eq!(
                reconcile(&mut genesis, true, Some(request(built_in))),
                Err(ChainIdConflict {
                    requested: request(built_in),
                    genesis: 1234
                })
            );
            assert_eq!(genesis.chain_id, 1234);
        }
    }

    #[test]
    fn configuration_file_requests_only_the_chain_id_it_states() {
        let directory =
            std::env::temp_dir().join(format!("verad-requested-chain-id-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let stating = directory.join("stating.toml");
        let silent = directory.join("silent.toml");
        std::fs::write(&stating, "chain_id = 1234\n").unwrap();
        std::fs::write(&silent, "data_dir = \"/tmp/vera\"\n").unwrap();

        assert_eq!(
            Requested::from_inputs(None, Some(&stating)).unwrap(),
            Some(Requested::ConfigFile(1234))
        );
        assert_eq!(Requested::from_inputs(None, Some(&silent)).unwrap(), None);
        assert_eq!(
            Requested::from_inputs(Some(7), Some(&stating)).unwrap(),
            Some(Requested::Flag(7))
        );
        assert_eq!(Requested::from_inputs(None, None).unwrap(), None);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn conflict_names_where_the_chain_id_was_requested() {
        let mut genesis = VeraGenesis::devnet();
        let genesis_id = genesis.chain_id;
        let mut message = |requested| {
            reconcile(&mut genesis, true, Some(requested))
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            message(Requested::Flag(5)),
            format!("--chain-id 5 conflicts with chain ID {genesis_id} of the genesis file")
        );
        assert_eq!(
            message(Requested::ConfigFile(5)),
            format!(
                "configuration file chain_id 5 conflicts with chain ID {genesis_id} of the genesis file"
            )
        );
    }
}
