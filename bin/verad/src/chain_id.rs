//! Chain ID selection for locally generated networks.

use vera_genesis::VeraGenesis;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("--chain-id {flag} conflicts with chain ID {genesis} of the genesis file")]
pub(crate) struct ChainIdConflict {
    flag: u64,
    genesis: u64,
}

/// Settle the chain ID a generated network's genesis and node configuration share.
///
/// A built-in genesis takes the flag's value. A genesis read from a file keeps
/// its own, which the flag may repeat but not change.
pub(crate) const fn reconcile(
    genesis: &mut VeraGenesis,
    from_file: bool,
    flag: Option<u64>,
) -> Result<u64, ChainIdConflict> {
    match flag {
        Some(flag) if from_file && flag != genesis.chain_id => {
            return Err(ChainIdConflict {
                flag,
                genesis: genesis.chain_id,
            });
        }
        Some(flag) => genesis.chain_id = flag,
        None => {}
    }
    Ok(genesis.chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_genesis_takes_the_flag_and_a_file_rejects_a_different_one() {
        let built_in = VeraGenesis::devnet().chain_id;

        let mut genesis = VeraGenesis::devnet();
        assert_eq!(reconcile(&mut genesis, false, None), Ok(built_in));
        assert_eq!(reconcile(&mut genesis, false, Some(1234)), Ok(1234));
        assert_eq!(genesis.chain_id, 1234);

        assert_eq!(reconcile(&mut genesis, true, None), Ok(1234));
        assert_eq!(reconcile(&mut genesis, true, Some(1234)), Ok(1234));
        assert_eq!(
            reconcile(&mut genesis, true, Some(built_in)),
            Err(ChainIdConflict {
                flag: built_in,
                genesis: 1234
            })
        );
        assert_eq!(genesis.chain_id, 1234);
    }
}
