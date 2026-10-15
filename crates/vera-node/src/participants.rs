//! Committee selection from execution-derived epoch rosters.

use std::{num::NonZeroU64, sync::Arc};

use alloy_primitives::{Address, keccak256};
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    marshal::Identifier,
    types::{Epoch, Height},
};
use commonware_cryptography::ed25519;
use commonware_glue::dkg::ParticipantsProvider;
use commonware_utils::{ordered::Set, sequence::Unit};
use vera_domain::PublicKey;
use vera_executor::SharedModuleState;

/// Derive a stable validator EVM address from its ed25519 consensus key.
#[must_use]
pub fn validator_address(public_key: &PublicKey) -> Address {
    let encoded = commonware_codec::Encode::encode(public_key);
    let digest = keccak256(encoded);
    Address::from_slice(&digest[12..])
}

/// Future committees selected by finalized execution, independent of lookup time.
#[derive(Clone)]
pub struct RegistryParticipants {
    modules: SharedModuleState,
    genesis_players: Set<PublicKey>,
    history: Arc<crate::FinalizedHistory>,
    epoch_length: NonZeroU64,
    marshal: Option<crate::marshal_floor::VeraMarshal>,
}

impl std::fmt::Debug for RegistryParticipants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryParticipants")
            .field("epoch_length", &self.epoch_length)
            .field("genesis_players", &self.genesis_players)
            .finish_non_exhaustive()
    }
}

impl RegistryParticipants {
    /// Genesis supplies the lookahead until the first epoch boundary is finalized.
    #[must_use]
    pub const fn new(
        modules: SharedModuleState,
        genesis_players: Set<PublicKey>,
        history: Arc<crate::FinalizedHistory>,
        epoch_length: NonZeroU64,
    ) -> Self {
        Self {
            modules,
            genesis_players,
            history,
            epoch_length,
            marshal: None,
        }
    }
    pub(crate) fn with_marshal(mut self, marshal: crate::marshal_floor::VeraMarshal) -> Self {
        self.marshal = Some(marshal);
        self
    }
}

impl ParticipantsProvider for RegistryParticipants {
    type PublicKey = PublicKey;
    type Directory = Unit;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        if epoch.get() <= 2 {
            return self.genesis_players.clone();
        }
        let bytes = {
            let modules = self.modules.read().expect("module state lock poisoned");
            modules
                .vera
                .consensus_roster(epoch.get())
                .map(<[u8]>::to_vec)
        };
        let Some(bytes) = bytes else {
            // Height lookups return only finalized blocks. Their boundary payloads
            // provide the same roster before execution state is recovered.
            if let Some(marshal) = &self.marshal {
                let height = (epoch.get() - 1)
                    .checked_mul(self.epoch_length.get())
                    .and_then(|height| height.checked_sub(1))
                    .expect("consensus roster boundary overflow");
                if let Some(block) = marshal
                    .get_block(Identifier::Height(Height::new(height)))
                    .await
                {
                    return crate::history::roster_from_boundary(block.inner(), epoch, height)
                        .expect("finalized consensus roster must be valid");
                }
            }
            return self
                .history
                .consensus_roster(epoch, self.epoch_length)
                .expect("historical consensus roster must be readable")
                .expect("future consensus roster must have been finalized in the previous epoch");
        };
        assert!(
            !bytes.is_empty()
                && bytes.len().is_multiple_of(32)
                && bytes.len() / 32 <= vera_domain::MAX_DKG_PARTICIPANTS.get() as usize,
            "invalid consensus roster size"
        );
        let keys: Vec<_> = bytes
            .as_chunks::<32>()
            .0
            .iter()
            .map(|bytes| {
                ed25519::PublicKey::read(&mut commonware_codec::Copying(bytes.as_slice()))
                    .expect("invalid consensus identity")
            })
            .collect();
        assert!(
            keys.windows(2).all(|pair| pair[0] < pair[1]),
            "unordered consensus roster"
        );
        Set::from_iter_dedup(keys)
    }

    async fn directory(&mut self, _epoch: Epoch, _players: Set<Self::PublicKey>) -> Unit {
        Unit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;
    use vera_modules::{kv_store::InMemoryKvStore, vera::VeraModule};

    fn history() -> (tempfile::TempDir, Arc<crate::FinalizedHistory>) {
        let directory = tempfile::tempdir().unwrap();
        let genesis = vera_app::genesis_block(
            vera_domain::StateRoot(alloy_primitives::B256::ZERO),
            Default::default(),
            alloy_primitives::B256::ZERO,
        );
        let history = Arc::new(crate::FinalizedHistory::open(directory.path(), &genesis).unwrap());
        (directory, history)
    }

    fn key(encoded: &str) -> PublicKey {
        PublicKey::read(&mut commonware_codec::Copying(
            hex::decode(encoded).unwrap().as_slice(),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn roster_selection_survives_later_rosters_and_store_recovery() {
        let first = key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let second = key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let genesis = Set::from_iter_dedup([first.clone()]);
        let modules = Arc::new(RwLock::new(vera_modules::ModuleState::default()));
        let (_directory, history) = history();
        let mut provider = RegistryParticipants::new(
            modules.clone(),
            genesis.clone(),
            history.clone(),
            NonZeroU64::new(20).unwrap(),
        );
        assert_eq!(provider.participants(Epoch::new(2)).await, genesis);
        let raw = |key: &PublicKey| -> [u8; 32] {
            commonware_codec::Encode::encode(key)
                .as_ref()
                .try_into()
                .unwrap()
        };
        modules
            .write()
            .unwrap()
            .vera
            .record_consensus_roster(3, &[raw(&first)])
            .unwrap();
        let selected = provider.participants(Epoch::new(3)).await;
        assert!(
            modules
                .write()
                .unwrap()
                .vera
                .record_consensus_roster(3, &[raw(&second)])
                .is_err()
        );
        modules
            .write()
            .unwrap()
            .vera
            .record_consensus_roster(4, &[raw(&second)])
            .unwrap();
        assert_eq!(provider.participants(Epoch::new(3)).await, selected);
        let stored = modules.read().unwrap().vera.store().serialize();
        let recovered = vera_modules::ModuleState {
            vera: VeraModule::from_store(InMemoryKvStore::deserialize(&stored).unwrap()),
            ..Default::default()
        };
        let mut restarted = RegistryParticipants::new(
            Arc::new(RwLock::new(recovered)),
            genesis,
            history,
            NonZeroU64::new(20).unwrap(),
        );
        assert_eq!(restarted.participants(Epoch::new(3)).await, selected);
        assert_eq!(
            restarted.participants(Epoch::new(4)).await,
            Set::from_iter_dedup([second])
        );
        assert!(
            modules
                .write()
                .unwrap()
                .vera
                .record_consensus_roster(3, &[raw(&first)])
                .is_ok()
        );
        assert!(
            modules
                .write()
                .unwrap()
                .vera
                .record_consensus_roster(3, &[])
                .is_err()
        );
    }

    #[tokio::test]
    #[should_panic(expected = "future consensus roster must have been finalized")]
    async fn missing_roster_does_not_fall_back_to_genesis() {
        let genesis = Set::from_iter_dedup([key(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )]);
        let (_directory, history) = history();
        let mut provider = RegistryParticipants::new(
            Arc::new(RwLock::new(vera_modules::ModuleState::default())),
            genesis,
            history,
            NonZeroU64::new(20).unwrap(),
        );
        provider.participants(Epoch::new(3)).await;
    }
}
