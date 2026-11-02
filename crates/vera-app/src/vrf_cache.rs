//! Proposal randomness retained until its round is behind finality.

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{simplex::scheme::bls12381_threshold::vrf::Seed, types::Round};
use commonware_cryptography::{Hasher as _, Sha256, bls12381::primitives::variant::MinSig};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

#[derive(Debug)]
struct Entry {
    #[cfg(test)]
    digest: B256,
    witness: Option<Seed<MinSig>>,
}

#[derive(Debug, Default)]
struct Seeds {
    rounds: BTreeMap<Round, Entry>,
    finalized: Option<Round>,
}

/// Canonical threshold seeds supplied by the consensus elector before proposals
/// are built or verified. Finalized and newer rounds remain available.
#[derive(Clone, Debug, Default)]
pub struct VrfSeedCache(Arc<RwLock<Seeds>>);

impl VrfSeedCache {
    #[cfg(test)]
    pub(crate) fn insert(&self, round: Round, prevrandao: B256) {
        let mut seeds = self.0.write().expect("VRF seed cache lock poisoned");
        if seeds.finalized.is_none_or(|finalized| round >= finalized) {
            seeds.rounds.insert(
                round,
                Entry {
                    digest: prevrandao,
                    witness: None,
                },
            );
        }
    }

    /// Record the verified seed used to unlock the proposal round.
    pub fn insert_seed(&self, round: Round, seed: Seed<MinSig>) {
        let mut seeds = self.0.write().expect("VRF seed cache lock poisoned");
        if seeds.finalized.is_none_or(|finalized| round >= finalized) {
            seeds.rounds.insert(
                round,
                Entry {
                    #[cfg(test)]
                    digest: seed_digest(&seed),
                    witness: Some(seed),
                },
            );
        }
    }

    pub(crate) fn witness(&self, round: Round) -> Option<Seed<MinSig>> {
        self.0
            .read()
            .expect("VRF seed cache lock poisoned")
            .rounds
            .get(&round)
            .and_then(|entry| entry.witness.clone())
    }

    #[cfg(test)]
    pub(crate) fn get(&self, round: Round) -> Option<B256> {
        self.0
            .read()
            .expect("VRF seed cache lock poisoned")
            .rounds
            .get(&round)
            .map(|entry| entry.digest)
    }

    /// Discard rounds that can no longer extend the finalized execution.
    pub(crate) fn finalized(&self, round: Round) {
        let mut seeds = self.0.write().expect("VRF seed cache lock poisoned");
        if seeds.finalized.is_some_and(|finalized| round <= finalized) {
            return;
        }
        seeds.finalized = Some(round);
        while seeds
            .rounds
            .first_key_value()
            .is_some_and(|(oldest, _)| *oldest < round)
        {
            seeds.rounds.pop_first();
        }
    }
}

pub(crate) fn seed_digest(seed: &Seed<MinSig>) -> B256 {
    let encoded = seed.signature.encode();
    B256::from(Sha256::hash(&[encoded.as_ref()]).0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::{Epoch, View};

    fn round(epoch: u64, view: u64) -> Round {
        Round::new(Epoch::new(epoch), View::new(view))
    }

    #[test]
    fn finality_retires_old_seeds_without_losing_pending_rounds() {
        let cache = VrfSeedCache::default();
        let elector = cache.clone();
        for view in 1..=2_000 {
            elector.insert(round(0, view), B256::repeat_byte(1));
            cache.finalized(round(0, view));
            assert_eq!(cache.0.read().unwrap().rounds.len(), 1);
        }
        let pending = round(0, 2_001);
        let next_epoch = round(1, 1);
        elector.insert(pending, B256::repeat_byte(2));
        elector.insert(next_epoch, B256::repeat_byte(3));
        cache.finalized(round(0, 1_999));
        elector.insert(round(0, 1), B256::ZERO);
        assert_eq!(cache.0.read().unwrap().rounds.len(), 3);
        assert_eq!(cache.get(pending), Some(B256::repeat_byte(2)));
        assert!(cache.get(round(0, 1)).is_none());
        cache.finalized(next_epoch);
        assert_eq!(cache.0.read().unwrap().rounds.len(), 1);
        assert_eq!(cache.get(next_epoch), Some(B256::repeat_byte(3)));
        elector.insert(pending, B256::ZERO);
        assert!(cache.get(pending).is_none());
    }
}
