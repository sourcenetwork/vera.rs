//! Secret store of a lone validator whose share the host holds.

use std::collections::BTreeMap;

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::DealerPrivMsg, primitives::group::Share},
    transcript::Summary,
};
use commonware_glue::dkg;

/// In-memory [`dkg::SecretStore`] serving one share for every epoch.
///
/// A committee of one reshares to itself with a constant polynomial: the
/// dealing it sends itself and the share of the next epoch are both the share
/// it started with. The store therefore answers any epoch from that share and
/// keeps nothing durable. A dealing received before a restart is rebuilt from
/// the share, because the ceremony's journal still records its acknowledgement.
pub(crate) struct HeldSecretStore {
    share: Share,
    local: Vec<u8>,
    seeds: BTreeMap<Epoch, Summary>,
}

impl HeldSecretStore {
    pub(crate) fn new(local: &impl PublicKey, share: Share) -> Self {
        Self {
            share,
            local: local.encode().to_vec(),
            seeds: BTreeMap::new(),
        }
    }
}

impl dkg::SecretStore for HeldSecretStore {
    /// # Panics
    ///
    /// Panics when a ceremony yields another share, which only a committee of
    /// more than one validator does. Such a share cannot be kept in memory alone.
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        assert!(
            share == self.share,
            "the consensus share changed in epoch {epoch}; key material held by the host supports a single validator"
        );
    }

    async fn get_share(&mut self, _: Epoch) -> Option<Share> {
        Some(self.share.clone())
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.seeds.insert(epoch, seed);
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        self.seeds.get(&epoch).copied()
    }

    async fn put_dealing<P: PublicKey>(&mut self, _: Epoch, _: P, _: DealerPrivMsg) {}

    async fn get_dealing<P: PublicKey>(&mut self, _: Epoch, dealer: &P) -> Option<DealerPrivMsg> {
        (dealer.encode().as_ref() == self.local.as_slice()).then(|| {
            self.share
                .private
                .expose(|scalar| DealerPrivMsg::new(scalar.clone()))
        })
    }

    async fn prune(&mut self, min: Epoch) {
        self.seeds.retain(|epoch, _| *epoch >= min);
    }
}

#[cfg(test)]
#[path = "held_tests.rs"]
mod tests;
