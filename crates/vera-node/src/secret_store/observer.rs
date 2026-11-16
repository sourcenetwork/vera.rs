//! Secret store of a node that follows a deployment without validating it.

use std::collections::BTreeMap;

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::DealerPrivMsg, primitives::group::Share},
    transcript::Summary,
};
use commonware_glue::dkg;

/// In-memory [`dkg::SecretStore`] that never holds a share or a dealing.
///
/// A backup is in no committee, so every ceremony it observes yields it
/// nothing to keep. The seeds only order its own randomness within one run.
#[derive(Default)]
pub(crate) struct ObserverSecretStore {
    seeds: BTreeMap<Epoch, Summary>,
}

impl dkg::SecretStore for ObserverSecretStore {
    /// # Panics
    ///
    /// Panics when a ceremony yields a share, which only a member of a
    /// committee receives. A backup must not come to hold one.
    async fn put_share(&mut self, epoch: Epoch, _: Share) {
        panic!("a backup received a consensus share in epoch {epoch}");
    }

    async fn get_share(&mut self, _: Epoch) -> Option<Share> {
        None
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.seeds.insert(epoch, seed);
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        self.seeds.get(&epoch).copied()
    }

    async fn put_dealing<P: PublicKey>(&mut self, _: Epoch, _: P, _: DealerPrivMsg) {}

    async fn get_dealing<P: PublicKey>(&mut self, _: Epoch, _: &P) -> Option<DealerPrivMsg> {
        None
    }

    async fn prune(&mut self, min: Epoch) {
        self.seeds.retain(|epoch, _| *epoch >= min);
    }
}
