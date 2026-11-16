//! The secret store a node runs with: files in its directory, or the host's memory.

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::DealerPrivMsg, primitives::group::Share},
    transcript::Summary,
};
use commonware_glue::dkg;

use super::{FileSecretStore, HeldSecretStore};

/// One store type for the reshare actor, whichever way the key material is kept.
pub(crate) enum NodeSecretStore {
    File(FileSecretStore),
    Held(HeldSecretStore),
}

impl dkg::SecretStore for NodeSecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        match self {
            Self::File(store) => store.put_share(epoch, share).await,
            Self::Held(store) => store.put_share(epoch, share).await,
        }
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        match self {
            Self::File(store) => store.get_share(epoch).await,
            Self::Held(store) => store.get_share(epoch).await,
        }
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        match self {
            Self::File(store) => store.put_seed(epoch, seed).await,
            Self::Held(store) => store.put_seed(epoch, seed).await,
        }
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        match self {
            Self::File(store) => store.get_seed(epoch).await,
            Self::Held(store) => store.get_seed(epoch).await,
        }
    }

    async fn put_dealing<P: PublicKey>(&mut self, epoch: Epoch, dealer: P, private: DealerPrivMsg) {
        match self {
            Self::File(store) => store.put_dealing(epoch, dealer, private).await,
            Self::Held(store) => store.put_dealing(epoch, dealer, private).await,
        }
    }

    async fn get_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        match self {
            Self::File(store) => store.get_dealing(epoch, dealer).await,
            Self::Held(store) => store.get_dealing(epoch, dealer).await,
        }
    }

    async fn prune(&mut self, min: Epoch) {
        match self {
            Self::File(store) => store.prune(min).await,
            Self::Held(store) => store.prune(min).await,
        }
    }
}
