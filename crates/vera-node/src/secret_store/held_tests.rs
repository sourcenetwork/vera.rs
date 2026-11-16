use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_glue::dkg::SecretStore as _;

use super::HeldSecretStore;

fn share(seed: u64) -> (commonware_cryptography::ed25519::PublicKey, super::Share) {
    let local = PrivateKey::from_seed(seed).public_key();
    let (_, shares) = crate::trusted_setup(seed, [local.clone()]).unwrap();
    let share = shares.get_value(&local).cloned().unwrap();
    (local, share)
}

#[tokio::test]
async fn every_epoch_is_served_the_held_share() {
    let (local, held) = share(1);
    let mut store = HeldSecretStore::new(&local, held.clone());

    store.put_share(Epoch::new(7), held.clone()).await;
    store.prune(Epoch::new(7)).await;

    for epoch in [0, 6, 7, 1_000] {
        assert_eq!(store.get_share(Epoch::new(epoch)).await, Some(held.clone()));
    }
}

#[tokio::test]
#[should_panic(expected = "supports a single validator")]
async fn a_different_share_is_not_accepted() {
    let (local, held) = share(1);
    let (_, other) = share(2);

    HeldSecretStore::new(&local, held)
        .put_share(Epoch::new(1), other)
        .await;
}

#[tokio::test]
async fn only_the_validators_own_dealing_is_rebuilt_from_the_share() {
    let (local, held) = share(1);
    let (stranger, _) = share(2);
    let mut store = HeldSecretStore::new(&local, held.clone());

    let dealing = store.get_dealing(Epoch::new(3), &local).await.unwrap();

    assert_eq!(dealing.encode(), held.encode()[held.encode().len() - 32..]);
    assert!(store.get_dealing(Epoch::new(3), &stranger).await.is_none());
}
