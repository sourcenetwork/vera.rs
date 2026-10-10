use super::*;
use commonware_glue::dkg::SecretStore as _;
use futures::FutureExt as _;

fn seed(value: u8) -> Summary {
    Summary::decode(commonware_codec::Copying(&[value; 32][..])).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn persistence_yields_and_cached_reads_keep_the_durable_view() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    let mut store = FileSecretStore::load(&path).unwrap();
    store.put_seed(Epoch::new(1), seed(1)).await;
    let first = store.clone();
    let mut reader = store.clone();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let first = tokio::task::spawn_blocking(move || {
        let mut entered = Some(entered);
        first.update_with_sync(
            |data| {
                data.seeds.insert(2, hex::encode(seed(2).encode()));
            },
            |file| {
                if let Some(entered) = entered.take() {
                    entered.send(()).unwrap();
                    wait.recv_timeout(std::time::Duration::from_secs(30))
                        .map_err(std::io::Error::other)?;
                }
                file.sync_all()
            },
        )
    });
    started.await.unwrap();

    let mut pending = Box::pin(store.put_seed(Epoch::new(3), seed(3)));
    assert!(
        pending.as_mut().now_or_never().is_none(),
        "a serialized write must yield while persistence is busy"
    );
    assert_eq!(
        reader.get_seed(Epoch::new(1)).now_or_never().unwrap(),
        Some(seed(1))
    );
    assert!(
        reader
            .get_seed(Epoch::new(2))
            .now_or_never()
            .unwrap()
            .is_none(),
        "pending material must not be published before durability"
    );

    release.send(()).unwrap();
    first.await.unwrap().unwrap();
    pending.await;
    let mut reopened = FileSecretStore::load(&path).unwrap();
    for value in 1..=3 {
        assert_eq!(
            reopened.get_seed(Epoch::new(u64::from(value))).await,
            Some(seed(value))
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn failed_background_persistence_panics_without_publishing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    let retained = directory.path().join("retained.json");
    let mut store = FileSecretStore::load(&path).unwrap();
    store.put_seed(Epoch::new(1), seed(1)).await;
    let mut reader = store.clone();
    let original = fs::read(&path).unwrap();
    fs::rename(&path, &retained).unwrap();
    fs::create_dir(&path).unwrap();

    let failure = tokio::spawn(async move {
        store.put_seed(Epoch::new(2), seed(2)).await;
    })
    .await
    .unwrap_err();
    assert!(failure.is_panic());
    assert_eq!(reader.get_seed(Epoch::new(1)).await, Some(seed(1)));
    assert!(reader.get_seed(Epoch::new(2)).await.is_none());
    assert_eq!(fs::read(&retained).unwrap(), original);

    fs::remove_dir(&path).unwrap();
    fs::rename(&retained, &path).unwrap();
    let mut reopened = FileSecretStore::load(path).unwrap();
    assert_eq!(reopened.get_seed(Epoch::new(1)).await, Some(seed(1)));
    assert!(reopened.get_seed(Epoch::new(2)).await.is_none());
}

#[tokio::test]
async fn asynchronous_material_updates_and_pruning_survive_reopening() {
    use commonware_cryptography::{
        Signer as _,
        bls12381::primitives::group::{Private, Scalar},
        ed25519,
    };
    use commonware_utils::Participant;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    let mut store = FileSecretStore::load(&path).unwrap();
    let dealer = ed25519::PrivateKey::from_seed(7).public_key();
    let share = Share::new(Participant::new(1), Private::new(Scalar::from(1u64)));
    let expected_share = share.encode();
    let expected_dealing = DealerPrivMsg::new(Scalar::from(1u64)).encode();
    for epoch in [Epoch::new(1), Epoch::new(2)] {
        store.put_share(epoch, share.clone()).await;
        store.put_seed(epoch, seed(7)).await;
        store
            .put_dealing(
                epoch,
                dealer.clone(),
                DealerPrivMsg::new(Scalar::from(1u64)),
            )
            .await;
    }
    let mut reopened = FileSecretStore::load(&path).unwrap();
    for epoch in [Epoch::new(1), Epoch::new(2)] {
        assert_eq!(
            reopened.get_share(epoch).await.unwrap().encode(),
            expected_share
        );
        assert_eq!(reopened.get_seed(epoch).await, Some(seed(7)));
        assert_eq!(
            reopened
                .get_dealing(epoch, dealer.clone())
                .await
                .unwrap()
                .encode(),
            expected_dealing
        );
    }
    store.prune(Epoch::new(2)).await;
    let mut reopened = FileSecretStore::load(&path).unwrap();
    assert!(reopened.get_share(Epoch::new(1)).await.is_none());
    assert!(reopened.get_seed(Epoch::new(1)).await.is_none());
    assert!(
        reopened
            .get_dealing(Epoch::new(1), dealer.clone())
            .await
            .is_none()
    );
    assert_eq!(
        reopened.get_share(Epoch::new(2)).await.unwrap().encode(),
        expected_share
    );
    assert_eq!(reopened.get_seed(Epoch::new(2)).await, Some(seed(7)));
    assert_eq!(
        reopened
            .get_dealing(Epoch::new(2), dealer)
            .await
            .unwrap()
            .encode(),
        expected_dealing
    );
}
