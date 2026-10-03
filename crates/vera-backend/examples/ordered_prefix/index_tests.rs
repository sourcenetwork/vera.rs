use super::*;
use commonware_storage::{mmr, qmdb::current::ordered::variable::Db, translator::EightCap};
use index::KeyPrefix;
use vera_backend::native::INDEX_PREFIX_BYTES;

type NarrowStore =
    Db<mmr::Family, tokio::Context, Vec<u8>, Bytes, Sha256, EightCap, 32, Sequential>;

fn keys() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        vec![0; INDEX_PREFIX_BYTES],
        vec![0; INDEX_PREFIX_BYTES + 1],
        [vec![0; INDEX_PREFIX_BYTES], vec![1]].concat(),
        [vec![0; INDEX_PREFIX_BYTES], vec![1, 0]].concat(),
        [vec![0; INDEX_PREFIX_BYTES], vec![255]].concat(),
        vec![255; INDEX_PREFIX_BYTES],
        vec![255; INDEX_PREFIX_BYTES + 1],
    ]
}

#[test]
fn translated_collisions_preserve_prefix_completeness() {
    let translator = KeyPrefix::default();
    let keys = keys();
    for pair in keys.windows(2) {
        assert!(pair[0] < pair[1]);
        assert!(translator.transform(&pair[0]) <= translator.transform(&pair[1]));
    }
    assert_eq!(
        translator.transform(&keys[2]),
        translator.transform(&keys[6])
    );
    run(|context| async move {
        let cfg = config(&context);
        let db = Store::init(context, cfg, None).await.unwrap();
        let db = tests::write(
            db,
            keys.iter()
                .map(|key| (key.clone(), Some(Bytes::from_static(b"record"))))
                .collect(),
        )
        .await;
        for prefix in &keys {
            let witness = proof::prove(&db, prefix).await.unwrap();
            let expected: Vec<_> = keys.iter().filter(|key| key.starts_with(prefix)).collect();
            assert_eq!(
                witness
                    .entries
                    .iter()
                    .map(|entry| &entry.key)
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(witness.verify(prefix, &db.root()));
            for i in 0..witness.entries.len() {
                let mut incomplete = witness.clone();
                incomplete.entries.remove(i);
                assert!(!incomplete.verify(prefix, &db.root()));
            }
        }
    });
}

#[test]
fn reopening_with_a_wider_index_preserves_committed_state() {
    let directory = tempfile::tempdir().unwrap();
    let runtime =
        || tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path()));
    let root = runtime().start(|context| async move {
        let cfg = config(&context);
        let db = NarrowStore::init(context, cfg, None).await.unwrap();
        let mut batch = db.new_batch();
        for key in keys() {
            batch = batch.write(key, Some(Bytes::from_static(b"record")));
        }
        let batch = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        db.commit().await.unwrap().root()
    });
    runtime().start(|context| async move {
        let cfg = config(&context);
        let db = Store::init(context, cfg, None).await.unwrap();
        assert_eq!(db.root(), root);
        for key in keys() {
            assert_eq!(
                db.get(&key).await.unwrap(),
                Some(Bytes::from_static(b"record"))
            );
        }
        let witness = proof::prove(&db, &[0; INDEX_PREFIX_BYTES]).await.unwrap();
        assert!(witness.verify(&[0; INDEX_PREFIX_BYTES], &root));
        assert_eq!(witness.entries.len(), 5);
    });
}
