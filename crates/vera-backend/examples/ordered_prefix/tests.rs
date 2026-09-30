use super::*;

pub(super) async fn write(db: Store, entries: Vec<(Vec<u8>, Option<Bytes>)>) -> Store {
    let mut batch = db.new_batch();
    for (key, value) in entries {
        batch = batch.write(key, value);
    }
    let batch = batch.merkleize(&db, None).await.unwrap();
    let (db, _) = db.apply_batch(batch).await.unwrap();
    db.commit().await.unwrap()
}

#[test]
fn complete_prefixes_match_all_subsets_and_reject_omissions() {
    run(|context| async move {
        let cfg = config(&context);
        let mut db = Store::init(context, cfg, None).await.unwrap();
        let keys = [b"".as_slice(), b"\0", b"a", b"aa", b"ab", b"b", b"\xff"];
        let prefixes = [
            b"".as_slice(),
            b"\0",
            b"\0\0",
            b"a",
            b"aa",
            b"ab",
            b"ac",
            b"b",
            b"c",
            b"\xff",
            b"\xff\xff",
        ];
        let empty = proof::prove(&db, b"a").await.unwrap();
        assert!(empty.verify(b"a", &db.root()));
        for mask in 0..(1 << keys.len()) {
            db = write(
                db,
                keys.iter()
                    .enumerate()
                    .map(|(i, key)| {
                        (
                            key.to_vec(),
                            (mask & (1 << i) != 0).then(|| Bytes::from_static(b"value")),
                        )
                    })
                    .collect(),
            )
            .await;
            for prefix in prefixes {
                let witness = proof::prove(&db, prefix).await.unwrap();
                let expected: Vec<_> = keys
                    .iter()
                    .enumerate()
                    .filter(|(i, key)| mask & (1 << i) != 0 && key.starts_with(prefix))
                    .map(|(_, key)| *key)
                    .collect();
                assert_eq!(
                    witness
                        .entries
                        .iter()
                        .map(|entry| entry.key.as_slice())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert!(
                    witness.verify(prefix, &db.root()),
                    "mask={mask}, prefix={prefix:?}"
                );
                for index in 0..witness.entries.len() {
                    let mut omitted = witness.clone();
                    omitted.entries.remove(index);
                    assert!(
                        omitted
                            .entries
                            .iter()
                            .all(|entry| entry.proof.verify::<Sha256, _>(
                                entry.key.clone(),
                                entry.value.clone(),
                                &db.root()
                            ))
                    );
                    assert!(
                        !omitted.verify(prefix, &db.root()),
                        "omission {index}, mask={mask}, prefix={prefix:?}"
                    );
                }
            }
        }
    });
}

#[test]
fn rejects_tampering_and_mixed_revisions() {
    run(|context| async move {
        let cfg = config(&context);
        let db = Store::init(context, cfg, None).await.unwrap();
        let mut db = write(
            db,
            [
                b"a".as_slice(),
                b"blocked/1",
                b"blocked/2",
                b"blocked/3",
                b"z",
            ]
            .into_iter()
            .map(|key| (key.to_vec(), Some(Bytes::from_static(b"deny"))))
            .collect(),
        )
        .await;
        let prefix = b"blocked/";
        let old_root = db.root();
        let witness = proof::prove(&db, prefix).await.unwrap();
        assert!(witness.verify(prefix, &old_root));
        assert!(!witness.verify(b"reader/", &old_root));
        let mut tampered = witness.clone();
        tampered.boundary = None;
        assert!(!tampered.verify(prefix, &old_root));
        let mut tampered = witness.clone();
        tampered.entries[0].value = Bytes::from_static(b"allow");
        assert!(!tampered.verify(prefix, &old_root));
        let mut tampered = witness.clone();
        tampered.entries[0].key.push(0);
        assert!(!tampered.verify(prefix, &old_root));
        let mut tampered = witness.clone();
        tampered.entries[0].proof.next_key = b"blocked/3".to_vec();
        tampered.entries.remove(1);
        assert!(!tampered.verify(prefix, &old_root));
        let mut tampered = witness.clone();
        tampered.entries.swap(0, 1);
        assert!(!tampered.verify(prefix, &old_root));
        let mut tampered = witness.clone();
        tampered.entries.push(tampered.entries[2].clone());
        assert!(!tampered.verify(prefix, &old_root));

        db = write(db, vec![(b"blocked/2".to_vec(), None)]).await;
        let current = proof::prove(&db, prefix).await.unwrap();
        assert!(current.verify(prefix, &db.root()));
        assert!(!witness.verify(prefix, &db.root()));
        assert!(!current.verify(prefix, &old_root));
        let mut mixed = current.clone();
        mixed.entries[0] = witness.entries[0].clone();
        assert!(!mixed.verify(prefix, &db.root()));
        db = write(
            db,
            vec![(b"blocked/2".to_vec(), Some(Bytes::from_static(b"deny")))],
        )
        .await;
        assert!(!current.verify(prefix, &db.root()));
        assert!(
            proof::prove(&db, prefix)
                .await
                .unwrap()
                .verify(prefix, &db.root())
        );
    });
}
