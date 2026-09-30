use super::*;
use commonware_cryptography::Sha256;
use commonware_storage::qmdb;

#[test]
fn byte_budget_batches_small_records_and_splits_large_records() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let db = Shared::<NativeDb>::init(context.child("source"), state_config("source", cache).0, None)
            .await;
        let mut batch = db.new_batches().await;
        for i in 0..8 {
            batch = batch.write(
                vec![i; MAX_KEY_BYTES],
                Some(Bytes::from(vec![i; MAX_VALUE_BYTES])),
            );
        }
        for i in 0..128 {
            batch = batch.write(
                format!("small/{i:04}").into_bytes(),
                Some(Bytes::from_static(b"value")),
            );
        }
        db.apply(batch.merkleize().await.unwrap()).await;
        assert!(db.finalize().await.durable().await);
        let target = db.committed_targets().await;
        let wire = WireDatabase::new(db.clone());
        let mut start = target.range.start();
        let mut wide = false;
        let mut split = false;
        let mut responses = 0;
        while start < target.range.end() {
            let request = Request::Operations {
                size: target.range.end(),
                start,
                max_ops: NZU64!(1000),
            };
            let (response, feedback) = wire.serve(request).await.unwrap();
            assert!(feedback.is_none());
            assert!(response.encode_size() <= MAX_RESPONSE_BYTES);
            let encoded = response.encode();
            let response = Response::<mmr::Family, WireOperation, Digest>::decode_cfg(
                encoded,
                &(MAX_FETCH_OPS.get() as usize, ()),
            )
            .unwrap();
            let Response::Operations { proof, operations } = response else {
                panic!("expected operations")
            };
            assert!(!operations.is_empty());
            assert!(operations.len() as u64 <= MAX_FETCH_OPS.get());
            let actual: Vec<_> = operations.into_iter().map(|op| op.0).collect();
            assert!(qmdb::verify_proof::<Sha256, _, _>(
                &proof,
                start,
                &actual,
                &target.root
            ));
            let expected = db
                .serve(Request::Operations {
                    max_ops: NonZeroU64::new(actual.len() as u64).unwrap(),
                    size: target.range.end(),
                    start,
                })
                .await
                .unwrap()
                .0;
            let Response::Operations {
                operations: expected,
                ..
            } = expected
            else {
                unreachable!()
            };
            assert_eq!(actual, expected);
            wide |= actual.len() as u64 == MAX_FETCH_OPS.get();
            split |= actual.iter().any(|op| op.encode_size() > MAX_VALUE_BYTES)
                && (actual.len() as u64) < MAX_FETCH_OPS.get()
                && start.saturating_add(actual.len() as u64) < target.range.end();
            start = start.saturating_add(actual.len() as u64);
            responses += 1;
        }
        assert!(wide, "small records never filled a batch");
        assert!(split, "large records did not exercise the byte budget");
        let mut baseline_start = target.range.start();
        let mut baseline_responses = 0;
        while baseline_start < target.range.end() {
            let (response, _) = db
                .serve(Request::Operations {
                    size: target.range.end(),
                    start: baseline_start,
                    max_ops: NZU64!(2),
                })
                .await
                .unwrap();
            let Response::Operations { operations, .. } = response else {
                unreachable!()
            };
            baseline_start = baseline_start.saturating_add(operations.len() as u64);
            baseline_responses += 1;
        }
        assert!(responses < baseline_responses);
        let (boundary, _) = wire
            .serve(Request::Boundary {
                size: target.range.end(),
                start: target.range.start(),
            })
            .await
            .unwrap();
        assert!(boundary.encode_size() <= MAX_RESPONSE_BYTES);
        assert!(matches!(boundary, Response::Boundary { .. }));
        assert!(
            wire.serve(Request::Operations {
                size: target.range.end(),
                start: target.range.end(),
                max_ops: MAX_FETCH_OPS
            })
            .await
            .is_err()
        );
        assert!(
            wire.serve(Request::Operations {
                size: target.range.end().saturating_add(1),
                start: target.range.start(),
                max_ops: MAX_FETCH_OPS
            })
            .await
            .is_err()
        );
        eprintln!(
            "native byte batching: {responses} responses versus {baseline_responses} at two operations for {} retained operations",
            *target.range.end() - *target.range.start()
        );
    });
}
