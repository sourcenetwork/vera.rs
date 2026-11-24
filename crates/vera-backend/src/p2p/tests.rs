use super::*;
use crate::native::state_config;
use bytes::Bytes;
use commonware_glue::stateful::db::{DatabaseSet as _, Unmerkleized as _};
use commonware_runtime::{
    Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio as runtime_tokio,
};
use commonware_utils::{NZU16, NZUsize};
use std::time::Duration;

#[::tokio::test]
async fn feedback_translation_preserves_verdicts_and_cancels_candidates() {
    use commonware_utils::channel::{mpsc, oneshot};
    ::tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (verdict, first) = oneshot::channel();
        let (candidates, receiver) = mpsc::channel(1);
        let feedback = translate_feedback::<NativeDb>(Feedback::new(verdict, receiver));
        let (verdict, second) = oneshot::channel();
        candidates
            .send((
                Response::Operations {
                    proof: commonware_storage::merkle::Proof {
                        leaves: commonware_storage::merkle::Location::new(7),
                        inactive_peaks: 0,
                        digests: Vec::new(),
                    },
                    operations: Vec::new(),
                },
                verdict,
            ))
            .await
            .unwrap();
        let (response, feedback) = feedback.reject().await.unwrap();
        assert!(!first.await.unwrap());
        assert!(
            matches!(response, Response::Operations { proof, operations }
            if *proof.leaves == 7 && operations.is_empty())
        );
        feedback.accept();
        assert!(second.await.unwrap());
        candidates.closed().await;
    })
    .await
    .expect("feedback translation stalled");
}

#[::tokio::test]
async fn dropping_translated_feedback_cancels_without_a_verdict() {
    use commonware_utils::channel::{mpsc, oneshot};
    ::tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (verdict, result) = oneshot::channel();
        let (candidates, receiver) = mpsc::channel(1);
        let feedback = translate_feedback::<NativeDb>(Feedback::new(verdict, receiver));
        drop(feedback);
        assert!(result.await.is_err());
        candidates.closed().await;
    })
    .await
    .expect("dropping feedback left the request open");
}

#[::tokio::test]
async fn cancelling_translated_retry_closes_the_original_request() {
    use commonware_utils::channel::{mpsc, oneshot};
    ::tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (verdict, result) = oneshot::channel();
        let (candidates, receiver) = mpsc::channel(1);
        let feedback = translate_feedback::<NativeDb>(Feedback::new(verdict, receiver));
        let retry = ::tokio::spawn(feedback.reject());
        assert!(!result.await.unwrap());
        retry.abort();
        assert!(matches!(retry.await, Err(error) if error.is_cancelled()));
        candidates.closed().await;
    })
    .await
    .expect("cancelling a retry left the source request open");
}

async fn write_record(db: &Shared<NativeDb>, byte: u8) {
    let batch = db
        .new_batches()
        .await
        .write(vec![byte; 32], Some(Bytes::from(vec![byte; 8])))
        .merkleize()
        .await
        .unwrap();
    db.apply(batch).await;
    assert!(db.finalize().await.durable().await);
}

#[test]
fn a_request_one_block_ahead_is_answered_once_the_block_is_applied() {
    let directory = tempfile::tempdir().unwrap();
    runtime_tokio::Runner::new(
        runtime_tokio::Config::new().with_storage_directory(directory.path()),
    )
    .start(|context| async move {
        let cache = CacheRef::new(NZU16!(4084), NZUsize!(64));
        let db = Shared::<NativeDb>::init(
            context.child("records"),
            state_config("records", cache.clone()).0,
            None,
        )
        .await;
        // The same blocks on a second database give the target of the next block.
        let reference = Shared::<NativeDb>::init(
            context.child("reference"),
            state_config("reference", cache).0,
            None,
        )
        .await;
        for byte in [1, 2] {
            write_record(&reference, byte).await;
        }
        let next = reference.committed_targets().await;
        write_record(&db, 1).await;
        let wire = WireDatabase::<NativeDb>::new(db.clone());
        let writer = {
            let db = db.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                write_record(&db, 2).await;
                db.committed_targets().await
            })
        };
        let started = std::time::Instant::now();
        let served = wire
            .serve(Request::Operations {
                size: next.range.end(),
                start: next.range.start(),
                max_ops: MAX_FETCH_OPS,
            })
            .await;
        assert_eq!(writer.await.unwrap(), next);
        assert!(served.is_ok(), "{:?}", served.err());
        assert!(started.elapsed() >= Duration::from_millis(100));

        let never = wire
            .serve(Request::Operations {
                size: next.range.end() + 100,
                start: next.range.start(),
                max_ops: MAX_FETCH_OPS,
            })
            .await;
        assert!(never.is_err());
        assert!(started.elapsed() >= ahead::WAIT);
    });
}
