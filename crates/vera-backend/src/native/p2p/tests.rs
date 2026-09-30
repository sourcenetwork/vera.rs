use super::*;
use crate::{
    native::{MAX_KEY_BYTES, MAX_VALUE_BYTES, NativeDb, Operation, state_config},
    p2p::Partition as _,
};
use bytes::Bytes;
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, EncodeSize as _};
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    AttachableResolver, DatabaseSet as _, Shared, StateSyncDb as _, SyncEngineConfig,
    Unmerkleized as _, p2p,
};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    merkle::{Location, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof, mmr},
    qmdb::{
        any::ordered::variable::Update,
        sync::{Feedback, Request, Response, Source},
    },
};
use commonware_utils::{NZU16, NZU64, NZUsize, channel::mpsc};
use std::{num::NonZeroU64, time::Duration};

mod batching;
mod network;
mod recovery;

fn update(key: usize, value: usize, next_key: usize) -> Operation {
    Operation::Update(Update {
        key: vec![1; key],
        value: Bytes::from(vec![2; value]),
        next_key: vec![3; next_key],
    })
}

#[test]
fn wire_codec_bounds_every_variable_field_and_response() {
    let largest = update(MAX_KEY_BYTES, MAX_VALUE_BYTES, MAX_KEY_BYTES);
    let operations = vec![crate::p2p::WireOperation::<NativeDb>(largest.clone()); 2];
    let response = Response::<mmr::Family, _, Digest>::Operations {
        proof: Proof {
            leaves: Location::new(2),
            inactive_peaks: 0,
            digests: vec![Digest::from([0; 32]); 2 * MAX_PROOF_DIGESTS_PER_ELEMENT],
        },
        operations,
    };
    let bytes = response.encode();
    assert!(bytes.len() < 4 * 1024 * 1024 - 1024);
    let decoded =
        Response::<mmr::Family, WireOperation, Digest>::decode_cfg(bytes.clone(), &(2, ()))
            .unwrap();
    assert_eq!(decoded.encode(), bytes);
    assert!(Response::<mmr::Family, WireOperation, Digest>::decode_cfg(bytes, &(1, ())).is_err());
    let excessive_count = Response::<mmr::Family, _, Digest>::Operations {
        proof: Proof {
            leaves: Location::new(3),
            inactive_peaks: 0,
            digests: Vec::new(),
        },
        operations: vec![crate::p2p::WireOperation::<NativeDb>(Operation::Delete(Vec::new())); 3],
    };
    assert!(
        Response::<mmr::Family, WireOperation, Digest>::decode_cfg(
            excessive_count.encode(),
            &(2, ()),
        )
        .is_err()
    );

    for operation in [
        largest,
        Operation::Delete(vec![1; MAX_KEY_BYTES]),
        Operation::CommitFloor(
            Some(Bytes::from(vec![1; MAX_VALUE_BYTES])),
            Location::new(0),
        ),
        Operation::CommitFloor(None, Location::new(0)),
    ] {
        assert!(NativeDb::accepts(&operation));
        let bytes = operation.encode();
        assert_eq!(WireOperation::decode(bytes.clone()).unwrap().0, operation);
        assert_eq!(
            crate::p2p::WireOperation::<NativeDb>(operation).encode(),
            bytes
        );
        assert!(WireOperation::decode(bytes.slice(..bytes.len() - 1)).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(WireOperation::decode(commonware_codec::Copying(trailing.as_slice())).is_err());
    }
    for operation in [
        update(MAX_KEY_BYTES + 1, 0, 0),
        update(0, MAX_VALUE_BYTES + 1, 0),
        update(0, 0, MAX_KEY_BYTES + 1),
        Operation::Delete(vec![1; MAX_KEY_BYTES + 1]),
        Operation::CommitFloor(
            Some(Bytes::from(vec![1; MAX_VALUE_BYTES + 1])),
            Location::new(0),
        ),
    ] {
        assert!(!NativeDb::accepts(&operation));
        assert!(WireOperation::decode(operation.encode()).is_err());
    }
}

#[test]
fn peer_sync_preserves_roots_and_reports_rejected_responses() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(|context| async move {
        ::tokio::time::timeout(Duration::from_secs(20), async {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let source = Shared::<NativeDb>::init(
                context.child("source"),
                state_config("source", cache.clone()).0,
                None,
            )
            .await;
            let batch = source
                .new_batches()
                .await
                .write(
                    vec![1; MAX_KEY_BYTES],
                    Some(Bytes::from(vec![4; MAX_VALUE_BYTES])),
                )
                .write(
                    vec![2; MAX_KEY_BYTES],
                    Some(Bytes::from(vec![5; MAX_VALUE_BYTES])),
                )
                .write(b"removed".to_vec(), Some(Bytes::from_static(b"old")));
            source.apply(batch.merkleize().await.unwrap()).await;
            assert!(source.finalize().await.durable().await);
            let batch = source.new_batches().await.write(b"removed".to_vec(), None);
            source.apply(batch.merkleize().await.unwrap()).await;
            assert!(source.finalize().await.durable().await);
            let target = source.committed_targets().await;
            let root = source.read().await.root();

            let mut peers = network::Peers::start(&context);
            peers.resolvers[0].attach_database(source.clone()).await;
            let (_updates, updates_rx) = mpsc::channel(1);
            let replica = NativeDb::sync_db(
                context.child("replica"),
                state_config("replica", cache).0,
                peers.resolvers[1].clone(),
                target.clone(),
                updates_rx,
                None,
                None,
                SyncEngineConfig {
                    fetch_batch_size: NZU64!(64),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: 2,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 1,
                },
            )
            .await
            .unwrap();
            assert_eq!(replica.root(), root);
            assert_eq!(replica.ops_root(), target.root);
            assert_eq!(
                replica.get(&vec![1; MAX_KEY_BYTES]).await.unwrap(),
                Some(Bytes::from(vec![4; MAX_VALUE_BYTES]))
            );
            assert!(replica.get(&b"removed".to_vec()).await.unwrap().is_none());

            let (response, feedback) = peers.resolvers[1]
                .serve(Request::Boundary {
                    size: target.range.end(),
                    start: target.range.start(),
                })
                .await
                .unwrap();
            assert!(matches!(response, Response::Boundary { .. }));
            let rejection = feedback.unwrap().reject();
            let blocked = async {
                while !peers.blocked[1]
                    .recv()
                    .await
                    .unwrap()
                    .iter()
                    .any(|peer| peer == &peers.identities[0])
                {}
            };
            ::tokio::pin!(rejection, blocked);
            ::tokio::select! {
                result = &mut rejection => {
                    assert!(result.is_none(), "rejected peer supplied another response");
                    blocked.await;
                },
                () = &mut blocked => {},
            }
        })
        .await
        .expect("peer synchronization timed out");
    });
}
