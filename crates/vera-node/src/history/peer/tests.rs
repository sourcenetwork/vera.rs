use super::*;
use crate::history::{
    RECORD, Record, key,
    transfer::tests::{certify, revision},
};
use alloy_primitives::B256;
use commonware_cryptography::ChaCha20Poly1305;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_p2p::{Address, AddressableManager as _, authenticated::lookup};
use commonware_runtime::{Quota, Runner as _, Supervisor as _, tokio};
use commonware_stream::{
    cups::{self, Cups},
    sake::{self, Sake},
};
use commonware_utils::{NZU32, ordered::Map};
use vera_domain::BlockId;
use vera_indexer::{BlockIndex, LightBlockIndex};

#[test]
fn chunk_decoder_checks_framing_offsets_lengths_and_overflow() {
    fn encoded(total: u64, offset: u64, bytes: &[u8]) -> Vec<u8> {
        [
            total.to_be_bytes().as_slice(),
            offset.to_be_bytes().as_slice(),
            bytes,
        ]
        .concat()
    }
    assert_eq!(
        decode_chunk(&encoded(3, 0, &[1, 2, 3]), 0).unwrap().bytes,
        [1, 2, 3]
    );
    for bytes in [
        vec![],
        vec![0; 16],
        vec![0; HISTORY_CHUNK_BYTES + 17],
        encoded(4, 0, &[1]),
        encoded(1, 1, &[1]),
        encoded(2, 1, &[1]),
        encoded(u64::MAX, u64::MAX, &[1]),
    ] {
        assert!(decode_chunk(&bytes, 0).is_err());
    }
    assert!(decode_chunk(&encoded(u64::MAX, u64::MAX, &[1]), u64::MAX).is_err());
}

#[test]
fn peer_import_rejects_bad_records_and_resumes_after_cancellation() {
    let directory = tempfile::tempdir().unwrap();
    let runner = tokio::Runner::new(
        tokio::Config::new().with_storage_directory(directory.path().join("runtime")),
    );
    runner.start(|context| async move {
        ::tokio::time::timeout(Duration::from_secs(30), async {
            let (genesis, _) = revision(0, BlockId(B256::ZERO));
            let (first, first_receipts) = revision(1, genesis.id());
            let (second, second_receipts) = revision(2, first.id());
            let histories: Vec<_> = (0..3)
                .map(|i| {
                    Arc::new(
                        FinalizedHistory::open(
                            directory.path().join(format!("history{i}")),
                            &genesis,
                        )
                        .unwrap(),
                    )
                })
                .collect();
            for history in &histories[..2] {
                history.append(&first, &first_receipts, 100).unwrap();
                history.append(&second, &second_receipts, 100).unwrap();
            }
            let bytes = histories[1].db.get(key(RECORD, 2)).unwrap().unwrap();
            let mut altered: Record = borsh::from_slice(&bytes).unwrap();
            altered.gas_limit += 1;
            histories[1]
                .db
                .put(key(RECORD, 2), borsh::to_vec(&altered).unwrap())
                .unwrap();
            let epochs = Arc::new(LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()));
            let (second_proof, _) = certify(&second, 77);
            epochs.insert_epoch_material(
                0,
                vera_indexer::StoredEpochMaterial {
                    bytes: hex::decode(second_proof.epoch_material.trim_start_matches("0x"))
                        .unwrap(),
                },
            );
            for (i, history) in histories[..2].iter().enumerate() {
                let proof = if i == 0 {
                    second_proof.clone()
                } else {
                    certify(&second, 78).0
                };
                let certificate = crate::FinalizationArtifacts {
                    epoch: 0,
                    finalization: hex::decode(proof.finalization.trim_start_matches("0x")).unwrap(),
                    certificate: vec![],
                };
                history.store_finalization(2, Some(&certificate)).unwrap();
            }
            let (light, trusted) = certify(&second, 77);
            histories[2].begin_import(&light, &trusted).unwrap();
            let keys = [
                PrivateKey::from_seed(31),
                PrivateKey::from_seed(32),
                PrivateKey::from_seed(33),
            ];
            let listeners = keys
                .each_ref()
                .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
            let addresses = listeners.each_ref().map(|l| l.local_addr().unwrap());
            let identities = keys.each_ref().map(|k| k.public_key());
            let membership: Map<_, Address> = identities
                .iter()
                .cloned()
                .zip(addresses.map(Into::into))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let mut handles = Vec::new();
            let mut clients = Vec::new();
            for (i, (key, listener)) in keys.into_iter().zip(listeners).enumerate() {
                let mut cfg = lookup::Config::local(
                    Cups::<_, ChaCha20Poly1305>::new(
                        Sake {
                            signer: key,
                            synchrony_bound: std::time::Duration::from_secs(5),
                            max_handshake_age: std::time::Duration::from_secs(10),
                            version: sake::Version::V1,
                        },
                        cups::Version::V1,
                    ),
                    b"vera-history-transfer-test",
                    addresses[i],
                    NZUsize!(3),
                    crate::MAX_MESSAGE_SIZE,
                );
                cfg.dial_frequency = Duration::from_millis(10);
                cfg.peer_connection_cooldown = Duration::from_millis(10);
                let peer_context = context.child(["honest", "corrupt", "replica"][i]);
                let (mut network, mut oracle) =
                    lookup::Network::new(peer_context.child("network"), cfg);
                oracle.track(0, membership.clone());
                let (client, handle) = start_history_peer(
                    peer_context.child("history"),
                    histories[i].clone(),
                    epochs.clone(),
                    oracle.clone(),
                    oracle,
                    identities[i].clone(),
                    network.register(0, Quota::per_second(NZU32!(100))),
                );
                clients.push(client);
                handles.push(handle);
                drop(listener);
                handles.push(network.start());
            }
            let client = &mut clients[2];
            let limits = HistoryLimits {
                record_bytes: bytes.len(),
                logs: 1,
            };
            let absent = PrivateKey::from_seed(404).public_key();
            assert!(
                ::tokio::time::timeout(
                    Duration::from_millis(30),
                    client.import_next_from(absent, &histories[2], limits, Duration::from_secs(10))
                )
                .await
                .is_err()
            );
            assert!(client.delivery.0.lock().is_none());
            assert_eq!(histories[2].import_next().unwrap(), Some((2, second.id())));
            let error = client
                .import_next_from(
                    identities[0].clone(),
                    &histories[2],
                    HistoryLimits {
                        record_bytes: 1,
                        ..limits
                    },
                    Duration::from_secs(10),
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("assembly limit"));
            let error = client
                .import_next_from(
                    identities[1].clone(),
                    &histories[2],
                    limits,
                    Duration::from_secs(10),
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("receipt commitment mismatch"));
            assert_eq!(histories[2].import_next().unwrap(), Some((2, second.id())));
            histories[1].db.put(key(RECORD, 2), &bytes).unwrap();
            let error = client
                .import_next_from(
                    identities[1].clone(),
                    &histories[2],
                    limits,
                    Duration::from_secs(10),
                )
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("certificate verification failed")
            );
            assert_eq!(histories[2].import_next().unwrap(), Some((2, second.id())));
            for expected in [2, 1] {
                assert_eq!(
                    client
                        .import_next_from(
                            identities[0].clone(),
                            &histories[2],
                            limits,
                            Duration::from_secs(10)
                        )
                        .await
                        .unwrap(),
                    Some(expected)
                );
            }
            assert_eq!(histories[2].import_next().unwrap(), None);
            let lookup: crate::FinalizationLookup =
                Arc::new(|_| panic!("imported history must not use local certificate lookup"));
            let index = BlockIndex::new();
            histories[2]
                .recover(
                    &genesis,
                    &second,
                    &index,
                    &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                    &lookup,
                )
                .await
                .unwrap();
            assert_eq!(index.head_block_number(), 2);
            assert_eq!(
                histories[2].db.get(key(RECORD, 2)).unwrap(),
                histories[0].db.get(key(RECORD, 2)).unwrap()
            );
            let proof = histories[2]
                .light_block(
                    1,
                    &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                )
                .unwrap();
            assert_eq!(proof.descendants.len(), 1);
            assert_eq!(
                vera_domain::verify_finalized_block(&proof, &trusted).unwrap(),
                first
            );
            for handle in handles {
                handle.abort();
            }
        })
        .await
        .expect("history peer test deadline");
    });
}
