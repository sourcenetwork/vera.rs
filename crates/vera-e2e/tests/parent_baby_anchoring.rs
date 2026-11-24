//! A parent deployment of four validators anchors the revisions of two baby
//! deployments, each one embedded validator. A reader that trusts only the
//! parent's key verifies relayed policy snapshots and learns when they are
//! stale; a baby's anchors are ordered by the parent's finalized revisions; a
//! forked baby cannot replace an anchored block at its height.
//!
//! Requires `cargo build -p verad` before running.

#[path = "parent_baby/anchor.rs"]
mod anchor;
#[path = "parent_baby/baby.rs"]
mod baby;

use anchor::Parent;
use baby::{Baby, block_hash};
use vera_client::{
    AccessRequest, Actor, BlsSigner, Object, Operation, RefusalKind, VeraClient,
    anchoring::{AnchoredSnapshot, AnchoringError, deployment_id},
};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};

const PARENT_CHAIN: u64 = 9_611;
const LAPTOP_CHAIN: u64 = 9_612;
const PHONE_CHAIN: u64 = 9_613;
const READER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const OTHER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

fn read(actor: &str) -> AccessRequest {
    AccessRequest {
        actor: Actor(actor.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "collection".into(),
                id: "notes".into(),
            },
            permission: "read".into(),
        }],
    }
}

async fn start_parent() -> (TestCluster, Parent) {
    let key = *KeySet::builder()
        .seed(PARENT_CHAIN)
        .build()
        .expect("bootstrap keys")
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .seed(PARENT_CHAIN)
        .chain_id(PARENT_CHAIN)
        .genesis(GenesisBuilder::devnet())
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .expect("parent cluster should start");
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .expect("parent cluster should become healthy");
    let client = VeraClient::new(cluster.node(0).rpc_url());
    (cluster, Parent { client, key })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parent_orders_and_attests_the_policies_of_two_babies() {
    let (_cluster, parent) = start_parent().await;
    let directories = [(); 3].map(|()| tempfile::tempdir().unwrap());
    let laptop_deployment = baby::deal(LAPTOP_CHAIN);
    let laptop = Baby::open(directories[0].path(), laptop_deployment.clone(), false).await;
    let phone = Baby::open(directories[1].path(), baby::deal(PHONE_CHAIN), false).await;
    let laptop_author = BlsSigner::random(laptop.chain_id).unwrap();
    let phone_author = BlsSigner::random(phone.chain_id).unwrap();
    let laptop_relay = BlsSigner::random(PARENT_CHAIN).unwrap();
    let phone_relay = BlsSigner::random(PARENT_CHAIN).unwrap();

    let laptop_policy = laptop.share_notes(&laptop_author, READER).await;
    let phone_policy = phone.share_notes(&phone_author, OTHER).await;
    let first = parent
        .anchor_policy(&laptop, &laptop_relay, &laptop_policy)
        .await;
    let phone_first = parent
        .anchor_policy(&phone, &phone_relay, &phone_policy)
        .await;

    // A third party holds only the parent's key and the relayed bytes.
    let laptop_id = deployment_id(&laptop.key);
    let phone_id = deployment_id(&phone.key);
    let relayed = AnchoredSnapshot::decode(&first.snapshot.encode()).unwrap();
    let verified = relayed
        .verify(&laptop_id, &laptop_policy, &parent.key, 0)
        .unwrap();
    assert_eq!(verified.anchor.sequence, 1);
    assert!(verified.check(&read(READER)).unwrap());
    assert!(!verified.check(&read(OTHER)).unwrap());
    let phone_verified = AnchoredSnapshot::decode(&phone_first.snapshot.encode())
        .unwrap()
        .verify(&phone_id, &phone_policy, &parent.key, 0)
        .unwrap();
    assert_eq!(phone_verified.anchor.sequence, 1);
    assert!(phone_verified.check(&read(OTHER)).unwrap());
    assert!(!phone_verified.check(&read(READER)).unwrap());
    // Each baby's snapshot is bound to its own deployment.
    assert!(
        relayed
            .verify(&phone_id, &laptop_policy, &parent.key, 0)
            .is_err()
    );

    // Two more versions of the laptop's policy, each anchored.
    laptop.revoke(&laptop_author, &laptop_policy, READER).await;
    let second = parent
        .anchor_policy(&laptop, &laptop_relay, &laptop_policy)
        .await;
    laptop.grant(&laptop_author, &laptop_policy, OTHER).await;
    let third = parent
        .anchor_policy(&laptop, &laptop_relay, &laptop_policy)
        .await;
    let versions = [&first, &second, &third];
    for (earlier, later) in versions.iter().zip(&versions[1..]) {
        assert_eq!(later.record.sequence, earlier.record.sequence + 1);
        assert!(later.record.height > earlier.record.height);
        assert!(later.parent_height > earlier.parent_height);
        assert!(later.parent_time >= earlier.parent_time);
    }
    let newest = third
        .snapshot
        .verify(&laptop_id, &laptop_policy, &parent.key, 0)
        .unwrap();
    assert!(!newest.check(&read(READER)).unwrap());
    assert!(newest.check(&read(OTHER)).unwrap());
    // The snapshot carries the time of the parent revision it read the anchor
    // at; the time the anchor was recorded is that of `anchored_at`.
    assert!(newest.anchor_revision >= third.parent_height);
    assert!(newest.anchor_timestamp >= third.parent_time);
    let recorded = parent
        .client
        .read_finalized_revision(newest.anchor.anchored_at, &parent.key)
        .await
        .unwrap();
    assert_eq!(recorded.timestamp, third.parent_time);

    // The parent's state holds only the newest anchor. The older ones remain
    // provable, in order, from the parent's certified receipts.
    for version in versions {
        let (event, time) = parent.anchored_event(version.submission).await;
        assert_eq!(event.sequence, version.record.sequence);
        assert_eq!(time, version.parent_time);
    }

    // The first snapshot still verifies on its own and is stale once the
    // reader learns the newest anchor.
    let latest = parent
        .client
        .read_latest_anchor(&laptop_id, third.parent_height, &parent.key)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(latest, third.record);
    assert!(matches!(
        verified.ensure_current(&latest),
        Err(AnchoringError::Stale { held: 1, latest: 3 })
    ));
    newest.ensure_current(&latest).unwrap();
    // The phone's anchors are counted on their own.
    let phone_latest = parent
        .client
        .read_latest_anchor(&phone_id, 0, &parent.key)
        .await
        .unwrap()
        .record
        .unwrap();
    phone_verified.ensure_current(&phone_latest).unwrap();

    // A second device opens the laptop's deployment from its export and
    // finalizes a different history under the same key.
    let fork = Baby::open(directories[2].path(), laptop_deployment, true).await;
    assert_eq!(fork.key, laptop.key);
    let fork_author = BlsSigner::random(fork.chain_id).unwrap();
    fork.share_notes(&fork_author, OTHER).await;
    let anchored = third.record.height;
    let conflicting = fork.revision_at(anchored).await;
    assert_ne!(block_hash(&conflicting), third.record.block_hash);
    assert_eq!(
        parent
            .try_anchor(&laptop_relay, &conflicting, &fork.key)
            .await,
        Err(RefusalKind::NotNewer),
        "a conflicting block at an anchored height loses to the first one"
    );
    let below = fork.revision_at(anchored - 1).await;
    assert_eq!(
        parent.try_anchor(&laptop_relay, &below, &fork.key).await,
        Err(RefusalKind::NotNewer),
    );
    let unchanged = parent
        .client
        .read_latest_anchor(&laptop_id, 0, &parent.key)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(unchanged, third.record);

    // The parent does not check ancestry between anchors, so the fork's block
    // above the anchored height is accepted as the laptop's next anchor. A
    // reader detects the fork only by comparing the two anchored histories.
    let above = fork.revision_at(anchored + 2).await;
    let submission = parent
        .try_anchor(&laptop_relay, &above, &fork.key)
        .await
        .expect("a fork above the latest anchor is not detected by the parent");
    let (event, _) = parent.anchored_event(submission).await;
    assert_eq!(
        (event.sequence, event.height, event.blockHash.0),
        (4, anchored + 2, block_hash(&above).0)
    );
    assert!(matches!(
        newest.ensure_current(
            &parent
                .client
                .read_latest_anchor(&laptop_id, 0, &parent.key)
                .await
                .unwrap()
                .record
                .unwrap()
        ),
        Err(AnchoringError::Stale { held: 3, latest: 4 })
    ));

    for node in [fork, laptop, phone] {
        node.node.stop().await.unwrap();
    }
}
