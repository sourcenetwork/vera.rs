//! A parent deployment of four validators anchors the revisions of two baby
//! deployments, each one embedded validator. A reader that trusts only the
//! parent's key verifies relayed policy snapshots and learns when they are
//! stale; a baby's anchors are one chain, each proven to descend from the one
//! before; one count orders the anchors of both babies; a second device's
//! history under the same key is refused and recorded as a fork.
//!
//! Requires `cargo build -p verad` before running.

#[path = "support/administration.rs"]
mod administration;
#[path = "parent_baby/anchor.rs"]
mod anchor;
#[path = "parent_baby/baby.rs"]
mod baby;

use alloy_primitives::B256;
use anchor::Parent;
use baby::{Baby, block_hash};
use vera_client::{
    AccessRequest, Actor, BlsSigner, Object, Operation, RefusalKind, VeraClient,
    anchoring::{AnchorEntry, AnchoredSnapshot, AnchoringError, deployment_id},
};
use vera_domain::{TermChange, TermCut};
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
        .genesis(GenesisBuilder::devnet().operators(administration::operators()))
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .expect("parent cluster should start");
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .expect("parent cluster should become healthy");
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let parent = Parent {
        client,
        key,
        sequence: 0.into(),
    };
    (cluster, parent)
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

    // The parent's operators admit each baby and the relay that submits for
    // it. Until then nothing of a baby is anchored, by anyone.
    let first_revision = laptop.revision_at(1).await;
    let refused = parent
        .try_submit(&laptop_relay, &laptop, &first_revision)
        .await
        .expect_err("a signer without a grant is refused at admission");
    assert!(refused.to_string().contains("may not submit anchors"));
    parent.register(&laptop).await;
    parent.register(&phone).await;
    parent.grant(&laptop, &laptop_relay, 64).await;
    parent.grant(&phone, &phone_relay, 64).await;
    // A grant is for one deployment: the phone's relay is not the laptop's.
    assert!(
        parent
            .try_submit(&phone_relay, &laptop, &first_revision)
            .await
            .is_err()
    );
    let registered = parent
        .client
        .read_registered_deployment(&deployment_id(&laptop.key), 0, &parent.key)
        .await
        .unwrap()
        .expect("a third party reads the registration");
    assert_eq!(registered.operators, baby::operators());
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
    // The parent numbers the anchors of both babies in one order, so a reader
    // compares the two verified anchors although each baby counts its own.
    assert_eq!((verified.anchor.order, phone_verified.anchor.order), (1, 2));
    assert!(verified.anchored_before(&phone_verified));
    assert!(!phone_verified.anchored_before(&verified));
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
        assert!(later.record.order > earlier.record.order);
        assert!(later.record.height > earlier.record.height);
        assert!(later.parent_height > earlier.parent_height);
        assert!(later.parent_time >= earlier.parent_time);
    }
    // The phone's anchor came between the laptop's first and second.
    assert_eq!(
        [first.record.order, second.record.order, third.record.order],
        [1, 3, 4]
    );
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

    // The certified receipt of each anchor carries its event and the time of
    // the parent's revision that recorded it.
    for version in versions {
        let (event, time) = parent.anchored_event(version.submission).await;
        assert_eq!(
            (event.sequence, event.order),
            (version.record.sequence, version.record.order)
        );
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
        parent.try_anchor(&laptop_relay, &fork, &conflicting).await,
        Err(RefusalKind::NotNewer),
        "a conflicting block at an anchored height loses to the first one"
    );
    let below = fork.revision_at(anchored - 1).await;
    assert_eq!(
        parent.try_anchor(&laptop_relay, &fork, &below).await,
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

    // The fork's block above the anchored height carries a certificate, but
    // it does not descend from the anchored block: the proof its node gives
    // names its own block at that height.
    let above = fork.revision_at(anchored + 2).await;
    assert_eq!(
        parent.try_anchor(&laptop_relay, &fork, &above).await,
        Err(RefusalKind::NotDescendant),
        "a block of another history is not the laptop's next anchor"
    );
    let latest = || async {
        parent
            .client
            .read_latest_anchor(&laptop_id, 0, &parent.key)
            .await
            .unwrap()
            .record
            .unwrap()
    };
    assert_eq!(latest().await, third.record);

    // Reported, both of the fork's blocks are evidence that the key finalized
    // two histories. A third party reads it with the parent's key alone.
    assert!(
        parent
            .client
            .read_forks(&laptop_id, B256::ZERO, 128, 0, &parent.key)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    for height in [anchored, anchored + 2] {
        parent
            .try_report_fork(&laptop_relay, &fork, height, &third.record)
            .await
            .expect("a block of another history is a fork");
    }
    assert_eq!(
        parent
            .try_report_fork(&laptop_relay, &fork, anchored + 2, &third.record)
            .await,
        Err(RefusalKind::AlreadyExists)
    );
    // The laptop's own history is no fork of its anchor.
    assert_eq!(
        parent
            .try_report_fork(&laptop_relay, &laptop, anchored, &third.record)
            .await,
        Err(RefusalKind::InvalidProof)
    );
    let mut forks = parent
        .client
        .read_forks(&laptop_id, B256::ZERO, 128, 0, &parent.key)
        .await
        .unwrap()
        .entries;
    forks.sort_by_key(|fork| fork.height);
    assert_eq!(forks.len(), 2);
    for (record, revision) in forks.iter().zip([&conflicting, &above]) {
        assert_eq!(record.sequence, third.record.sequence);
        assert_eq!(record.anchored_height, anchored);
        assert_eq!(record.anchored_block, third.record.block_hash);
        assert_eq!(record.height, revision.height);
        assert_eq!(record.block_hash, block_hash(revision));
        assert_eq!(record.ancestor, block_hash(&conflicting));
    }
    assert!(
        parent
            .client
            .read_forks(&phone_id, B256::ZERO, 128, 0, &parent.key)
            .await
            .unwrap()
            .entries
            .is_empty()
    );

    // The fork does not lock the laptop out: its next version is anchored on
    // top of the third, and the reader learns its snapshot is stale.
    laptop.revoke(&laptop_author, &laptop_policy, OTHER).await;
    let fourth = parent
        .anchor_policy(&laptop, &laptop_relay, &laptop_policy)
        .await;
    // The refused anchors and the fork reports took no number.
    assert_eq!((fourth.record.sequence, fourth.record.order), (4, 5));
    assert!(fourth.record.height > anchored);
    assert!(matches!(
        newest.ensure_current(&latest().await),
        Err(AnchoringError::Stale { held: 3, latest: 4 })
    ));

    // The parent keeps every anchor. A third party pages through the laptop's
    // policy versions in order with the parent's key alone.
    let page = parent
        .client
        .read_anchor_history(&laptop_id, 1, 3, 0, &parent.key)
        .await
        .unwrap();
    assert_eq!((page.entries.len(), page.next), (3, Some(4)));
    let rest = parent
        .client
        .read_anchor_history(&laptop_id, 4, 3, page.revision, &parent.key)
        .await
        .unwrap();
    assert_eq!((rest.entries.len(), rest.next), (1, None));
    assert!(rest.revision >= page.revision);
    let history = [page.entries, rest.entries].concat();
    for (entry, version) in history.iter().zip([&first, &second, &third, &fourth]) {
        assert_eq!(*entry, AnchorEntry::from(&version.record));
        assert_eq!(entry.anchored_at, version.parent_height);
    }
    let phone_history = parent
        .client
        .read_anchor_history(&phone_id, 1, 16, 0, &parent.key)
        .await
        .unwrap();
    assert_eq!(
        phone_history.entries,
        [AnchorEntry::from(&phone_first.record)]
    );
    assert_eq!(phone_history.next, None);

    // The laptop's owner moves the active role to a device that held the
    // chain up to the second anchor. Only the laptop's operators certify that.
    let change = TermChange {
        genesis_id: administration::genesis_id(&laptop.client).await,
        term: 1,
        holder: B256::repeat_byte(0xd1),
        cut: TermCut {
            height: second.record.height,
            block: second.record.block_hash,
        },
    };
    assert_eq!(
        parent
            .try_change_term(&laptop_relay, &laptop, &baby::certify(change, 2))
            .await,
        Err(RefusalKind::InvalidProof),
        "a term is recorded only under the baby's operator policy"
    );
    assert!(
        parent
            .client
            .read_anchor_terms(&laptop_id, 0, 128, 0, &parent.key)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    parent
        .try_change_term(&laptop_relay, &laptop, &baby::certify(change, 1))
        .await
        .expect("the baby's operators certify the term");

    // A third party reads the terms above its anchors' term with the
    // parent's key alone and learns which snapshots they voided: those of
    // anchors above the cut.
    let terms = parent
        .client
        .read_anchor_terms_above(&laptop_id, 0, 0, &parent.key)
        .await
        .unwrap();
    assert_eq!(
        parent
            .client
            .read_anchor_terms(&laptop_id, 0, 128, 0, &parent.key)
            .await
            .unwrap()
            .entries,
        terms
    );
    let [term] = terms.as_slice() else {
        panic!("one term is recorded");
    };
    assert_eq!((term.term, term.sequence), (1, 4));
    assert_eq!(
        (term.cut_height, term.cut_block),
        (second.record.height, second.record.block_hash)
    );
    verified.ensure_kept(&terms).unwrap();
    second
        .snapshot
        .verify(&laptop_id, &laptop_policy, &parent.key, 0)
        .unwrap()
        .ensure_kept(&terms)
        .unwrap();
    assert!(matches!(
        newest.ensure_kept(&terms),
        Err(AnchoringError::Superseded { held: 3, term: 1 })
    ));
    assert!(matches!(
        fourth
            .snapshot
            .verify(&laptop_id, &laptop_policy, &parent.key, 0)
            .unwrap()
            .ensure_kept(&terms),
        Err(AnchoringError::Superseded { held: 4, term: 1 })
    ));
    phone_verified.ensure_kept(&[]).unwrap();

    // The chain continues from the cut in term 1. The laptop still builds in
    // term 0, so its blocks above the cut are void and anchor nothing.
    let lineage = parent
        .client
        .read_anchor_lineage(&laptop_id, 0, &parent.key)
        .await
        .unwrap();
    assert_eq!(
        lineage.tip(),
        Some((second.record.height, second.record.block_hash))
    );
    let void = laptop.revision_at(fourth.record.height).await;
    assert_eq!(
        parent.try_anchor(&laptop_relay, &laptop, &void).await,
        Err(RefusalKind::NotNewer)
    );
    // The term voided the third and fourth anchors and renumbered none.
    let after_term = parent
        .client
        .read_anchor_history(&laptop_id, 1, 16, 0, &parent.key)
        .await
        .unwrap()
        .entries;
    assert_eq!(after_term, history);
    assert_eq!(
        after_term
            .iter()
            .map(|entry| entry.order)
            .collect::<Vec<_>>(),
        [1, 3, 4, 5]
    );

    for node in [fork, laptop, phone] {
        node.node.stop().await.unwrap();
    }
}
