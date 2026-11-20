//! A deployment anchors a policy snapshot in another deployment; a reader that
//! trusts only the anchoring deployment verifies a relayed copy and learns when
//! it is superseded.

use std::{net::SocketAddr, path::Path, time::Duration};

use alloy_primitives::B256;
use vera_client::administration::OperatorPolicy;
use vera_client::{
    AccessRequest, Actor, BlsSigner, Object, Operation, VeraClient,
    anchoring::{AnchoredSnapshot, AnchoringError, deployment_id},
};
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloGenesis};

const POLICY: &str = "\
name: shared-home
resources:
  - name: collection
    relations:
      - name: reader
        types: [actor]
    permissions:
      - name: read
        expr: reader
";
const READER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const DEADLINE: Duration = Duration::from_secs(60);

fn config(directory: &Path, chain_id: u64) -> EmbeddedConfig {
    let genesis = SoloGenesis {
        policies: Vec::new(),
        chain_id,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec!["0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let mut config = EmbeddedConfig::new(directory, genesis, SocketAddr::from(([127, 0, 0, 1], 0)));
    config.rpc_listen = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    config
}

fn client(node: &EmbeddedNode) -> VeraClient {
    VeraClient::new(format!("http://{}", node.rpc_addr().unwrap()))
}

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

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_snapshot_verifies_against_the_anchor_and_goes_stale_after_a_revocation() {
    let owner_dir = tempfile::tempdir().unwrap();
    let anchoring_dir = tempfile::tempdir().unwrap();
    let owner_chain = 9431;
    let anchoring_chain = 9432;
    let owner = EmbeddedNode::start(config(owner_dir.path(), owner_chain))
        .await
        .unwrap();
    let anchoring = EmbeddedNode::start(config(anchoring_dir.path(), anchoring_chain))
        .await
        .unwrap();
    let (d, s) = (client(&owner), client(&anchoring));
    let owner_key = *owner.consensus_key();
    let anchoring_key = *anchoring.consensus_key();
    let deployment = deployment_id(&owner_key);

    let author = BlsSigner::new(81u64.into(), owner_chain).unwrap();
    let created = d
        .native_create_policy(
            &author,
            POLICY.as_bytes(),
            1,
            vera_client::random_policy_nonce(),
        )
        .await
        .unwrap();
    assert_eq!(created.status, 1);
    let policy = d.get_policy_ids().await.unwrap().remove(0);
    let policy_id = vera_client::parse_policy_id(&policy).unwrap();
    let registered = d
        .native_register_object(&author, policy_id, "notes", "collection")
        .await
        .unwrap();
    assert_eq!(registered.status, 1);
    let granted = d
        .native_set_relationship(&author, policy_id, "collection", "notes", "reader", READER)
        .await
        .unwrap();
    assert_eq!(granted.status, 1);

    let relay = BlsSigner::new(82u64.into(), anchoring_chain).unwrap();
    let first = d
        .publish_policy_snapshot(&s, &relay, &policy, &owner_key, &anchoring_key, DEADLINE)
        .await
        .unwrap();

    // A third party relays the snapshot as bytes; the reader trusts only the anchoring key.
    let relayed = AnchoredSnapshot::decode(&first.encode()).unwrap();
    let verified = relayed
        .verify(&deployment, &policy, &anchoring_key, 0)
        .unwrap();
    assert_eq!(verified.anchor.sequence, 1);
    assert!(verified.state.exists());
    assert!(verified.check(&read(READER)).unwrap());
    assert!(
        !verified
            .check(&read(
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            ))
            .unwrap()
    );
    let latest = s
        .read_latest_anchor(&deployment, 0, &anchoring_key)
        .await
        .unwrap();
    verified
        .ensure_current(latest.record.as_ref().unwrap())
        .unwrap();

    // A snapshot whose relationships were changed does not verify.
    let mut altered = first.clone();
    let relationships = &mut altered.proof.prefixes[0].proof;
    let mut bytes = relationships.to_vec();
    let position = bytes
        .windows(b"reader".len())
        .position(|window| window == b"reader")
        .expect("the relationship record names its relation");
    bytes[position] = b'R';
    *relationships = bytes.into();
    assert!(
        altered
            .verify(&deployment, &policy, &anchoring_key, 0)
            .is_err()
    );

    // The snapshot of another deployment's anchor is refused.
    assert!(
        first
            .verify(&B256::repeat_byte(3), &policy, &anchoring_key, 0)
            .is_err()
    );

    let revoked = d
        .native_delete_relationship(&author, policy_id, "collection", "notes", "reader", READER)
        .await
        .unwrap();
    assert_eq!(revoked.status, 1);
    let second = d
        .publish_policy_snapshot(&s, &relay, &policy, &owner_key, &anchoring_key, DEADLINE)
        .await
        .unwrap();
    let newer = second
        .verify(&deployment, &policy, &anchoring_key, 0)
        .unwrap();
    assert_eq!(newer.anchor.sequence, 2);
    assert!(!newer.check(&read(READER)).unwrap());

    // The holder of the old snapshot still verifies it on its own, and is told
    // it is stale once it learns the newer anchor.
    let latest = s
        .read_latest_anchor(&deployment, 0, &anchoring_key)
        .await
        .unwrap()
        .record
        .unwrap();
    assert!(matches!(
        verified.ensure_current(&latest),
        Err(AnchoringError::Stale { held: 1, latest: 2 })
    ));

    // The old revision presented with the newer anchor's evidence does not verify.
    let mut mixed = first.clone();
    mixed.anchor = second.anchor.clone();
    assert!(matches!(
        mixed.verify(&deployment, &policy, &anchoring_key, 0),
        Err(AnchoringError::NotAnchored { .. })
    ));

    // The older revision cannot be anchored again.
    let resubmitted = s
        .submit_anchor(&relay, &first.revision, &owner_key)
        .await
        .unwrap();
    assert!(matches!(
        s.await_anchor(resubmitted, &anchoring_key, DEADLINE).await,
        Err(vera_client::ClientError::Anchoring(
            AnchoringError::Refused(_)
        ))
    ));

    owner.stop().await.unwrap();
    anchoring.stop().await.unwrap();
}
