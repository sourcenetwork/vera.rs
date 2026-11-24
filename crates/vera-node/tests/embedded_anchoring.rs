//! A deployment anchors a policy snapshot in another deployment; a reader that
//! trusts only the anchoring deployment verifies a relayed copy and learns when
//! it is superseded.

use std::{net::SocketAddr, path::Path, time::Duration};

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_client::administration::{
    AdministrativeCommand, AdministrativeRequest, OperatorPolicy, SignedAdministrativeRequest,
    approve_administration,
};
use vera_client::{
    AccessRequest, Actor, BlsSigner, Object, Operation, VeraClient,
    anchoring::{
        AnchorSubmitterGrant, AnchoredSnapshot, AnchoringError, DeploymentRegistration,
        deployment_id,
    },
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
/// The account key of both deployments, and the secret it is the public key of.
const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ACCOUNT_SECRET: [u8; 32] = {
    let mut secret = [0; 32];
    secret[31] = 1;
    secret
};

fn config(directory: &Path, chain_id: u64) -> EmbeddedConfig {
    let genesis = SoloGenesis {
        policies: Vec::new(),
        chain_id,
        operators: operators(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let mut config = EmbeddedConfig::new(directory, genesis, SocketAddr::from(([127, 0, 0, 1], 0)));
    config.rpc_listen = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    config
}

fn operators() -> OperatorPolicy {
    OperatorPolicy {
        threshold: 1,
        keys: vec![ACCOUNT_KEY.into()],
    }
}

/// The identifier of a deployment's genesis block: the parent of its first block.
async fn genesis_id(client: &VeraClient, key: &vera_domain::ConsensusPublicKey) -> B256 {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        if let Ok(first) = client.read_finalized_revision(1, key).await {
            return first.parent_hash.parse().unwrap();
        }
        assert!(tokio::time::Instant::now() < deadline, "no first revision");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Apply `commands` on the anchoring deployment, approved by its account key.
async fn administer(
    anchoring: &VeraClient,
    key: &vera_domain::ConsensusPublicKey,
    commands: Vec<AdministrativeCommand>,
) {
    let account = vera_client::Secp256k1SigningKey::from_bytes(&ACCOUNT_SECRET.into()).unwrap();
    let genesis = genesis_id(anchoring, key).await;
    let operator = BlsSigner::random(anchoring.chain_id().await.unwrap()).unwrap();
    let first = anchoring.administration().await.unwrap().unwrap().sequence;
    for (sequence, command) in (first..).zip(commands) {
        let request = AdministrativeRequest {
            genesis_id: genesis.0,
            sequence,
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
            command,
        };
        let approvals = vec![approve_administration(&request, 0, &account).unwrap()];
        let receipt = anchoring
            .native_apply_administration(
                &operator,
                &SignedAdministrativeRequest { request, approvals },
            )
            .await
            .unwrap();
        assert!(receipt.success);
    }
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
    assert!(created.success);
    let policy = d.get_policy_ids().await.unwrap().remove(0);
    let policy_id = vera_client::parse_policy_id(&policy).unwrap();
    let registered = d
        .native_register_object(&author, policy_id, "notes", "collection")
        .await
        .unwrap();
    assert!(registered.success);
    let granted = d
        .native_set_relationship(&author, policy_id, "collection", "notes", "reader", READER)
        .await
        .unwrap();
    assert!(granted.success);

    let relay = BlsSigner::new(82u64.into(), anchoring_chain).unwrap();
    // The anchoring deployment's operators admit the owner's deployment and its relay.
    assert!(
        d.publish_policy_snapshot(&s, &relay, &policy, &owner_key, &anchoring_key, DEADLINE)
            .await
            .is_err(),
        "nothing is anchored for a deployment that is not registered"
    );
    administer(
        &s,
        &anchoring_key,
        vec![
            AdministrativeCommand::RegisterDeployment(DeploymentRegistration {
                consensus_key: hex::encode(owner_key.encode()),
                genesis_id: genesis_id(&d, &owner_key).await.0,
                operators: operators(),
            }),
            AdministrativeCommand::SetAnchorSubmitter(AnchorSubmitterGrant {
                deployment: deployment.0,
                submitter: relay.did().to_owned(),
                quota: 16,
            }),
        ],
    )
    .await;
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
    assert!(revoked.success);
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
        .submit_anchor(&relay, &first.revision, &owner_key, None)
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
