//! A deployment switches its active device while another deployment anchors
//! it: the new term's blocks are anchored only under the term certificate,
//! and the chain of anchors continues from the certificate's cut.

#[allow(
    dead_code,
    reason = "shared with tests that switch devices in other ways"
)]
#[path = "support/devices.rs"]
mod devices;
#[allow(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
#[allow(
    dead_code,
    reason = "shared with tests that write through the method table"
)]
mod support;

use std::{net::SocketAddr, time::Duration};

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use devices::{certify, pair};
use vera_client::administration::{
    AdministrativeCommand, AdministrativeRequest, OperatorPolicy, SignedAdministrativeRequest,
    approve_administration,
};
use vera_client::{
    BlsSigner, ClientError, RefusalKind, VeraClient,
    anchoring::{AnchorSubmitterGrant, AnchoringError, DeploymentRegistration, deployment_id},
};
use vera_domain::ConsensusPublicKey;
use vera_node::{EmbedError, EmbeddedNode, TermRefusal};

const DEADLINE: Duration = Duration::from_secs(60);
const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn loopback() -> Option<SocketAddr> {
    Some(SocketAddr::from(([127, 0, 0, 1], 0)))
}

fn client(node: &EmbeddedNode) -> VeraClient {
    VeraClient::new(format!("http://{}", node.rpc_addr().unwrap()))
}

async fn height(client: &VeraClient) -> u64 {
    client
        .node_status()
        .await
        .unwrap()
        .finalized_height
        .unwrap_or(0)
}

async fn reach(client: &VeraClient, target: u64) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while height(client).await < target {
        assert!(
            tokio::time::Instant::now() < deadline,
            "stalled below {target}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The identifier of a deployment's genesis block: the parent of its first block.
async fn genesis_id(client: &VeraClient, key: &ConsensusPublicKey) -> B256 {
    reach(client, 1).await;
    let first = client.read_finalized_revision(1, key).await.unwrap();
    first.parent_hash.parse().unwrap()
}

/// The anchoring deployment and the relay its operators admit.
struct Anchoring {
    client: VeraClient,
    key: ConsensusPublicKey,
    relay: BlsSigner,
}

impl Anchoring {
    /// Register the deployment with consensus key `owner` and grant the relay.
    async fn admit(&self, owner: &ConsensusPublicKey, genesis: B256) {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let account = vera_client::Secp256k1SigningKey::from_bytes((&secret).into()).unwrap();
        let own_genesis = genesis_id(&self.client, &self.key).await;
        let operator = BlsSigner::random(self.client.chain_id().await.unwrap()).unwrap();
        let commands = [
            AdministrativeCommand::RegisterDeployment(DeploymentRegistration {
                consensus_key: hex::encode(owner.encode()),
                genesis_id: genesis.0,
                operators: OperatorPolicy {
                    threshold: 1,
                    keys: vec![ACCOUNT_KEY.into()],
                },
            }),
            AdministrativeCommand::SetAnchorSubmitter(AnchorSubmitterGrant {
                deployment: deployment_id(owner).0,
                submitter: self.relay.did().to_owned(),
                quota: 16,
            }),
        ];
        for (sequence, command) in (0..).zip(commands) {
            let request = AdministrativeRequest {
                genesis_id: own_genesis.0,
                sequence,
                expires_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 300,
                command,
            };
            let approvals = vec![approve_administration(&request, 0, &account).unwrap()];
            let receipt = self
                .client
                .native_apply_administration(
                    &operator,
                    &SignedAdministrativeRequest { request, approvals },
                )
                .await
                .unwrap();
            assert!(receipt.success);
        }
    }

    /// Anchor the revision of `device` at `height` and return the refusal, if any.
    async fn anchor(
        &self,
        device: &VeraClient,
        owner: &ConsensusPublicKey,
        height: u64,
    ) -> Result<(), RefusalKind> {
        let revision = device.read_finalized_revision(height, owner).await.unwrap();
        let lineage = self
            .client
            .read_anchor_lineage(&deployment_id(owner), 0, &self.key)
            .await
            .unwrap();
        let proof = device.anchor_proof(lineage.tip(), height).await.unwrap();
        let submission = self
            .client
            .submit_anchor(&self.relay, &revision, owner, proof.as_ref())
            .await
            .unwrap();
        self.outcome(submission).await
    }

    async fn outcome(&self, submission: B256) -> Result<(), RefusalKind> {
        match self
            .client
            .await_anchor(submission, &self.key, DEADLINE)
            .await
        {
            Ok(_) => Ok(()),
            Err(ClientError::Anchoring(AnchoringError::Refused(refusal))) => Err(refusal.kind),
            Err(error) => panic!("neither recorded nor refused: {error}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_switch_is_anchored_under_its_certificate_and_continues_from_its_cut() {
    let directories = [(); 3].map(|()| tempfile::tempdir().unwrap());
    let mut anchoring_config = support::config(directories[2].path(), 9_441);
    anchoring_config.rpc_listen = loopback();
    let anchoring_node = EmbeddedNode::start(anchoring_config).await.unwrap();

    let dealt = short_epochs::deployment(9_442, 93);
    let [mut first, mut second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        Duration::from_secs(30),
    );
    first.active.rpc_listen = loopback();
    second.backup.rpc_listen = loopback();
    let mut laptop = EmbeddedNode::start(first.active.clone()).await.unwrap();
    let mut phone = EmbeddedNode::start(second.backup.clone()).await.unwrap();
    let owner = *laptop.consensus_key();
    let deployment = deployment_id(&owner);
    let (laptop_client, phone_client) = (client(&laptop), client(&phone));

    let anchoring = Anchoring {
        client: client(&anchoring_node),
        key: *anchoring_node.consensus_key(),
        relay: BlsSigner::random(9_441).unwrap(),
    };
    anchoring
        .admit(&owner, genesis_id(&laptop_client, &owner).await)
        .await;

    // Term 0: the laptop's chain is anchored.
    let anchored = height(&laptop_client).await.max(2);
    reach(&laptop_client, anchored).await;
    anchoring
        .anchor(&laptop_client, &owner, anchored)
        .await
        .unwrap();

    // The laptop hands over to the phone, and the account's operator certifies it.
    let change = loop {
        match laptop.hand_over(&second.key.public_key()).await {
            Ok(change) => break change,
            Err(EmbedError::Term(
                TermRefusal::Unsettled | TermRefusal::SuccessorNotCurrent { .. },
            )) => tokio::time::sleep(Duration::from_secs(1)).await,
            Err(error) => panic!("{error}"),
        }
    };
    let cut = change.cut.height;
    assert!(cut >= anchored);
    let certificate = certify(change);
    phone
        .take_over(dealt.keys().clone(), certificate.clone())
        .await
        .unwrap();
    laptop.follow(certificate.clone()).await.unwrap();
    let phone_client = {
        drop(phone_client);
        client(&phone)
    };
    reach(&phone_client, cut + 2).await;

    // The phone's block is in term 1 and does descend from the anchor, but the
    // anchoring deployment holds no certificate of that term yet.
    assert_eq!(
        anchoring.anchor(&phone_client, &owner, cut + 2).await,
        Err(RefusalKind::Unauthorized)
    );
    let submission = anchoring
        .client
        .submit_term_change(&anchoring.relay, &owner, &certificate)
        .await
        .unwrap();
    anchoring.outcome(submission).await.unwrap();

    let lineage = anchoring
        .client
        .read_anchor_lineage(&deployment, 0, &anchoring.key)
        .await
        .unwrap();
    assert_eq!(lineage.certified_term(), 1);
    assert_eq!(lineage.tip(), Some((cut, certificate.change.cut.block)));
    let first_anchor = lineage
        .latest
        .clone()
        .expect("the term-0 anchor is the latest");
    assert_eq!((first_anchor.sequence, first_anchor.term), (1, 0));

    // The term's first anchor proves the cut.
    anchoring
        .anchor(&phone_client, &owner, cut + 2)
        .await
        .unwrap();
    let latest = anchoring
        .client
        .read_latest_anchor(&deployment, 0, &anchoring.key)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(
        (latest.sequence, latest.height, latest.term),
        (2, cut + 2, 1)
    );

    // The handover lost no block, so the term voids no anchor.
    let terms = anchoring
        .client
        .read_anchor_terms(&deployment, 0, &anchoring.key)
        .await
        .unwrap();
    assert_eq!(terms.len(), 1);
    for anchor in [&first_anchor, &latest] {
        assert!(!terms[0].supersedes(anchor.sequence, anchor.height, &anchor.block_hash));
    }

    for node in [laptop, phone, anchoring_node] {
        node.stop().await.unwrap();
    }
}
