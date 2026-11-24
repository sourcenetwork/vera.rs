//! A baby deployment: one embedded validator on a user's device, holding its own policy.

use std::{net::SocketAddr, path::Path, time::Duration};

use alloy_primitives::B256;
use vera_client::{BlsSigner, VeraClient};
use vera_domain::{ConsensusPublicKey, LightBlock};
use vera_modules::vera::administration::OperatorPolicy;
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloDeployment, SoloGenesis};

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
const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

pub(crate) struct Baby {
    pub(crate) node: EmbeddedNode,
    pub(crate) client: VeraClient,
    pub(crate) key: ConsensusPublicKey,
    pub(crate) chain_id: u64,
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// The operator policy of every baby: its owner's account key.
pub(crate) fn operators() -> OperatorPolicy {
    OperatorPolicy {
        threshold: 1,
        keys: vec![ACCOUNT_KEY.into()],
    }
}

/// A new deployment dealt in memory, as a host keeps it in its keystore.
pub(crate) fn deal(chain_id: u64) -> SoloDeployment {
    let identity = SoloGenesis {
        policies: Vec::new(),
        chain_id,
        operators: operators(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    SoloDeployment::create(&identity, loopback()).unwrap()
}

impl Baby {
    /// Open `deployment` in `directory`. `continuous` proposes at the daemon's
    /// cadence instead of waiting for requests, so the chain grows on its own.
    pub(crate) async fn open(
        directory: &Path,
        deployment: SoloDeployment,
        continuous: bool,
    ) -> Self {
        let chain_id = deployment.identity().unwrap().chain_id;
        let mut config = EmbeddedConfig::adopt(directory, deployment, loopback()).unwrap();
        config.rpc_listen = Some(loopback());
        if continuous {
            config.pacing = None;
        }
        let node = EmbeddedNode::start(config).await.unwrap();
        let client = VeraClient::new(format!("http://{}", node.rpc_addr().unwrap()));
        let key = *node.consensus_key();
        Self {
            node,
            client,
            key,
            chain_id,
        }
    }

    /// Create the policy, register `notes` under it and grant `reader` read access.
    pub(crate) async fn share_notes(&self, author: &BlsSigner, reader: &str) -> String {
        let created = self
            .client
            .native_create_policy(
                author,
                POLICY.as_bytes(),
                1,
                vera_client::random_policy_nonce(),
            )
            .await
            .unwrap();
        assert!(created.success);
        let policy = self.client.get_policy_ids().await.unwrap().remove(0);
        let id = vera_client::parse_policy_id(&policy).unwrap();
        let registered = self
            .client
            .native_register_object(author, id, "notes", "collection")
            .await
            .unwrap();
        assert!(registered.success);
        self.grant(author, &policy, reader).await;
        policy
    }

    pub(crate) async fn grant(&self, author: &BlsSigner, policy: &str, reader: &str) {
        let id = vera_client::parse_policy_id(policy).unwrap();
        let granted = self
            .client
            .native_set_relationship(author, id, "collection", "notes", "reader", reader)
            .await
            .unwrap();
        assert!(granted.success);
    }

    pub(crate) async fn revoke(&self, author: &BlsSigner, policy: &str, reader: &str) {
        let id = vera_client::parse_policy_id(policy).unwrap();
        let revoked = self
            .client
            .native_delete_relationship(author, id, "collection", "notes", "reader", reader)
            .await
            .unwrap();
        assert!(revoked.success);
    }

    /// Wait until the deployment has finalized `height`, then return that revision.
    pub(crate) async fn revision_at(&self, height: u64) -> LightBlock {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let reached = self
                .client
                .node_status()
                .await
                .unwrap()
                .finalized_height
                .unwrap_or(0);
            if reached >= height {
                return self
                    .client
                    .read_finalized_revision(height, &self.key)
                    .await
                    .unwrap();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "baby stalled at height {reached}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// The identifier of a revision's block, as an anchor records it.
pub(crate) fn block_hash(revision: &LightBlock) -> B256 {
    alloy_primitives::keccak256(revision.artifacts().unwrap().block)
}
