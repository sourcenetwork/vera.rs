//! Cross-object ACP: storage, replication, and resolution across a cluster.
//!
//! Seeds a cross-object "parent edge" (a relationship whose subject is another
//! object) plus a child grant on node 0, then on every other node asserts both
//! that they replicate and that an access check *resolves* across the edge: a
//! subject granted on the parent inherits access to the child through
//! `parent->reader`, evaluated on-chain by acp. (Simplex BFT requires ≥4 nodes for quorum, so
//! the "seed on one, resolve on another" check uses the 4-node minimum.)
//!
//! Requires `cargo build -p verad` (and `VERAD_BINARY`) before running.

#[path = "support/broadcast.rs"]
mod broadcast;
#[path = "support/native_receipt.rs"]
mod native_receipt;

use std::time::Duration;

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;

use vera_client::{ACP_ADDRESS, BlsSigner, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use vera_e2e::observe::ClusterAssertions;
use vera_modules::acp::abi::IAcp;

/// Policy with a `document` whose `read` inherits from `reader` on its parent
/// `collection` (`parent->reader`), so a `document#parent` edge can point at a
/// collection.
const TEST_POLICY_YAML: &str = "\
name: cross-object-policy
resources:
  - name: collection
    relations:
      - name: reader
    permissions:
      - name: read
        expr: reader
      - name: update
      - name: delete
  - name: document
    relations:
      - name: parent
        types: [collection]
      - name: reader
    permissions:
      - name: read
        expr: reader + parent->reader
      - name: update
      - name: delete
";

fn parse_policy_id(hex_str: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode_to_slice(hex, &mut bytes).expect("policy ID should be valid hex");
    FixedBytes::from(bytes)
}

#[tokio::test]
async fn cross_object_grant_replicates_across_nodes() {
    let chain_id = 9001;
    let genesis = GenesisBuilder::devnet();

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .chain_id(chain_id)
        .genesis(genesis)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .expect("cluster should start");

    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .expect("cluster should become healthy");

    let state = cluster.observe(Duration::from_millis(200));
    state
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("should reach height 3");

    let client = VeraClient::new(cluster.node(0).rpc_url());
    let signer = BlsSigner::random(chain_id).expect("random BLS signer");

    let alice = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

    // ── 1. Create the policy on node 0 (the signer becomes its owner) ──────
    let create = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
    }
    .abi_encode();
    let create_receipt = broadcast::native(&cluster, &client, &signer, ACP_ADDRESS, create).await;
    assert!(create_receipt.success, "createPolicy should succeed");

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert_eq!(policy_ids.len(), 1, "exactly one policy expected");
    let policy_id = parse_policy_id(&policy_ids[0]);

    for (resource, object_id) in [("document", "doc1"), ("collection", "col1")] {
        let register = IAcp::registerObjectCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
        }
        .abi_encode();
        let receipt = broadcast::native(&cluster, &client, &signer, ACP_ADDRESS, register).await;
        assert!(receipt.success, "register {resource}/{object_id}");
    }

    // ── 2. Seed the parent edge via setRelationshipSubject ───────────────
    // document:doc1#parent @ collection:col1 — an object subject (subjectKind
    // 2), the cross-object shape the actor-only setRelationship cannot express.
    // The signer registered both objects and owns them.
    let parent_calldata = IAcp::setRelationshipSubjectCall {
        policyId: policy_id,
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "parent".into(),
        subjectKind: 2,
        subjectResource: "collection".into(),
        subjectObjectId: "col1".into(),
        subjectRelation: String::new(),
    }
    .abi_encode();
    let parent_receipt =
        broadcast::native(&cluster, &client, &signer, ACP_ADDRESS, parent_calldata).await;
    assert!(
        parent_receipt.success,
        "setting the parent edge should succeed"
    );

    // ── 3. Seed the child grant: collection:col1#reader @ alice ──────────
    let grant = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "collection".into(),
        objectId: "col1".into(),
        relation: "reader".into(),
        actor: alice.into(),
    }
    .abi_encode();
    let grant_receipt = broadcast::native(&cluster, &client, &signer, ACP_ADDRESS, grant).await;
    assert!(grant_receipt.success, "child grant should succeed");

    // ── 4. Converge, then verify replication on BOTH nodes ───────────────
    let max_block = create_receipt
        .block_number
        .max(parent_receipt.block_number)
        .max(grant_receipt.block_number);
    state
        .wait_for_height(max_block + 1, Duration::from_secs(20))
        .await
        .expect("nodes should advance past the seed blocks");

    for node_idx in 0..cluster.node_count() {
        let node = VeraClient::new(cluster.node(node_idx).rpc_url());

        // The parent edge (object subject) is stored and queryable. Empty
        // actor → no subject filter → all subjects on document:doc1#parent.
        let parent_rels = node
            .filter_relationships(policy_id, "document", "doc1", "parent", "")
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} filter_relationships(parent): {e}"));
        let parent_json = String::from_utf8_lossy(&parent_rels);
        assert!(
            parent_json.contains(r#""subject":{"object":{"resource":"collection","id":"col1"}}"#),
            "node{node_idx} should have the parent edge to col1, got: {parent_json}"
        );

        // The child grant (entity subject) replicated too.
        let has_grant = node
            .has_relationship(policy_id, "collection", "col1", "reader", alice)
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} has_relationship(grant): {e}"));
        assert!(
            has_grant,
            "node{node_idx} should have the col1#reader grant for alice"
        );

        // Cross-object RESOLUTION: alice has no direct grant on doc1, but
        // document#read = reader + parent->reader (and the owner), so she
        // inherits read of doc1 from her reader grant on doc1's parent
        // collection col1, resolved on-chain by acp via a module query.
        let can_read = node
            .verify_access_request(
                policy_id,
                vec!["document".into()],
                vec!["doc1".into()],
                vec!["read".into()],
                alice,
            )
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} verify_access_request(doc1 read): {e}"));
        assert!(
            can_read,
            "node{node_idx}: alice should inherit read on doc1 via reader on parent col1"
        );

        // Fail closed: doc2 has no parent edge, so nothing is inherited.
        let no_inherit = node
            .verify_access_request(
                policy_id,
                vec!["document".into()],
                vec!["doc2".into()],
                vec!["read".into()],
                alice,
            )
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} verify_access_request(doc2 read): {e}"));
        assert!(
            !no_inherit,
            "node{node_idx}: doc2 has no parent edge, so read must be denied"
        );
    }

    // ── 5. Revoke the cross-object edge via deleteRelationshipSubject ─────
    // Removing the parent edge (the same object subject) must revoke the
    // inherited access everywhere.
    let revoke_calldata = IAcp::deleteRelationshipSubjectCall {
        policyId: policy_id,
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "parent".into(),
        subjectKind: 2,
        subjectResource: "collection".into(),
        subjectObjectId: "col1".into(),
        subjectRelation: String::new(),
    }
    .abi_encode();
    let revoke_receipt =
        broadcast::native(&cluster, &client, &signer, ACP_ADDRESS, revoke_calldata).await;
    assert!(
        revoke_receipt.success,
        "revoking the parent edge should succeed"
    );

    state
        .wait_for_height(revoke_receipt.block_number + 1, Duration::from_secs(20))
        .await
        .expect("nodes should advance past the revoke block");

    for node_idx in 0..cluster.node_count() {
        let node = VeraClient::new(cluster.node(node_idx).rpc_url());

        // The parent edge is gone.
        let parent_rels = node
            .filter_relationships(policy_id, "document", "doc1", "parent", "")
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} filter_relationships(parent): {e}"));
        let parent_json = String::from_utf8_lossy(&parent_rels);
        assert!(
            !parent_json.contains("col1"),
            "node{node_idx}: parent edge to col1 should be removed, got: {parent_json}"
        );

        // Resolution now denies: with no parent edge, nothing is inherited.
        let still_reads = node
            .verify_access_request(
                policy_id,
                vec!["document".into()],
                vec!["doc1".into()],
                vec!["read".into()],
                alice,
            )
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} verify_access_request(revoked): {e}"));
        assert!(
            !still_reads,
            "node{node_idx}: read on doc1 must be revoked after the parent edge is deleted"
        );
    }

    // Each node is polled independently, so one cached sample can straddle
    // several finalized blocks. Require convergence within a bounded wait.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let nodes = state.all_nodes();
        let min = nodes.iter().map(|node| node.effective_height()).min();
        let max = nodes.iter().map(|node| node.effective_height()).max();
        if nodes.len() == cluster.node_count()
            && nodes.iter().all(|node| node.is_healthy)
            && matches!((min, max), (Some(min), Some(max))
                if min > revoke_receipt.block_number && max - min <= 2)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "all nodes should converge within two blocks past revocation: {nodes:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    state
        .assert_no_errors()
        .expect("no unexpected errors in cluster logs");
}
