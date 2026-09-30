//! Cross-object ACP: storage, replication, and resolution across a cluster.
//!
//! Seeds a cross-object "parent edge" (a relationship whose subject is an
//! `EntitySet`, i.e. another object's userset) plus a child grant on node 0,
//! then on every other node asserts both that they replicate and that an access
//! check *resolves* across the edge: a subject granted on the parent inherits
//! access to the child through `TupleToUserset`, evaluated on-chain by the
//! zanzibar `PermissionEngine`. (Simplex BFT requires ≥4 nodes for quorum, so
//! the "seed on one, resolve on another" check uses the 4-node minimum.)
//!
//! Requires `cargo build -p verad` (and `VERAD_BINARY`) before running.

use std::time::Duration;

use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_sol_types::SolCall;

use vera_client::{ACP_ADDRESS, EvmSigner, TransactionReceipt, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use vera_e2e::observe::ClusterAssertions;
use vera_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};
use vera_modules::acp::abi::IAcp;

/// Hardhat account 0 — funded; creates the policy and signs all txs.
const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Policy with a `document` whose `read` inherits from `reader` on its parent
/// `collection` (`parent->reader`), so a `document#parent` edge can point at a
/// collection userset.
const TEST_POLICY_YAML: &str = "\
name: cross-object-policy
resources:
  - name: collection
    relations:
      - name: owner
      - name: reader
    permissions:
      - name: read
        expr: owner + reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
  - name: document
    relations:
      - name: owner
      - name: parent
      - name: reader
    permissions:
      - name: read
        expr: owner + reader + parent->reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
";

fn parse_policy_id(hex_str: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode_to_slice(hex, &mut bytes).expect("policy ID should be valid hex");
    FixedBytes::from(bytes)
}

/// Sign an EVM tx and broadcast to every node so the current leader has it.
async fn broadcast_evm_tx(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &EvmSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let nonce = client
        .get_nonce(signer.address())
        .await
        .expect("get_nonce should work");
    let raw = signer
        .sign_tx(target, Bytes::from(calldata), nonce)
        .expect("EVM sign should succeed");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let r = raw.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move { VeraClient::new(url).send_raw_transaction(&r).await })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok(Ok(hash)) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the EVM tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
        .await
        .expect("EVM receipt should appear")
}

#[tokio::test]
async fn cross_object_grant_replicates_across_nodes() {
    let chain_id = 9001;
    let genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .chain_id(chain_id)
        .genesis(genesis)
        .preset(ConsensusPreset::Fast)
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
    let signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");

    let alice = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

    // ── 1. Create the policy on node 0 (account0 becomes its owner) ──────
    let create = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let create_receipt = broadcast_evm_tx(&cluster, &client, &signer, ACP_ADDRESS, create).await;
    assert_eq!(create_receipt.status, 1, "createPolicy should succeed");

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
        let receipt = broadcast_evm_tx(&cluster, &client, &signer, ACP_ADDRESS, register).await;
        assert_eq!(receipt.status, 1, "register {resource}/{object_id}");
    }

    // ── 2. Seed the parent edge via setRelationshipSubject ───────────────
    // document:doc1#parent @ collection:col1#reader — a userset subject
    // (subjectKind 3), the cross-object shape the entity-only setRelationship
    // cannot express. The signer registered both objects and owns them.
    let parent_calldata = IAcp::setRelationshipSubjectCall {
        policyId: policy_id,
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "parent".into(),
        subjectKind: 3,
        subjectResource: "collection".into(),
        subjectObjectId: "col1".into(),
        subjectRelation: "reader".into(),
    }
    .abi_encode();
    let parent_receipt =
        broadcast_evm_tx(&cluster, &client, &signer, ACP_ADDRESS, parent_calldata).await;
    assert_eq!(
        parent_receipt.status, 1,
        "setting the userset parent edge should succeed"
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
    let grant_receipt = broadcast_evm_tx(&cluster, &client, &signer, ACP_ADDRESS, grant).await;
    assert_eq!(grant_receipt.status, 1, "child grant should succeed");

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

        // The parent edge (EntitySet subject) is stored and queryable. Empty
        // actor → no subject filter → all subjects on document:doc1#parent.
        let parent_rels = node
            .filter_relationships(policy_id, "document", "doc1", "parent", "")
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} filter_relationships(parent): {e}"));
        let parent_json = String::from_utf8_lossy(&parent_rels);
        assert!(
            parent_json.contains("EntitySet") && parent_json.contains("col1"),
            "node{node_idx} should have the EntitySet parent edge to col1, got: {parent_json}"
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
        // document#read = owner + reader + parent->reader, so the chain inherits
        // her read of doc1 from her reader grant on doc1's parent collection
        // col1 — resolved on-chain through the zanzibar PermissionEngine
        // (TupleToUserset) via eth_call.
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
    // Removing the parent edge (the same userset subject) must revoke the
    // inherited access everywhere.
    let revoke_calldata = IAcp::deleteRelationshipSubjectCall {
        policyId: policy_id,
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "parent".into(),
        subjectKind: 3,
        subjectResource: "collection".into(),
        subjectObjectId: "col1".into(),
        subjectRelation: "reader".into(),
    }
    .abi_encode();
    let revoke_receipt =
        broadcast_evm_tx(&cluster, &client, &signer, ACP_ADDRESS, revoke_calldata).await;
    assert_eq!(
        revoke_receipt.status, 1,
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

    state
        .assert_heights_converged(2)
        .expect("heights should converge");
    state
        .assert_no_errors()
        .expect("no unexpected errors in cluster logs");
}
