//! Light client verification end-to-end test.
//!
//! Exercises the full light client pipeline: gossip headers, light block
//! verification, module state proofs, and state change detection across
//! block boundaries.
//!
//! Requires `cargo build -p verad` before running.

use std::time::Duration;

use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_sol_types::SolCall;

use jsonrpsee::core::client::SubscriptionClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use vera_client::{
    ACP_ADDRESS, EvmSigner, ModuleId, PERMISSION_LIMITS, RECORD_PROOF_BYTES, TransactionReceipt,
    VeraClient,
};
use vera_domain::{LightBlock, verify_light_block};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};
use vera_modules::acp::abi::IAcp;

#[path = "light_client/decision.rs"]
mod decision;
#[path = "light_client/permission.rs"]
mod permission;

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const TEST_POLICY_YAML: &str = "\
name: test-policy
resources:
  - name: document
    relations:
      - name: reader
      - name: blocked
    permissions:
      - name: read
        expr: reader - blocked->blocked
";

fn parse_policy_id(hex_str: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode_to_slice(hex, &mut bytes).expect("policy ID should be valid hex");
    FixedBytes::from(bytes)
}

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
            tokio::spawn(async move {
                let result = VeraClient::new(url).send_raw_transaction(&r).await;
                (i, result)
            })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok((_node_idx, Ok(hash))) = fut.await {
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
async fn light_client_proof_verification() {
    let chain_id = 9003;
    let trusted_key = *KeySet::builder()
        .seed(chain_id)
        .build()
        .expect("bootstrap keys")
        .epoch_info()
        .output
        .public()
        .public();
    let genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .seed(chain_id)
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
    let latest: serde_json::Value = client
        .rpc_call_typed("eth_getBlockByNumber", serde_json::json!(["latest", false]))
        .await
        .expect("latest block should be readable");
    let mix_hash = latest["mixHash"]
        .as_str()
        .expect("latest block should expose prevrandao");
    assert_ne!(
        mix_hash,
        format!("0x{}", "00".repeat(32)),
        "post-genesis prevrandao must come from the threshold VRF seed"
    );
    let evm_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");

    let create_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let create_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, create_calldata).await;
    assert_eq!(create_receipt.status, 1, "create_policy should succeed");

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert!(!policy_ids.is_empty(), "should have at least one policy");
    let policy_id = parse_policy_id(&policy_ids[0]);

    let register_calldata = IAcp::registerObjectCall {
        policyId: policy_id,
        objectId: "doc1".into(),
        resource: "document".into(),
    }
    .abi_encode();
    let register_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        register_calldata,
    )
    .await;
    assert_eq!(register_receipt.status, 1, "register_object should succeed");
    let h_register = register_receipt.block_number;

    let ws_client = WsClientBuilder::default()
        .build(&cluster.node(0).ws_url())
        .await
        .expect("WebSocket connection should succeed");

    let mut headers_sub = ws_client
        .subscribe::<serde_json::Value, _>(
            "eth_subscribe",
            rpc_params!["headers"],
            "eth_unsubscribe",
        )
        .await
        .expect("headers subscription should succeed");

    // Consume headers until we reach one at or past h_register.
    let header_1 = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let h = headers_sub
                .next()
                .await
                .expect("subscription should not close")
                .expect("header should deserialize");
            let height = h["height"].as_u64().expect("height should be u64");
            if height >= h_register {
                return h;
            }
        }
    })
    .await
    .expect("should receive header at or past h_register within timeout");

    let h1 = header_1["height"].as_u64().expect("height should be u64");
    assert!(
        !header_1["module_state_root"].is_null(),
        "module_state_root should be present"
    );
    let header_1_msr = header_1["module_state_root"]
        .as_str()
        .expect("module_state_root should be a string");

    let light_block: LightBlock = client
        .rpc_call_typed("vera_getLightBlock", serde_json::json!([h1]))
        .await
        .expect("vera_getLightBlock should succeed");

    let (_state_root, module_state_root) =
        verify_light_block(&light_block, &trusted_key).expect("light block should verify");

    let lb_msr_hex = format!("0x{}", hex::encode(module_state_root.as_slice()));
    assert_eq!(
        lb_msr_hex, header_1_msr,
        "light block module_state_root should match gossip header"
    );

    let policy_id_str = &policy_ids[0];
    let acp_key = format!("policy/objs/{policy_id_str}");
    let response = client
        .read_current_record(
            ModuleId::Acp,
            acp_key.as_bytes(),
            h1,
            &trusted_key,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    let proof_1 = response.record;
    assert!(proof_1.value.is_some());
    let request = permission::request();
    let empty_readers = permission::evidence(&client, policy_id_str, &request, h1).await;
    assert!(
        !empty_readers
            .verify(policy_id_str, &request, h1, &trusted_key, PERMISSION_LIMITS)
            .unwrap()
    );
    permission::assert_absent_relation_directory(&empty_readers.proof, policy_id_str, "reader");

    let set_rel_calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "reader".into(),
        actor: permission::READER_DID.into(),
    }
    .abi_encode();
    let mutate_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        set_rel_calldata,
    )
    .await;
    assert_eq!(mutate_receipt.status, 1, "set_relationship should succeed");
    let h_mutate = mutate_receipt.block_number;

    // Native proof roots may advance on empty revisions; require the confirmed mutation.
    let invalidation_height = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let h = headers_sub
                .next()
                .await
                .expect("subscription should not close")
                .expect("header should deserialize");
            let height = h["height"].as_u64().expect("height should be u64");
            if height < h_mutate {
                continue;
            }

            let lb: LightBlock = client
                .rpc_call_typed("vera_getLightBlock", serde_json::json!([height]))
                .await
                .expect("vera_getLightBlock should succeed");
            let (_, msr) =
                verify_light_block(&lb, &trusted_key).expect("light block should verify");

            if proof_1
                .verify(msr, ModuleId::Acp, acp_key.as_bytes(), RECORD_PROOF_BYTES)
                .is_err()
            {
                return (height, msr);
            }
        }
    })
    .await
    .expect("old proof should eventually fail against a new block");

    let (h_invalidated, module_state_root_2) = invalidation_height;
    assert!(
        h_invalidated >= h_mutate,
        "proof should not invalidate before the mutation block \
         (invalidated at {h_invalidated}, mutation at {h_mutate})"
    );

    let response = client
        .read_current_record(
            ModuleId::Acp,
            acp_key.as_bytes(),
            h_invalidated,
            &trusted_key,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    let proof_2 = response.record;
    assert_ne!(proof_2.roots[0], proof_1.roots[0]);
    assert!(
        proof_1
            .verify(
                module_state_root_2,
                ModuleId::Acp,
                acp_key.as_bytes(),
                RECORD_PROOF_BYTES
            )
            .is_err()
    );
    // A direct grant needs only a point; an unrelated actor requires complete enumeration.
    let mut outsider = request.clone();
    outsider.actor = vera_client::Actor(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap(),
    );
    let readers = permission::evidence(&client, policy_id_str, &outsider, h_invalidated).await;
    assert!(
        !readers
            .verify(
                policy_id_str,
                &outsider,
                h_invalidated,
                &trusted_key,
                PERMISSION_LIMITS
            )
            .unwrap()
    );
    let reader_prefix = permission::relation_prefix(&readers.proof, policy_id_str, "reader", None);
    assert_eq!(
        permission::prefix(&readers.proof, &reader_prefix)
            .entries
            .len(),
        1
    );
    let mut omitted = readers.clone();
    permission::remove_prefix_records(&mut omitted.proof, &reader_prefix);
    assert!(
        omitted
            .verify(
                policy_id_str,
                &outsider,
                h_invalidated,
                &trusted_key,
                PERMISSION_LIMITS
            )
            .is_err()
    );
    let historical = client
        .verify_access_at(
            policy_id_str,
            &request,
            &empty_readers.revision,
            &trusted_key,
            PERMISSION_LIMITS,
        )
        .await;
    assert!(
        historical.is_err(),
        "changed native state cannot provide historical activity evidence"
    );
    let mut mixed = empty_readers;
    mixed.revision = readers.revision;
    assert!(
        mixed
            .verify(
                policy_id_str,
                &request,
                h_invalidated,
                &trusted_key,
                PERMISSION_LIMITS
            )
            .is_err()
    );
    permission::check_permissions(
        &cluster,
        &client,
        &evm_signer,
        policy_id_str,
        h_invalidated,
        &trusted_key,
    )
    .await;
    decision::check_decisions(&cluster, &client, &evm_signer, policy_id_str, &trusted_key).await;
}
