//! Helpers for the embedded thread tests, which run without an async runtime
//! so that every thread they observe belongs to the node.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::ReceiptResponse;
use vera_modules::{acp::abi::IAcp, vera::administration::OperatorPolicy};
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloGenesis};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const POLICY: &str = "\
name: threads
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
    permissions:
      - name: read
        expr: reader
";

/// Drives a future on the calling thread without any async runtime.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::sync::Arc::new(Unpark(std::thread::current())).into();
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}

/// A deployment in `directory` with explicit thread counts.
pub(crate) fn config(directory: &Path, chain_id: u64) -> EmbeddedConfig {
    let genesis = SoloGenesis {
        chain_id,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let listen = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut config = EmbeddedConfig::new(directory, genesis, listen);
    config.worker_threads = Some(1);
    config.max_blocking_threads = Some(16);
    config.verification_threads = 2;
    config
}

/// Creates a policy through the in-process method table and waits for its certified receipt.
pub(crate) fn finalize_a_write(node: &EmbeddedNode, signer: &BlsSigner) {
    let call = IAcp::createPolicyCall {
        policy: POLICY.as_bytes().to_vec().into(),
        marshalType: 1,
    };
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let submission: B256 = block_on(node.rpc().request(
        "vera_sendNativeTx",
        vec![json!(format!("0x{}", hex::encode(wire)))],
    ))
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let proof: Option<ReceiptResponse> = block_on(
            node.rpc()
                .request("vera_getReceiptProof", vec![json!(submission)]),
        )
        .unwrap();
        if let Some(proof) = proof {
            let receipt = proof.verify(submission, node.consensus_key()).unwrap();
            assert!(receipt.success(), "policy creation must succeed");
            return;
        }
        assert!(Instant::now() < deadline, "certified receipt deadline");
        std::thread::sleep(Duration::from_millis(50));
    }
}
