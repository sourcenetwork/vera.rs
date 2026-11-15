//! Unsigned dry runs of native module calls.

use alloy_primitives::Address;
use vera_domain::{NativeCallRequest, NativeCallSimulation};

use super::VeraClient;
use crate::error::ClientError;

impl VeraClient {
    /// Dry-run a native module call as `signer` against the node's head
    /// revision (`vera_simulateNativeCall`).
    ///
    /// The node authenticates neither the signer nor its answer: the result
    /// says what that DID could do when the node evaluated it, authorizes
    /// nothing and is not evidence of any revision. A submitted request may
    /// still be refused once state has moved on.
    pub async fn simulate_native_call(
        &self,
        signer: &str,
        target: Address,
        calldata: &[u8],
    ) -> Result<NativeCallSimulation, ClientError> {
        let request = NativeCallRequest {
            signer: signer.to_owned(),
            target,
            calldata: calldata.to_vec().into(),
        };
        self.rpc_call_typed("vera_simulateNativeCall", serde_json::json!([request]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::stub::{Reply, Stub};
    use super::*;
    use crate::ACP_ADDRESS;

    #[tokio::test]
    async fn a_dry_run_names_its_signer_and_decodes_a_refusal() {
        let stub = Stub::serve(vec![Reply::Result(json!({
            "success": false,
            "reason": "only the policy creator can delete it",
            "gasUsed": "0xf4240",
            "output": "0x",
            "logs": [],
            "blockNumber": "0x7",
            "timestamp": "0x6b49d27b",
        }))]);
        let client = VeraClient::new(stub.url.clone());
        let simulation = client
            .simulate_native_call("did:key:other", ACP_ADDRESS, &[0xde, 0xad])
            .await
            .unwrap();
        assert!(!simulation.success);
        assert_eq!(
            simulation.reason.as_deref(),
            Some("only the policy creator can delete it")
        );
        assert_eq!(simulation.gas_used.to::<u64>(), 1_000_000);
        assert_eq!(simulation.block_number.to::<u64>(), 7);

        let requests = stub.requests();
        assert_eq!(requests[0]["method"], "vera_simulateNativeCall");
        assert_eq!(
            requests[0]["params"],
            json!([{
                "signer": "did:key:other",
                "target": "0x0000000000000000000000000000000000000810",
                "calldata": "0xdead",
            }])
        );
    }
}
