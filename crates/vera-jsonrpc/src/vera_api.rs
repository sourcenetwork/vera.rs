//! Vera-specific JSON-RPC API implementation.

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use vera_domain::{LightBlock, ModuleId, NativeCallRequest, NativeCallSimulation, ViewCallResult};

#[cfg(test)]
mod admission_tests;
mod capture;
mod light;
mod page;
mod permission;
mod policy;
mod prefix;
mod receipt;
#[cfg(test)]
mod receipt_tests;
mod record;
mod snapshot;
use vera_executor::SharedModuleState;
use vera_indexer::{BlockIndex, LightBlockIndex};
use vera_permission::{
    AccessRequest, PermissionProof, PermissionResponse, PolicyPrefixPageResponse,
    PolicyPrefixResponse, PolicySnapshotResponse, PrefixPageRequest, PrefixPageResponse,
    PrefixResponse, RecordResponse,
};

use crate::{
    error::RpcError,
    state::{NodeState, NodeStatus},
    state_provider::StateProvider,
    tx_submit::TxSubmitCallback,
    types::{RpcLog, RpcTransactionReceipt},
};

/// Durable light-block lookup, executed outside the asynchronous RPC worker.
/// `Ok(None)` means the revision has no finalization certificate yet.
pub type LightBlockLookup = Arc<dyn Fn(u64) -> Result<Option<LightBlock>, RpcError> + Send + Sync>;

/// Durable receipt evidence lookup, executed on a bounded blocking worker.
pub type ReceiptProofLookup =
    Arc<dyn Fn(B256) -> Result<Option<vera_domain::ReceiptResponse>, RpcError> + Send + Sync>;

/// Vera-specific JSON-RPC API trait.
///
/// Provides methods specific to vera node operations.
#[rpc(server, namespace = "vera")]
pub trait VeraApi {
    /// Returns the current node status including consensus information.
    #[method(name = "nodeStatus")]
    async fn node_status(&self) -> RpcResult<NodeStatus>;

    /// Returns the certificate of the newest term this node holds, or null
    /// when the deployment's active device never changed.
    ///
    /// The node verified it against its own state. A caller verifies it
    /// against the operator policy in state it has authenticated itself.
    #[method(name = "getTermCertificate")]
    async fn term_certificate(&self) -> RpcResult<Option<vera_domain::TermCertificate>>;

    /// Submits a BLS-signed native transaction.
    ///
    /// Accepts wire-format bytes (`0x45 || RLP(NativeTx)`), validates the
    /// format prefix, decodes the transaction, and returns the tx_id.
    /// Rejects bytes that do not start with the native tx type byte.
    #[method(name = "sendNativeTx")]
    async fn send_native_tx(&self, data: Bytes) -> RpcResult<B256>;

    /// Returns the execution result of a native request: its place in a
    /// revision, target module, signer, sequence, gas, logs and refusal.
    ///
    /// Execution data only; `vera_getReceiptProof` returns finality evidence.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(&self, hash: B256)
    -> RpcResult<Option<RpcTransactionReceipt>>;

    /// Return the complete receipt commitment and finality evidence for a submission.
    /// A missing response does not prove that the submission was never accepted.
    #[method(name = "getReceiptProof")]
    async fn get_receipt_proof(
        &self,
        hash: B256,
    ) -> RpcResult<Option<vera_domain::ReceiptResponse>>;

    /// Returns the on-chain native nonce for a BLS identity.
    #[method(name = "getNativeNonce")]
    async fn get_native_nonce(&self, did: String) -> RpcResult<U64>;

    /// Dry-runs a native module call as the DID the request names, at the
    /// head revision, without a signature or a sequence.
    ///
    /// The DID is not authenticated: the answer says what that DID could do
    /// and authorizes nothing. No state is written and no revision records
    /// the outcome.
    #[method(name = "simulateNativeCall")]
    async fn simulate_native_call(
        &self,
        request: NativeCallRequest,
    ) -> RpcResult<NativeCallSimulation>;

    /// Evaluates a read-only module call that carries no signer, against the
    /// committed module state at the head revision.
    ///
    /// Unauthenticated: the answer is this node's word. It carries no
    /// finality certificate and no state proof, and must not decide access
    /// or be recorded as a decision. The `vera_getCurrent*Proof` methods are
    /// the authenticated path.
    ///
    /// `target` is a module address and `calldata` is bounded like a native
    /// submission; anything else fails with -32602. A method that needs a
    /// signer answers with an `unauthenticated` refusal. Nothing is written
    /// and no gas is charged. The call runs on the simulation slots: when
    /// they stay occupied it fails with the retryable -32002.
    #[method(name = "call")]
    async fn call(&self, target: Address, calldata: Bytes) -> RpcResult<ViewCallResult>;

    /// Return bounded evidence for evaluating this request at a finalized revision.
    #[method(name = "getPermissionProof")]
    async fn get_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        height: U64,
    ) -> RpcResult<PermissionProof>;

    /// Capture current native evidence and return its matching finalized revision.
    #[method(name = "getCurrentPermissionProof")]
    async fn get_current_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        minimum_height: U64,
    ) -> RpcResult<PermissionResponse>;

    /// Capture a native record and its finalized revision, including proven absence.
    #[method(name = "getCurrentRecordProof")]
    async fn get_current_record_proof(
        &self,
        module: ModuleId,
        key: Bytes,
        minimum_height: U64,
    ) -> RpcResult<RecordResponse>;

    /// Capture every native record under a prefix with its finalized revision.
    #[method(name = "getCurrentPrefixProof")]
    async fn get_current_prefix_proof(
        &self,
        module: ModuleId,
        prefix: Bytes,
        minimum_height: U64,
    ) -> RpcResult<PrefixResponse>;

    /// Capture a bounded native page with its finalized revision.
    #[method(name = "getCurrentPrefixPageProof")]
    async fn get_current_prefix_page_proof(
        &self,
        request: PrefixPageRequest,
        minimum_height: U64,
    ) -> RpcResult<PrefixPageResponse>;

    /// Capture policy liveness and a complete relationship prefix at one finalized revision.
    #[method(name = "getCurrentPolicyPrefixProof")]
    async fn get_current_policy_prefix_proof(
        &self,
        policy: String,
        prefix: Bytes,
        minimum_height: U64,
    ) -> RpcResult<PolicyPrefixResponse>;

    /// Capture policy liveness and a bounded relationship page at one finalized revision.
    #[method(name = "getCurrentPolicyPrefixPageProof")]
    async fn get_current_policy_prefix_page_proof(
        &self,
        policy: String,
        request: PrefixPageRequest,
        minimum_height: U64,
    ) -> RpcResult<PolicyPrefixPageResponse>;

    /// Capture a policy record and every relationship, index and object record
    /// of the policy at one finalized revision: the state a snapshot anchors.
    #[method(name = "getCurrentPolicySnapshot")]
    async fn get_current_policy_snapshot(
        &self,
        policy: String,
        minimum_height: U64,
    ) -> RpcResult<PolicySnapshotResponse>;

    /// Returns a light block at the given height.
    ///
    /// Verify it with `vera_domain::verify_light_block` and a consensus key from
    /// the deployment's authenticated bootstrap configuration.
    #[method(name = "getLightBlock")]
    async fn get_light_block(&self, height: U64) -> RpcResult<LightBlock>;
}

/// Implementation of the vera RPC API.
pub struct VeraApiImpl {
    state: Arc<NodeState>,
    tx_submit: Option<TxSubmitCallback>,
    index: Option<Arc<BlockIndex>>,
    modules: Option<SharedModuleState>,
    native_modules: Option<vera_backend::native::NativeStateSet>,
    light_block_index: Option<Arc<LightBlockIndex>>,
    light_block_lookup: Option<LightBlockLookup>,
    receipt_proof_lookup: Option<ReceiptProofLookup>,
    archive: Option<crate::ArchiveReader>,
    simulator: Option<Arc<dyn StateProvider>>,
}

impl std::fmt::Debug for VeraApiImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VeraApiImpl")
            .field("state", &self.state)
            .field("tx_submit", &self.tx_submit.is_some())
            .field("index", &self.index.is_some())
            .field("modules", &self.modules.is_some())
            .field("native_modules", &self.native_modules.is_some())
            .field("light_block_index", &self.light_block_index.is_some())
            .field("light_block_lookup", &self.light_block_lookup.is_some())
            .finish()
    }
}

impl VeraApiImpl {
    /// Create a new vera API implementation.
    #[must_use]
    pub fn new(state: Arc<NodeState>, tx_submit: Option<TxSubmitCallback>) -> Self {
        Self {
            state,
            tx_submit,
            index: None,
            modules: None,
            native_modules: None,
            light_block_index: None,
            light_block_lookup: None,
            receipt_proof_lookup: None,
            archive: None,
            simulator: None,
        }
    }

    /// Run dry runs and view calls through this provider, so both share its
    /// simulation slots.
    #[must_use]
    pub fn with_simulator(mut self, provider: Arc<dyn StateProvider>) -> Self {
        self.simulator = Some(provider);
        self
    }

    /// Set the block index and shared module state for receipt/nonce queries.
    #[must_use]
    pub fn with_index_and_modules(
        mut self,
        index: Arc<BlockIndex>,
        modules: SharedModuleState,
    ) -> Self {
        self.index = Some(index);
        self.modules = Some(modules);
        self
    }

    /// Serve permission evidence from the selected ordered module databases.
    #[must_use]
    pub fn with_native_modules(
        mut self,
        databases: vera_backend::native::NativeStateSet,
        modules: SharedModuleState,
    ) -> Self {
        self.native_modules = Some(databases);
        self.modules = Some(modules);
        self
    }

    /// Set the light block index for `getLightBlock` queries.
    #[must_use]
    pub fn with_light_block_index(mut self, index: Arc<LightBlockIndex>) -> Self {
        self.light_block_index = Some(index);
        self
    }

    /// Serve direct and indirect finality proofs from durable history.
    #[must_use]
    pub fn with_light_block_lookup(mut self, lookup: LightBlockLookup) -> Self {
        self.light_block_lookup = Some(lookup);
        self
    }

    /// Configure durable receipt evidence for submissions absent from the memory index.
    pub fn with_receipt_proof_lookup(mut self, lookup: ReceiptProofLookup) -> Self {
        self.receipt_proof_lookup = Some(lookup);
        self
    }

    /// Enable durable point reads for receipts absent from memory.
    pub fn with_archive(mut self, archive: crate::ArchiveReader) -> Self {
        self.archive = Some(archive);
        self
    }
}

#[jsonrpsee::core::async_trait]
impl VeraApiServer for VeraApiImpl {
    async fn node_status(&self) -> RpcResult<NodeStatus> {
        let mut status = self.state.status();
        status.head_height = self.index.as_ref().map(|index| index.head_block_number());
        Ok(status)
    }

    async fn term_certificate(&self) -> RpcResult<Option<vera_domain::TermCertificate>> {
        Ok(self.state.term_certificate())
    }

    async fn send_native_tx(&self, data: Bytes) -> RpcResult<B256> {
        let first = data
            .first()
            .ok_or_else(|| RpcError::InvalidTransaction("empty transaction".into()))?;

        if !vera_domain::NativeTx::is_native_tx(*first) {
            return Err(RpcError::InvalidTransaction(
                "not a native transaction (expected 0x45 prefix)".into(),
            )
            .into());
        }

        let ntx = vera_domain::NativeTx::decode_wire(&data)
            .map_err(|e| RpcError::InvalidTransaction(format!("native tx decode: {e}")))?;
        let tx_hash = ntx.tx_id().0;

        if let Some(ref submit) = self.tx_submit {
            match submit(data).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(RpcError::InvalidTransaction("duplicate transaction".into()).into());
                }
                Err(error) => return Err(error.into()),
            }
        }

        Ok(tx_hash)
    }

    async fn get_transaction_receipt(
        &self,
        hash: B256,
    ) -> RpcResult<Option<RpcTransactionReceipt>> {
        let Some(ref index) = self.index else {
            return Err(RpcError::Internal("block index not available".into()).into());
        };

        let mut receipt = index.get_receipt(&hash);
        if receipt.is_none()
            && let Some(archive) = &self.archive
            && let Some(index) = archive
                .read(vera_indexer::IndexQuery::Submission(hash))
                .await?
        {
            receipt = index.get_receipt(&hash);
        }
        let Some(receipt) = receipt else {
            return Ok(None);
        };

        let logs = receipt
            .logs
            .into_iter()
            .map(|log| RpcLog {
                address: log.address,
                topics: log.topics,
                data: log.data,
                block_number: U64::from(receipt.block_number),
                transaction_hash: receipt.transaction_hash,
                transaction_index: U64::from(receipt.transaction_index),
                block_hash: receipt.block_hash,
                log_index: U64::from(log.log_index),
            })
            .collect();

        Ok(Some(RpcTransactionReceipt {
            transaction_hash: receipt.transaction_hash,
            transaction_index: U64::from(receipt.transaction_index),
            block_hash: receipt.block_hash,
            block_number: U64::from(receipt.block_number),
            target: receipt.target,
            signer_did: receipt.signer_did,
            nonce: U64::from(receipt.nonce),
            gas_used: U64::from(receipt.gas_used),
            cumulative_gas_used: U64::from(receipt.cumulative_gas_used),
            success: receipt.status,
            logs,
            refusal: receipt.refusal,
        }))
    }

    async fn get_receipt_proof(
        &self,
        hash: B256,
    ) -> RpcResult<Option<vera_domain::ReceiptResponse>> {
        self.receipt_proof(hash).await
    }

    async fn get_native_nonce(&self, did: String) -> RpcResult<U64> {
        let Some(ref modules) = self.modules else {
            return Err(RpcError::Internal("module state not available".into()).into());
        };

        let guard = modules
            .read()
            .map_err(|_| RpcError::Internal("lock poisoned".into()))?;
        let nonce = guard
            .nonces
            .get_nonce(&did)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(U64::from(nonce))
    }

    async fn simulate_native_call(
        &self,
        request: NativeCallRequest,
    ) -> RpcResult<NativeCallSimulation> {
        let Some(simulator) = &self.simulator else {
            return Err(RpcError::NotImplemented.into());
        };
        Ok(simulator.simulate_native_call(request).await?)
    }

    async fn call(&self, target: Address, calldata: Bytes) -> RpcResult<ViewCallResult> {
        let Some(simulator) = &self.simulator else {
            return Err(RpcError::NotImplemented.into());
        };
        Ok(simulator.view_call(target, calldata).await?)
    }

    async fn get_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        height: U64,
    ) -> RpcResult<PermissionProof> {
        let _permit = self.state.proof_permit()?;
        self.permission_proof(&policy, &request, height.to()).await
    }

    async fn get_current_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        minimum_height: U64,
    ) -> RpcResult<PermissionResponse> {
        let _request = self.state.permission_read_permit()?;
        self.current_permission_proof(&policy, &request, minimum_height.to())
            .await
    }

    async fn get_current_record_proof(
        &self,
        module: ModuleId,
        key: Bytes,
        minimum_height: U64,
    ) -> RpcResult<RecordResponse> {
        let _request = self.state.permission_read_permit()?;
        self.current_record_proof(module, &key, minimum_height.to())
            .await
    }

    async fn get_current_prefix_proof(
        &self,
        module: ModuleId,
        prefix: Bytes,
        minimum_height: U64,
    ) -> RpcResult<PrefixResponse> {
        let _request = self.state.permission_read_permit()?;
        self.current_prefix_proof(module, &prefix, minimum_height.to())
            .await
    }

    async fn get_current_prefix_page_proof(
        &self,
        request: PrefixPageRequest,
        minimum_height: U64,
    ) -> RpcResult<PrefixPageResponse> {
        let _request = self.state.permission_read_permit()?;
        self.current_prefix_page_proof(&request, minimum_height.to())
            .await
    }

    async fn get_current_policy_prefix_proof(
        &self,
        policy: String,
        prefix: Bytes,
        minimum_height: U64,
    ) -> RpcResult<PolicyPrefixResponse> {
        let _request = self.state.permission_read_permit()?;
        self.current_policy_prefix_proof(&policy, &prefix, minimum_height.to())
            .await
    }

    async fn get_current_policy_prefix_page_proof(
        &self,
        policy: String,
        request: PrefixPageRequest,
        minimum_height: U64,
    ) -> RpcResult<PolicyPrefixPageResponse> {
        let _request = self.state.permission_read_permit()?;
        self.current_policy_prefix_page_proof(&policy, &request, minimum_height.to())
            .await
    }

    async fn get_current_policy_snapshot(
        &self,
        policy: String,
        minimum_height: U64,
    ) -> RpcResult<PolicySnapshotResponse> {
        let _request = self.state.permission_read_permit()?;
        self.current_policy_snapshot(&policy, minimum_height.to())
            .await
    }

    async fn get_light_block(&self, height: U64) -> RpcResult<LightBlock> {
        let height: u64 = height.to();
        let cached = {
            let _permit = self.state.proof_permit()?;
            self.cached_light_block(height)?
        };
        match cached {
            Some(light) => Ok(light),
            None => self
                .archived_light_block(height)
                .await?
                .ok_or_else(|| light::certificate_not_found(height)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use vera_domain::NativeTx;

    fn sample_native_tx() -> NativeTx {
        NativeTx {
            chain_id: 1,
            nonce: 42,
            bls_pubkey: FixedBytes::from([0xAA; 48]),
            target: Address::from([
                0x08, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            calldata: Bytes::from(vec![0xDE, 0xAD]),
            signature: FixedBytes::from([0xBB; 96]),
        }
    }

    #[tokio::test]
    async fn send_native_tx_returns_correct_tx_id() {
        let ntx = sample_native_tx();
        let wire = Bytes::from(ntx.encode_wire());
        let expected = ntx.tx_id().0;

        let submitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let submitted_clone = submitted.clone();
        let callback: TxSubmitCallback = Arc::new(move |_| {
            submitted_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { Ok(true) })
        });

        let state = Arc::new(NodeState::new(1, 0, 1));
        let api = VeraApiImpl::new(state, Some(callback));
        let result = VeraApiServer::send_native_tx(&api, wire).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
        assert!(submitted.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn send_native_tx_preserves_retryable_admission_failures() {
        use crate::{TxSubmitError, error_codes};

        for error in [
            TxSubmitError::AtCapacity,
            TxSubmitError::NotReady,
            TxSubmitError::Rejected("invalid signature".into()),
        ] {
            let retryable = !matches!(error, TxSubmitError::Rejected(_));
            let callback: TxSubmitCallback = Arc::new(move |_| {
                let error = error.clone();
                Box::pin(async move { Err(error) })
            });
            let api = VeraApiImpl::new(Arc::new(NodeState::new(1, 0, 1)), Some(callback));
            let wire = Bytes::from(sample_native_tx().encode_wire());
            let response = VeraApiServer::send_native_tx(&api, wire).await.unwrap_err();
            if retryable {
                assert_eq!(response.code(), error_codes::RESOURCE_UNAVAILABLE);
                let data: serde_json::Value =
                    serde_json::from_str(response.data().unwrap().get()).unwrap();
                assert_eq!(data, serde_json::json!({"retryable": true}));
            } else {
                assert_eq!(response.code(), error_codes::INVALID_PARAMS);
                assert!(response.data().is_none());
            }
        }
    }

    #[tokio::test]
    async fn send_native_tx_rejects_bytes_that_are_not_a_native_request() {
        let state = Arc::new(NodeState::new(1, 0, 1));
        let api = VeraApiImpl::new(state, None);
        let other = Bytes::from(vec![0x02, 0xAA, 0xBB]);
        let result = VeraApiServer::send_native_tx(&api, other).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message().contains("not a native transaction"));
    }

    #[tokio::test]
    async fn send_native_tx_rejects_empty() {
        let state = Arc::new(NodeState::new(1, 0, 1));
        let api = VeraApiImpl::new(state, None);
        let result = VeraApiServer::send_native_tx(&api, Bytes::new()).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message().contains("empty transaction"));
    }
}
