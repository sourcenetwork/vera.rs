use crate::{
    bls_signer::BlsSigner,
    client::{ACP_ADDRESS, VeraClient},
    error::ClientError,
    types::TransactionReceipt,
};
use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use vera_modules::acp::{abi::IAcp, types::SuppliedMetadata};

impl VeraClient {
    /// Execute an object command with optional supplied record metadata.
    pub async fn native_policy_command(
        &self,
        signer: &BlsSigner,
        policy_id: FixedBytes<32>,
        request: &vera_modules::acp::types::PolicyCommandRequest,
    ) -> Result<TransactionReceipt, ClientError> {
        let call = IAcp::executePolicyCommandCall {
            policyId: policy_id,
            request: serde_json::to_vec(request)?.into(),
        };
        self.send_native_precompile_tx(signer, ACP_ADDRESS, call.abi_encode().into())
            .await
    }

    /// Create a policy with supplied metadata and an optional required specification.
    pub async fn native_create_policy_with_options(
        &self,
        signer: &BlsSigner,
        request: &vera_modules::acp::types::PolicyCreation,
    ) -> Result<TransactionReceipt, ClientError> {
        let call = IAcp::createPolicyWithOptionsCall {
            request: serde_json::to_vec(request)?.into(),
        };
        self.send_native_precompile_tx(signer, ACP_ADDRESS, call.abi_encode().into())
            .await
    }

    /// Transfer a registration to a new owner through authenticated native execution.
    pub async fn native_transfer_object(
        &self,
        signer: &BlsSigner,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        new_owner: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let call = IAcp::transferObjectCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            newOwner: new_owner.into(),
        };
        self.send_native_precompile_tx(signer, ACP_ADDRESS, call.abi_encode().into())
            .await
    }

    /// Remove a policy and its relationships; requires policy ownership.
    pub async fn native_delete_policy(
        &self,
        signer: &BlsSigner,
        policy_id: FixedBytes<32>,
    ) -> Result<TransactionReceipt, ClientError> {
        self.send_native_precompile_tx(
            signer,
            ACP_ADDRESS,
            IAcp::deletePolicyCall {
                policyId: policy_id,
            }
            .abi_encode()
            .into(),
        )
        .await
    }

    /// Replace policy metadata without editing its authorization rules.
    pub async fn native_edit_policy_metadata(
        &self,
        signer: &BlsSigner,
        policy_id: FixedBytes<32>,
        metadata: &SuppliedMetadata,
    ) -> Result<TransactionReceipt, ClientError> {
        let call = IAcp::editPolicyMetadataCall {
            policyId: policy_id,
            metadata: serde_json::to_vec(metadata)?.into(),
        };
        self.send_native_precompile_tx(signer, ACP_ADDRESS, call.abi_encode().into())
            .await
    }
}
