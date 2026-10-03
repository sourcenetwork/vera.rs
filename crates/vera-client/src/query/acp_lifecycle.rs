use crate::{
    client::{ACP_ADDRESS, VeraClient},
    error::ClientError,
};
use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use vera_modules::acp::{
    abi::IAcp,
    catalogue::PolicyCatalogue,
    types::{PolicyRecord, RelationshipRecord},
};

impl VeraClient {
    /// List policies in bounded pages. Successive endpoint reads may observe different revisions.
    pub async fn get_policies_page(
        &self,
        cursor: Option<&[u8]>,
    ) -> Result<vera_modules::acp::pages::RecordPage<PolicyRecord>, ClientError> {
        let call = IAcp::getPoliciesPageCall {
            cursor: cursor.unwrap_or_default().to_vec().into(),
        };
        let output = self.eth_call(ACP_ADDRESS, call.abi_encode().into()).await?;
        let bytes = IAcp::getPoliciesPageCall::abi_decode_returns(&output)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// List live relationships with structured selectors and an exclusive cursor; no finality proof is attached.
    pub async fn get_relationships_page(
        &self,
        policy_id: FixedBytes<32>,
        request: &vera_modules::acp::pages::RelationshipPageRequest,
    ) -> Result<vera_modules::acp::pages::RecordPage<RelationshipRecord>, ClientError> {
        let call = IAcp::getRelationshipsPageCall {
            policyId: policy_id,
            request: serde_json::to_vec(request)?.into(),
        };
        let output = self.eth_call(ACP_ADDRESS, call.abi_encode().into()).await?;
        let bytes = IAcp::getRelationshipsPageCall::abi_decode_returns(&output)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Evaluate policy assertions at the endpoint's current state; the report is not certified evidence.
    pub async fn evaluate_policy_theorem(
        &self,
        policy_id: FixedBytes<32>,
        source: &str,
    ) -> Result<vera_modules::acp::theorem::TheoremReport, ClientError> {
        let call = IAcp::evaluateTheoremCall {
            policyId: policy_id,
            source: source.into(),
        };
        let output = self.eth_call(ACP_ADDRESS, call.abi_encode().into()).await?;
        let bytes = IAcp::evaluateTheoremCall::abi_decode_returns(&output)
            .map_err(|error| ClientError::AbiDecode(error.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Read an endpoint's live object catalogue. This response carries no finality proof.
    pub async fn get_policy_catalogue(
        &self,
        policy_id: FixedBytes<32>,
    ) -> Result<PolicyCatalogue, ClientError> {
        let input = IAcp::getPolicyCatalogueCall {
            policyId: policy_id,
        }
        .abi_encode();
        let output = self.eth_call(ACP_ADDRESS, input.into()).await?;
        let bytes = IAcp::getPolicyCatalogueCall::abi_decode_returns(&output)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Read full policy records from an endpoint, without finality verification.
    pub async fn get_policies(&self) -> Result<Vec<PolicyRecord>, ClientError> {
        let output = self
            .eth_call(ACP_ADDRESS, IAcp::getPoliciesCall {}.abi_encode().into())
            .await?;
        let bytes = IAcp::getPoliciesCall::abi_decode_returns(&output)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Read registration metadata, including an archived registration.
    pub async fn get_object_registration(
        &self,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
    ) -> Result<Option<RelationshipRecord>, ClientError> {
        let call = IAcp::getObjectRegistrationCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
        };
        let output = self.eth_call(ACP_ADDRESS, call.abi_encode().into()).await?;
        let bytes = IAcp::getObjectRegistrationCall::abi_decode_returns(&output)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Ask an endpoint to evaluate management authority; use certified records when trustless verification is required.
    pub async fn check_management_authority(
        &self,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<bool, ClientError> {
        let call = IAcp::checkManagementAuthorityCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            actor: actor.into(),
        };
        let output = self.eth_call(ACP_ADDRESS, call.abi_encode().into()).await?;
        IAcp::checkManagementAuthorityCall::abi_decode_returns(&output)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))
    }
}
