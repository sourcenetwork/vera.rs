//! ACP typed queries: unauthenticated view calls to the module at `0x0810`.

use alloy_primitives::{Bytes, FixedBytes};
use alloy_sol_types::SolCall;
use vera_modules::acp::abi::IAcp;

use crate::client::{ACP_ADDRESS, VeraClient};
use crate::error::ClientError;

impl VeraClient {
    /// Fetch a policy by ID (ABI-encoded JSON bytes).
    /// Unauthenticated; the verified read is [`VeraClient::read_policy`].
    pub async fn get_policy(&self, policy_id: FixedBytes<32>) -> Result<Bytes, ClientError> {
        let calldata = IAcp::getPolicyCall {
            policyId: policy_id,
        }
        .abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::getPolicyCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Check if a relationship exists in a policy.
    /// Unauthenticated; the verified read is [`VeraClient::read_current_record`].
    pub async fn has_relationship(
        &self,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<bool, ClientError> {
        let calldata = IAcp::hasRelationshipCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::hasRelationshipCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Verify an access request (read-only, does not persist a decision).
    /// Unauthenticated; the verified evaluation is [`VeraClient::verify_current_access`].
    pub async fn verify_access_request(
        &self,
        policy_id: FixedBytes<32>,
        resources: Vec<String>,
        object_ids: Vec<String>,
        permissions: Vec<String>,
        actor: &str,
    ) -> Result<bool, ClientError> {
        let calldata = IAcp::verifyAccessRequestCall {
            policyId: policy_id,
            resources,
            objectIds: object_ids,
            permissions,
            actor: actor.into(),
        }
        .abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::verifyAccessRequestCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Check if an object is registered and get its owner record.
    /// Unauthenticated; the verified read is [`VeraClient::read_current_policy_prefix`] with `PolicyPrefixResponse::verify_object_owner`.
    pub async fn get_object_owner(
        &self,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
    ) -> Result<(bool, Bytes), ClientError> {
        let calldata = IAcp::getObjectOwnerCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
        }
        .abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::getObjectOwnerCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok((decoded.registered, decoded.record))
    }

    /// List all policy IDs.
    /// Unauthenticated; the verified read is [`VeraClient::read_policy_page`].
    pub async fn get_policy_ids(&self) -> Result<Vec<String>, ClientError> {
        let calldata = IAcp::getPolicyIdsCall {}.abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::getPolicyIdsCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Filter relationships matching a selector.
    /// Unauthenticated; the verified reads are [`VeraClient::read_relationship_page`] and [`VeraClient::read_current_policy_prefix_page`].
    pub async fn filter_relationships(
        &self,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<Bytes, ClientError> {
        let calldata = IAcp::filterRelationshipsCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::filterRelationshipsCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Validate a policy definition without storing it.
    /// Unauthenticated; parse the policy locally with `vera-acp` to validate it without a node.
    pub async fn validate_policy(
        &self,
        policy: &[u8],
        marshal_type: u8,
    ) -> Result<(bool, String), ClientError> {
        let calldata = IAcp::validatePolicyCall {
            policy: policy.to_vec().into(),
            marshalType: marshal_type,
        }
        .abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::validatePolicyCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok((decoded.valid, decoded.reason))
    }

    /// Fetch a previously recorded access decision.
    /// Unauthenticated; the verified read is [`VeraClient::read_access_decision`].
    pub async fn get_access_decision(&self, decision_id: &str) -> Result<Bytes, ClientError> {
        let calldata = IAcp::getAccessDecisionCall {
            decisionId: decision_id.into(),
        }
        .abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::getAccessDecisionCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Fetch current ACP module parameters.
    /// Unauthenticated; the verified read is [`VeraClient::read_acp_parameters`].
    pub async fn get_acp_params(&self) -> Result<Bytes, ClientError> {
        let calldata = IAcp::getParamsCall {}.abi_encode();
        let result = self.view_call(ACP_ADDRESS, calldata.into()).await?;
        let decoded = IAcp::getParamsCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_policy_calldata_selector() {
        let policy_id = FixedBytes::ZERO;
        let calldata = IAcp::getPolicyCall {
            policyId: policy_id,
        }
        .abi_encode();
        assert_eq!(calldata.len(), 4 + 32);
        let selector = &calldata[..4];
        let expected = <IAcp::getPolicyCall as SolCall>::SELECTOR;
        assert_eq!(selector, expected);
    }

    #[test]
    fn has_relationship_calldata_roundtrip() {
        let policy_id = FixedBytes::ZERO;
        let call = IAcp::hasRelationshipCall {
            policyId: policy_id,
            resource: "namespace".into(),
            objectId: "obj1".into(),
            relation: "collaborator".into(),
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::hasRelationshipCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::hasRelationshipCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.resource, "namespace");
        assert_eq!(decoded.objectId, "obj1");
    }

    #[test]
    fn verify_access_request_calldata_roundtrip() {
        let policy_id = FixedBytes::ZERO;
        let call = IAcp::verifyAccessRequestCall {
            policyId: policy_id,
            resources: vec!["namespace".into()],
            objectIds: vec!["obj1".into()],
            permissions: vec!["create_post".into()],
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        let decoded = IAcp::verifyAccessRequestCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.resources, vec!["namespace"]);
        assert_eq!(decoded.permissions, vec!["create_post"]);
    }

    #[test]
    fn get_policy_ids_calldata_selector() {
        let calldata = IAcp::getPolicyIdsCall {}.abi_encode();
        assert_eq!(calldata.len(), 4);
        assert_eq!(
            &calldata[..4],
            <IAcp::getPolicyIdsCall as SolCall>::SELECTOR
        );
    }

    #[test]
    fn validate_policy_calldata_roundtrip() {
        let call = IAcp::validatePolicyCall {
            policy: b"name: test".to_vec().into(),
            marshalType: 1,
        };
        let encoded = call.abi_encode();
        let decoded = IAcp::validatePolicyCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.marshalType, 1);
    }

    #[test]
    fn get_params_calldata_selector() {
        let calldata = IAcp::getParamsCall {}.abi_encode();
        assert_eq!(calldata.len(), 4);
        assert_eq!(&calldata[..4], <IAcp::getParamsCall as SolCall>::SELECTOR);
    }
}
