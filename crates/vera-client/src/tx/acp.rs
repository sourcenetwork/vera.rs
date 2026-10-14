//! ACP state-changing transactions via `eth_sendRawTransaction` to precompile `0x0810`.

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use vera_modules::acp::abi::IAcp;

use crate::client::{ACP_ADDRESS, VeraClient, parse_policy_id};
use crate::error::ClientError;
use crate::signer::EvmSigner;
use crate::subject::RelationshipSubject;
use crate::types::TransactionReceipt;

impl VeraClient {
    /// Execute multiple ACP calls atomically in one EVM transaction.
    pub async fn batch_policy_calls(
        &self,
        signer: &EvmSigner,
        calls: Vec<Vec<u8>>,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::batchCallsCall {
            calls: calls.into_iter().map(Into::into).collect(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Create a new ACP policy.
    pub async fn create_policy(
        &self,
        signer: &EvmSigner,
        policy: &[u8],
        marshal_type: u8,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::createPolicyCall {
            policy: policy.to_vec().into(),
            marshalType: marshal_type,
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Set a relationship in an ACP policy.
    pub async fn set_relationship(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::setRelationshipCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Delete a relationship from an ACP policy.
    pub async fn delete_relationship(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::deleteRelationshipCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Set a relationship with a structured (possibly cross-object) subject.
    pub async fn set_relationship_subject(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &RelationshipSubject,
    ) -> Result<TransactionReceipt, ClientError> {
        let (kind, subject_resource, subject_object_id, subject_relation) = subject.to_abi_fields();
        let calldata = IAcp::setRelationshipSubjectCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            subjectKind: kind,
            subjectResource: subject_resource,
            subjectObjectId: subject_object_id,
            subjectRelation: subject_relation,
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Delete a relationship with a structured (possibly cross-object) subject.
    pub async fn delete_relationship_subject(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &RelationshipSubject,
    ) -> Result<TransactionReceipt, ClientError> {
        let (kind, subject_resource, subject_object_id, subject_relation) = subject.to_abi_fields();
        let calldata = IAcp::deleteRelationshipSubjectCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            subjectKind: kind,
            subjectResource: subject_resource,
            subjectObjectId: subject_object_id,
            subjectRelation: subject_relation,
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Register an object in an ACP policy.
    pub async fn register_object(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        object_id: &str,
        resource: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::registerObjectCall {
            policyId: policy_id,
            objectId: object_id.into(),
            resource: resource.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Archive an object in an ACP policy.
    pub async fn archive_object(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        object_id: &str,
        resource: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::archiveObjectCall {
            policyId: policy_id,
            objectId: object_id.into(),
            resource: resource.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Set a relationship via bearer JWT token (actor is the JWT issuer).
    #[allow(clippy::too_many_arguments)]
    pub async fn bearer_set_relationship(
        &self,
        signer: &EvmSigner,
        bearer_token: &str,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let actor_did =
            vera_identity::Did::new(actor).map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        let cmd =
            vera_modules::acp::types::PolicyCmd::SetRelationship(vera_acp::Relationship::new(
                resource,
                object_id,
                relation,
                vera_acp::Subject::entity(actor_did),
            ));
        self.send_bearer_cmd(signer, bearer_token, policy_id, &cmd)
            .await
    }

    /// Delete a relationship via bearer JWT token (actor is the JWT issuer).
    #[allow(clippy::too_many_arguments)]
    pub async fn bearer_delete_relationship(
        &self,
        signer: &EvmSigner,
        bearer_token: &str,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let actor_did =
            vera_identity::Did::new(actor).map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        let cmd =
            vera_modules::acp::types::PolicyCmd::DeleteRelationship(vera_acp::Relationship::new(
                resource,
                object_id,
                relation,
                vera_acp::Subject::entity(actor_did),
            ));
        self.send_bearer_cmd(signer, bearer_token, policy_id, &cmd)
            .await
    }

    /// Register an object via bearer JWT token (JWT issuer becomes owner).
    pub async fn bearer_register_object(
        &self,
        signer: &EvmSigner,
        bearer_token: &str,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let cmd =
            vera_modules::acp::types::PolicyCmd::RegisterObject(vera_modules::acp::types::Object {
                resource: resource.into(),
                id: object_id.into(),
            });
        self.send_bearer_cmd(signer, bearer_token, policy_id, &cmd)
            .await
    }

    /// Archive an object via bearer JWT token (JWT issuer must be owner).
    pub async fn bearer_archive_object(
        &self,
        signer: &EvmSigner,
        bearer_token: &str,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let cmd =
            vera_modules::acp::types::PolicyCmd::ArchiveObject(vera_modules::acp::types::Object {
                resource: resource.into(),
                id: object_id.into(),
            });
        self.send_bearer_cmd(signer, bearer_token, policy_id, &cmd)
            .await
    }

    /// Encode a `bearerPolicyCmd` precompile call and send it.
    async fn send_bearer_cmd(
        &self,
        signer: &EvmSigner,
        bearer_token: &str,
        policy_id: &str,
        cmd: &vera_modules::acp::types::PolicyCmd,
    ) -> Result<TransactionReceipt, ClientError> {
        let pid = parse_policy_id(policy_id)?;
        let cmd_bytes = serde_json::to_vec(cmd)?;
        let calldata = IAcp::bearerPolicyCmdCall {
            bearerToken: bearer_token.into(),
            policyId: pid,
            cmd: cmd_bytes.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Check access (persists a decision record on-chain).
    pub async fn check_access(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resources: Vec<String>,
        object_ids: Vec<String>,
        permissions: Vec<String>,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::checkAccessCall {
            policyId: policy_id,
            resources,
            objectIds: object_ids,
            permissions,
            actor: actor.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    use alloy_sol_types::SolCall;
    use vera_modules::acp::abi::IAcp;

    #[test]
    fn create_policy_calldata_roundtrip() {
        let call = IAcp::createPolicyCall {
            policy: b"name: test".to_vec().into(),
            marshalType: 1,
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IAcp::createPolicyCall as SolCall>::SELECTOR);
        let decoded = IAcp::createPolicyCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.marshalType, 1);
    }

    #[test]
    fn batch_calls_calldata_roundtrip() {
        let inner = IAcp::createPolicyCall {
            policy: b"name: batched".to_vec().into(),
            marshalType: 1,
        }
        .abi_encode();
        let call = IAcp::batchCallsCall {
            calls: vec![inner.into()],
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IAcp::batchCallsCall as SolCall>::SELECTOR);
        let decoded = IAcp::batchCallsCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.calls.len(), 1);
        assert_eq!(decoded.calls[0].to_vec(), call.calls[0].to_vec());
    }

    #[test]
    fn set_relationship_calldata_roundtrip() {
        let call = IAcp::setRelationshipCall {
            policyId: FixedBytes::ZERO,
            resource: "namespace".into(),
            objectId: "obj1".into(),
            relation: "collaborator".into(),
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::setRelationshipCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::setRelationshipCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.resource, "namespace");
        assert_eq!(decoded.relation, "collaborator");
    }

    #[test]
    fn delete_relationship_calldata_roundtrip() {
        let call = IAcp::deleteRelationshipCall {
            policyId: FixedBytes::ZERO,
            resource: "namespace".into(),
            objectId: "obj1".into(),
            relation: "collaborator".into(),
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::deleteRelationshipCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::deleteRelationshipCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.objectId, "obj1");
    }

    #[test]
    fn register_object_calldata_roundtrip() {
        let call = IAcp::registerObjectCall {
            policyId: FixedBytes::ZERO,
            objectId: "obj1".into(),
            resource: "namespace".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::registerObjectCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::registerObjectCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.objectId, "obj1");
        assert_eq!(decoded.resource, "namespace");
    }

    #[test]
    fn archive_object_calldata_roundtrip() {
        let call = IAcp::archiveObjectCall {
            policyId: FixedBytes::ZERO,
            objectId: "obj1".into(),
            resource: "namespace".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::archiveObjectCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::archiveObjectCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.objectId, "obj1");
    }

    #[test]
    fn bearer_policy_cmd_calldata_roundtrip() {
        let cmd =
            vera_modules::acp::types::PolicyCmd::RegisterObject(vera_modules::acp::types::Object {
                resource: "namespace".into(),
                id: "obj1".into(),
            });
        let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
        let call = IAcp::bearerPolicyCmdCall {
            bearerToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.test.sig".into(),
            policyId: FixedBytes::ZERO,
            cmd: cmd_bytes.into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::bearerPolicyCmdCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::bearerPolicyCmdCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.bearerToken, call.bearerToken);
        let decoded_cmd: vera_modules::acp::types::PolicyCmd =
            serde_json::from_slice(&decoded.cmd).unwrap();
        assert!(matches!(
            decoded_cmd,
            vera_modules::acp::types::PolicyCmd::RegisterObject(_)
        ));
    }

    #[test]
    fn check_access_calldata_roundtrip() {
        let call = IAcp::checkAccessCall {
            policyId: FixedBytes::ZERO,
            resources: vec!["namespace".into()],
            objectIds: vec!["obj1".into()],
            permissions: vec!["create_post".into()],
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IAcp::checkAccessCall as SolCall>::SELECTOR);
        let decoded = IAcp::checkAccessCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.resources, vec!["namespace"]);
        assert_eq!(decoded.permissions, vec!["create_post"]);
    }
}
