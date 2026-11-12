//! Operator approvals and administrative submission.

use alloy_sol_types::SolCall;
use k256_native::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
use vera_modules::vera::abi::IVera;

pub use vera_modules::vera::administration::{
    AdministrationState, AdministrativeCommand, AdministrativeRequest, OperatorApproval,
    OperatorPolicy, SignedAdministrativeRequest,
};

use crate::{BlsSigner, ClientError, EvmSigner, TransactionReceipt, VERA_ADDRESS, VeraClient};

/// Sign an explicit request using this key's index in the current operator policy.
pub fn approve_administration(
    request: &AdministrativeRequest,
    signer: u16,
    key: &SigningKey,
) -> Result<OperatorApproval, ClientError> {
    let digest = request
        .signing_digest()
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    Ok(OperatorApproval {
        signer,
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Build an approval from a signature made outside this library.
///
/// For operator keys this library cannot hold, such as hardware-backed keys.
/// The operator signs [`AdministrativeRequest::signing_digest`]: ECDSA keys
/// (secp256k1, P-256) as the prehash, Ed25519 keys as the message. `signature`
/// is the raw 64 bytes; either ECDSA `s` is accepted. A signature the key at
/// `signer` in `policy` did not make over this request is an error.
pub fn external_approval(
    request: &AdministrativeRequest,
    policy: &OperatorPolicy,
    signer: u16,
    signature: &[u8],
) -> Result<OperatorApproval, ClientError> {
    let signing = |error: &dyn std::fmt::Display| ClientError::Signing(error.to_string());
    let operator = policy.operator_did(signer).map_err(|e| signing(&e))?;
    let signature =
        vera_crypto::actor::canonical_signature(&operator, signature).map_err(|e| signing(&e))?;
    checked_approval(request, policy, signer, &signature)
}

/// Build an approval from an ASN.1 DER ECDSA signature, as platform key
/// stores return it. See [`external_approval`].
pub fn external_der_approval(
    request: &AdministrativeRequest,
    policy: &OperatorPolicy,
    signer: u16,
    signature: &[u8],
) -> Result<OperatorApproval, ClientError> {
    let signing = |error: &dyn std::fmt::Display| ClientError::Signing(error.to_string());
    let operator = policy.operator_did(signer).map_err(|e| signing(&e))?;
    let signature = vera_crypto::actor::canonical_der_signature(&operator, signature)
        .map_err(|e| signing(&e))?;
    checked_approval(request, policy, signer, &signature)
}

fn checked_approval(
    request: &AdministrativeRequest,
    policy: &OperatorPolicy,
    signer: u16,
    signature: &[u8],
) -> Result<OperatorApproval, ClientError> {
    let digest = request
        .signing_digest()
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    let approval = OperatorApproval {
        signer,
        signature: hex::encode(signature),
    };
    policy
        .verify_approval(&digest, &approval)
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    Ok(approval)
}

/// Operator configuration or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct AdministrationRecord {
    /// Revision authenticating this configuration.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Current operator policy and next administrative sequence.
    pub value: Option<AdministrationState>,
}

fn decode_state(bytes: &[u8]) -> Result<AdministrationState, ClientError> {
    let state: AdministrationState = borsh::from_slice(bytes)
        .map_err(|_| ClientError::InvalidResponse("invalid administration encoding"))?;
    state
        .policy
        .validate()
        .map_err(|_| ClientError::InvalidResponse("invalid operator policy"))?;
    Ok(state)
}

/// ACP configuration or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct AcpParameterRecord {
    /// Revision authenticating this configuration.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Stored parameters; absence selects `AcpParams::default()` during execution.
    pub value: Option<vera_modules::acp::types::AcpParams>,
}

impl VeraClient {
    /// Read ACP parameters from certified native state, distinguishing absence from corruption.
    pub async fn read_acp_parameters(
        &self,
        minimum: u64,
        trusted: &vera_domain::ConsensusPublicKey,
    ) -> Result<AcpParameterRecord, ClientError> {
        let response = self
            .read_current_record(
                vera_permission::ModuleId::Acp,
                vera_modules::acp::keys::PARAMS_KEY,
                minimum,
                trusted,
                vera_permission::RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| {
                borsh::from_slice(bytes)
                    .map_err(|_| ClientError::InvalidResponse("invalid ACP parameter encoding"))
            })
            .transpose()?;
        Ok(AcpParameterRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }

    /// Verify the current operator policy and sequence using independently configured consensus trust.
    pub async fn read_administration(
        &self,
        minimum: u64,
        trusted: &vera_domain::ConsensusPublicKey,
    ) -> Result<AdministrationRecord, ClientError> {
        let response = self
            .read_current_record(
                vera_permission::ModuleId::Vera,
                vera_modules::vera::administration::STATE_KEY,
                minimum,
                trusted,
                vera_permission::RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode_state(bytes))
            .transpose()?;
        Ok(AdministrationRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }

    /// Fetch the current operator policy and next administrative sequence.
    pub async fn administration(&self) -> Result<Option<AdministrationState>, ClientError> {
        let result = self
            .eth_call(
                VERA_ADDRESS,
                IVera::getAdministrationCall {}.abi_encode().into(),
            )
            .await?;
        let bytes = IVera::getAdministrationCall::abi_decode_returns(&result)
            .map_err(|error| ClientError::AbiDecode(error.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Submit operator approvals through an independent BLS submitter.
    pub async fn native_apply_administration(
        &self,
        submitter: &BlsSigner,
        signed: &SignedAdministrativeRequest,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IVera::applyAdministrationCall {
            request: serde_json::to_vec(signed)?.into(),
        }
        .abi_encode();
        self.send_native_precompile_tx(submitter, VERA_ADDRESS, calldata.into())
            .await
    }

    /// Submit operator approvals through an independent secp256k1 submitter.
    pub async fn apply_administration(
        &self,
        submitter: &EvmSigner,
        signed: &SignedAdministrativeRequest,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IVera::applyAdministrationCall {
            request: serde_json::to_vec(signed)?.into(),
        }
        .abi_encode();
        self.send_precompile_tx(submitter, VERA_ADDRESS, calldata.into())
            .await
    }
}

#[cfg(test)]
mod certified_tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;

    #[test]
    fn operator_signature_matches_previous_version() {
        let secret = [3u8; 32];
        let key = SigningKey::from_slice(&secret).unwrap();
        let legacy = k256::ecdsa::SigningKey::from_slice(&secret).unwrap();
        let request = AdministrativeRequest {
            genesis_id: [1; 32],
            sequence: 7,
            expires_at: 100,
            command: AdministrativeCommand::SetOperationBudget(1024),
        };
        let digest = request.signing_digest().unwrap();
        let old: k256::ecdsa::Signature = legacy.sign_prehash(&digest).unwrap();
        let approval = approve_administration(&request, 0, &key).unwrap();
        assert_eq!(approval.signature, hex::encode(old.to_bytes()));
        vera_crypto::secp256k1::verify_digest(
            &key.verifying_key().to_sec1_bytes(),
            &digest,
            &hex::decode(&approval.signature).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn an_external_secp256k1_signature_becomes_the_same_approval() {
        let key = SigningKey::from_slice(&[3; 32]).unwrap();
        let legacy = k256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let policy = OperatorPolicy {
            threshold: 1,
            keys: vec![hex::encode(key.verifying_key().to_sec1_bytes())],
        };
        let request = AdministrativeRequest {
            genesis_id: [1; 32],
            sequence: 7,
            expires_at: 100,
            command: AdministrativeCommand::SetOperationBudget(1024),
        };
        let own = approve_administration(&request, 0, &key).unwrap();
        let signature: k256::ecdsa::Signature = legacy
            .sign_prehash(&request.signing_digest().unwrap())
            .unwrap();
        let low = signature.normalize_s().unwrap_or(signature);
        let high = k256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
        for raw in [low.to_vec(), high.to_vec()] {
            assert_eq!(external_approval(&request, &policy, 0, &raw).unwrap(), own);
        }
        let der = low.to_der();
        assert_eq!(
            external_der_approval(&request, &policy, 0, der.as_bytes()).unwrap(),
            own
        );
        assert!(external_approval(&request, &policy, 1, &low.to_vec()).is_err());
        let other = AdministrativeRequest {
            sequence: 8,
            ..request
        };
        assert!(external_approval(&other, &policy, 0, &low.to_vec()).is_err());
    }

    #[test]
    fn certified_administration_rejects_malformed_policy_and_encoding() {
        let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let mut state = AdministrationState {
            policy: OperatorPolicy {
                threshold: 1,
                keys: vec![hex::encode(key.verifying_key().to_sec1_bytes())],
            },
            sequence: 7,
            membership_policy: Some([3; 32]),
        };
        let bytes = borsh::to_vec(&state).unwrap();
        assert_eq!(decode_state(&bytes).unwrap(), state);
        assert!(decode_state(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_state(&trailing).is_err());
        state.policy.threshold = 0;
        assert!(decode_state(&borsh::to_vec(&state).unwrap()).is_err());
        state.policy.threshold = 1;
        state.policy.keys.push(state.policy.keys[0].clone());
        assert!(decode_state(&borsh::to_vec(&state).unwrap()).is_err());
    }
}
