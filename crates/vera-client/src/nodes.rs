//! Threshold-service node commands with authority independent of the submission worker.

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use k256_native::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
use vera_domain::ConsensusPublicKey;
use vera_modules::vera::abi::IVera;
pub use vera_modules::vera::nodes::{
    NodeCommand, NodeInfo, NodeRecord, NodeRequest, NodeTarget, SignedNodeRequest,
};

use crate::{BlsSigner, ClientError, ModuleId, RECORD_PROOF_BYTES, VERA_ADDRESS, VeraClient};

/// A certified node record or absence at one revision.
#[derive(Clone, Debug)]
pub struct NodeRead {
    /// Captured finalized revision.
    pub revision: u64,
    /// Captured revision's Unix timestamp.
    pub timestamp: u64,
    /// Validated service metadata, or certified absence.
    pub record: Option<NodeRecord>,
}

/// Sign the complete node request using the node key or current controller.
pub fn sign_node_request(
    request: NodeRequest,
    key: &SigningKey,
) -> Result<SignedNodeRequest, ClientError> {
    let digest = request
        .signing_digest()
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    Ok(SignedNodeRequest {
        request,
        signer_key: hex::encode(key.verifying_key().to_sec1_bytes()),
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Encode a node command for `NativeWorker::prepare` before network submission.
pub fn encode_node_request(
    signed: &SignedNodeRequest,
) -> Result<alloy_primitives::Bytes, ClientError> {
    let request = serde_json::to_vec(signed)?;
    if request.len() > vera_modules::vera::nodes::MAX_NODE_BYTES {
        return Err(ClientError::Signing(
            "node request exceeds byte limit".into(),
        ));
    }
    Ok(IVera::applyNodeRequestCall {
        request: request.into(),
    }
    .abi_encode()
    .into())
}

impl VeraClient {
    /// Submit an authorized node command. Retain the returned ID for certified receipt recovery.
    pub async fn submit_node_request(
        &self,
        submitter: &BlsSigner,
        signed: &SignedNodeRequest,
    ) -> Result<B256, ClientError> {
        let wire = submitter.sign_native_tx(VERA_ADDRESS, encode_node_request(signed)?)?;
        let expected: B256 = vera_domain::NativeTx::decode_wire(&wire)
            .map_err(|e| ClientError::Signing(e.to_string()))?
            .tx_id()
            .0;
        let submitted = self.send_native_tx(&wire).await?;
        if submitted != expected {
            return Err(ClientError::InvalidResponse(
                "node submission identifier mismatch",
            ));
        }
        Ok(submitted)
    }

    /// Read node metadata with caller-provided consensus trust and minimum revision.
    pub async fn read_threshold_node(
        &self,
        node_key: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<NodeRead, ClientError> {
        let key = vera_modules::vera::nodes::node_key(node_key)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let response = self
            .read_current_record(ModuleId::Vera, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let record = response
            .record
            .value
            .map(|bytes| {
                if bytes.len() > vera_modules::vera::nodes::MAX_NODE_BYTES {
                    return Err(ClientError::InvalidResponse(
                        "node record exceeds byte limit",
                    ));
                }
                let record: NodeRecord = serde_json::from_slice(&bytes)?;
                record
                    .validate(node_key)
                    .map_err(|_| ClientError::InvalidResponse("invalid node record"))?;
                Ok::<_, ClientError>(record)
            })
            .transpose()?;
        Ok(NodeRead {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            record,
        })
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;

    #[test]
    fn native_node_and_ring_signatures_match_previous_version() {
        let secret = [31; 32];
        let key = crate::Secp256k1SigningKey::from_slice(&secret).unwrap();
        let legacy = k256::ecdsa::SigningKey::from_slice(&secret).unwrap();
        let node_key = hex::encode(key.verifying_key().to_sec1_bytes());
        let node = NodeRequest {
            deployment_root: [1; 32],
            deployment_id: 42,
            node_key: node_key.clone(),
            sequence: 1,
            expires_at: 100,
            command: NodeCommand::SetPeer("peer".into()),
        };
        let digest = node.signing_digest().unwrap();
        let old: k256::ecdsa::Signature = legacy.sign_prehash(&digest).unwrap();
        let signed = sign_node_request(node, &key).unwrap();
        assert_eq!(signed.signature, hex::encode(old.to_bytes()));
        vera_crypto::secp256k1::verify_digest(
            &hex::decode(&signed.signer_key).unwrap(),
            &digest,
            &hex::decode(&signed.signature).unwrap(),
        )
        .unwrap();

        let ring = crate::rings::RingParticipantRequest {
            deployment_root: [1; 32],
            deployment_id: 42,
            ring_id: "ring".into(),
            node_key,
            command: crate::rings::RingParticipantCommand::Cancel,
            expires_at: 100,
        };
        let digest = ring.signing_digest().unwrap();
        let old: k256::ecdsa::Signature = legacy.sign_prehash(&digest).unwrap();
        let signed = crate::rings::sign_ring_participant_request(ring, &key).unwrap();
        assert_eq!(signed.signature, hex::encode(old.to_bytes()));
        vera_crypto::secp256k1::verify_digest(
            &hex::decode(&signed.request.node_key).unwrap(),
            &digest,
            &hex::decode(&signed.signature).unwrap(),
        )
        .unwrap();
    }
}
