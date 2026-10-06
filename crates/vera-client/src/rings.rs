//! Durable command encoding and certified reads for threshold-service rings.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall as _;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
use vera_domain::ConsensusPublicKey;
use vera_modules::vera::abi::IVera;
pub use vera_modules::vera::rings::reports::{
    CommitteeScope, NodeDemerits, NodeOffline, ReportEnvelope, ReportOutcome, SignedReport,
};
pub use vera_modules::vera::rings::{
    ReportingConfig, ReshareTarget, RingCommand, RingConfig, RingParticipantCommand,
    RingParticipantRequest, RingPublicKeys, RingRecord, RingReshareRequest, RingSettings,
    RingState, RingUpdate, ScheduledUpgrade, SignedRingParticipantRequest, ThresholdScheme,
    ring_deployment_label,
};

use crate::{ClientError, ModuleId, RECORD_PROOF_BYTES, VeraClient};

/// Encode a delegated command for `NativeWorker::prepare(VERA_ADDRESS, calldata)`.
pub fn encode_ring_command(command: &RingCommand, token: &str) -> Result<Bytes, ClientError> {
    Ok(IVera::applyRingCommandCall {
        request: request_bytes(command)?,
        bearerToken: token.into(),
    }
    .abi_encode()
    .into())
}

/// Sign with the participating node's key, independent of its submission worker.
pub fn sign_ring_participant_request(
    request: RingParticipantRequest,
    key: &SigningKey,
) -> Result<SignedRingParticipantRequest, ClientError> {
    if request.node_key != hex::encode(key.verifying_key().to_sec1_bytes()) {
        return Err(ClientError::Signing("ring participant key mismatch".into()));
    }
    let digest = request
        .signing_digest()
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    Ok(SignedRingParticipantRequest {
        request,
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Encode a participant request for durable preparation before submission.
pub fn encode_ring_participant_request(
    signed: &SignedRingParticipantRequest,
) -> Result<Bytes, ClientError> {
    Ok(IVera::applyRingParticipantRequestCall {
        request: request_bytes(signed)?,
    }
    .abi_encode()
    .into())
}

/// Encode a threshold-signed reshare for durable worker preparation.
pub fn encode_ring_reshare(request: &RingReshareRequest) -> Result<Bytes, ClientError> {
    Ok(IVera::finalizeRingReshareCall {
        request: request_bytes(request)?,
    }
    .abi_encode()
    .into())
}

/// Recover reshare parameters from a journaled command without consulting newer ring state.
pub fn decode_ring_reshare(calldata: &[u8]) -> Result<Option<RingReshareRequest>, ClientError> {
    if !calldata.starts_with(&IVera::finalizeRingReshareCall::SELECTOR) {
        return Ok(None);
    }
    if calldata.len() > vera_modules::vera::rings::MAX_RING_REQUEST_BYTES + 100 {
        return Err(ClientError::InvalidResponse(
            "reshare call exceeds byte limit",
        ));
    }
    let call = IVera::finalizeRingReshareCall::abi_decode(calldata)
        .map_err(|_| ClientError::InvalidResponse("invalid reshare call"))?;
    let request = serde_json::from_slice(&call.request)?;
    if encode_ring_reshare(&request)?.as_ref() != calldata {
        return Err(ClientError::InvalidResponse("noncanonical reshare call"));
    }
    Ok(Some(request))
}

/// Encode an aggregate-signed fault report for durable worker preparation.
pub fn encode_ring_report(report: &SignedReport) -> Result<Bytes, ClientError> {
    let bytes = serde_json::to_vec(report)?;
    if bytes.len() > vera_modules::vera::rings::reports::MAX_REPORT_REQUEST_BYTES {
        return Err(ClientError::Signing("report exceeds byte limit".into()));
    }
    Ok(IVera::submitRingReportCall {
        request: bytes.into(),
    }
    .abi_encode()
    .into())
}

fn request_bytes(request: &impl serde::Serialize) -> Result<Bytes, ClientError> {
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > vera_modules::vera::rings::MAX_RING_REQUEST_BYTES {
        return Err(ClientError::Signing(
            "ring request exceeds byte limit".into(),
        ));
    }
    Ok(bytes.into())
}

/// A certified ring state, including cancellation/conflict, or certified absence.
#[derive(Clone, Debug)]
pub struct RingRead {
    /// Finalized revision covering this read.
    pub revision: u64,
    /// Finalized revision's Unix timestamp.
    pub timestamp: u64,
    /// Authenticated and validated ring record.
    pub record: Option<RingRecord>,
}

/// Certified fault-score state for a threshold ring member.
#[derive(Clone, Debug)]
pub struct NodeDemeritsRead {
    /// Certified revision covering this read.
    pub revision: u64,
    /// Revision's Unix timestamp.
    pub timestamp: u64,
    /// Stored score, or certified absence.
    pub record: Option<NodeDemerits>,
}

impl VeraClient {
    /// Read recorded fault points; apply the ring's reset interval with `effective_points`.
    pub async fn read_threshold_node_demerits(
        &self,
        ring_id: &str,
        node_key: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<NodeDemeritsRead, ClientError> {
        let key = vera_modules::vera::rings::reports::demerits_key(ring_id, node_key)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let response = self
            .read_current_record(ModuleId::Vera, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let record = response
            .record
            .value
            .map(|bytes| {
                if bytes.len() > 512 {
                    return Err(ClientError::InvalidResponse(
                        "fault-score record exceeds byte limit",
                    ));
                }
                let record: NodeDemerits = serde_json::from_slice(&bytes)?;
                if record.points == 0
                    || record.window_started_at == 0
                    || record.revision.block_height == 0
                    || record.revision.block_height > response.revision.height
                {
                    return Err(ClientError::InvalidResponse("invalid fault-score record"));
                }
                Ok(record)
            })
            .transpose()?;
        Ok(NodeDemeritsRead {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            record,
        })
    }

    /// Read ring metadata against caller-provisioned consensus trust and minimum revision.
    pub async fn read_threshold_ring(
        &self,
        id: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<RingRead, ClientError> {
        let key = vera_modules::vera::rings::ring_key(id)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let response = self
            .read_current_record(ModuleId::Vera, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let record = response
            .record
            .value
            .map(|bytes| {
                if bytes.len() > vera_modules::vera::rings::MAX_RING_RECORD_BYTES {
                    return Err(ClientError::InvalidResponse(
                        "ring record exceeds byte limit",
                    ));
                }
                let record: RingRecord = serde_json::from_slice(&bytes)?;
                record
                    .validate(id)
                    .map_err(|_| ClientError::InvalidResponse("invalid ring record"))?;
                Ok::<_, ClientError>(record)
            })
            .transpose()?;
        Ok(RingRead {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            record,
        })
    }
}
