use super::*;
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Threshold authorization for the currently announced committee change.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingReshareRequest {
    /// Initial finalized deployment state.
    pub deployment_root: [u8; 32],
    /// Native deployment identifier.
    pub deployment_id: u64,
    /// Immutable ring identifier.
    pub ring_id: String,
    /// Ring sequence used to construct the signing document.
    pub expected_sequence: u64,
    /// Existing ring signature format.
    pub scheme: ThresholdScheme,
    /// Canonical lowercase hex aggregate signature.
    pub signature: String,
}

/// Deployment namespace supplied to the Orbis reshare signing document.
pub fn ring_deployment_label(root: [u8; 32], deployment_id: u64) -> String {
    format!("vera:{deployment_id}:{}", hex::encode(root))
}

impl RingRecord {
    /// Build Orbis reshare sign bytes from a validated current record and its pending target.
    pub fn reshare_signing_bytes(&self, deployment_id: u64) -> Result<Vec<u8>> {
        self.validate(&self.id)?;
        let RingState::Active { keys } = &self.state else {
            return Err(invalid("ring is not active"));
        };
        let settings = self.current_settings();
        let target = settings
            .pending_reshare
            .ok_or_else(|| invalid("reshare is not pending"))?;
        let mut state = SignState {
            public_key: keys.public_key.clone(),
            peers: settings.peer_node_keys,
            threshold: settings.threshold,
            next_peers: target.peer_node_keys.clone(),
            next_threshold: Some(target.threshold),
            sequence: self.sequence,
            policy_id: self.config.policy_id.clone(),
            allow_relays: settings.trusted_auth_relay_dids.is_some(),
            relays: settings.trusted_auth_relay_dids.unwrap_or_default(),
        };
        let current_state = Sha256::digest(state.encode_to_vec()).to_vec();
        state.peers = target.peer_node_keys;
        state.threshold = target.threshold;
        state.next_peers.clear();
        state.next_threshold = None;
        Ok(SignDoc {
            domain: "orbis-ring-reshare-finalize".into(),
            deployment: ring_deployment_label(self.deployment_root, deployment_id),
            ring_id: self.id.clone(),
            public_key: keys.public_key.clone(),
            current_state,
            finalized_state: Sha256::digest(state.encode_to_vec()).to_vec(),
            sequence: self.sequence,
        }
        .encode_to_vec())
    }
}

impl VeraModule {
    /// Finalize a pending reshare using the existing ring key without changing that key.
    pub fn finalize_ring_reshare(
        &mut self,
        context: &BlockExecCtx,
        request: &RingReshareRequest,
    ) -> Result<RingRecord> {
        if serde_json::to_vec(request).map_err(invalid)?.len() > MAX_RING_REQUEST_BYTES
            || request.deployment_root != context.genesis_id
            || request.deployment_id != context.deployment_id
        {
            return Err(invalid("reshare request size or deployment mismatch"));
        }
        let mut record = self
            .threshold_ring(&request.ring_id)?
            .ok_or_else(|| invalid("ring not found"))?;
        if record.deployment_root != context.genesis_id
            || record.sequence != request.expected_sequence
        {
            return Err(invalid("ring deployment or sequence changed"));
        }
        let message = record.reshare_signing_bytes(context.deployment_id)?;
        let RingState::Active { keys } = &record.state else {
            return Err(invalid("ring is not active"));
        };
        let signature = hex::decode(&request.signature).map_err(invalid)?;
        if hex::encode(&signature) != request.signature {
            return Err(invalid("noncanonical threshold signature"));
        }
        vera_crypto::threshold::verify(
            request.scheme,
            &hex::decode(&keys.public_key).map_err(invalid)?,
            &message,
            &signature,
        )
        .map_err(invalid)?;
        let mut settings = record.current_settings();
        let target = settings
            .pending_reshare
            .take()
            .ok_or_else(|| invalid("reshare is not pending"))?;
        self.require_ring_nodes(&target.peer_node_keys, &record)?;
        settings.peer_node_keys = target.peer_node_keys;
        settings.threshold = target.threshold;
        record.settings = Some(settings);
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("ring sequence exhausted"))?;
        record.revision = context.timestamp.clone();
        let bytes = super::record_bytes(&record)?;
        self.store.put(&ring_key(&record.id)?, bytes);
        Ok(record)
    }
}

// Wire tags match Orbis's reshare signing protocol; these are not stored records.
#[derive(Clone, Message)]
struct SignState {
    #[prost(string, tag = "1")]
    public_key: String,
    #[prost(string, repeated, tag = "2")]
    peers: Vec<String>,
    #[prost(uint32, tag = "3")]
    threshold: u32,
    #[prost(string, repeated, tag = "4")]
    next_peers: Vec<String>,
    #[prost(uint32, optional, tag = "5")]
    next_threshold: Option<u32>,
    #[prost(uint64, tag = "7")]
    sequence: u64,
    #[prost(string, tag = "8")]
    policy_id: String,
    #[prost(string, repeated, tag = "9")]
    relays: Vec<String>,
    #[prost(bool, tag = "10")]
    allow_relays: bool,
}

#[derive(Clone, Message)]
struct SignDoc {
    #[prost(string, tag = "1")]
    domain: String,
    #[prost(string, tag = "2")]
    deployment: String,
    #[prost(string, tag = "3")]
    ring_id: String,
    #[prost(string, tag = "4")]
    public_key: String,
    #[prost(bytes = "vec", tag = "5")]
    current_state: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    finalized_state: Vec<u8>,
    #[prost(uint64, tag = "7")]
    sequence: u64,
}
