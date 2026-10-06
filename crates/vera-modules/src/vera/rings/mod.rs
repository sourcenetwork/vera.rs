//! ACP-authorized ring lifecycle and participant-authenticated fresh-DKG outcomes.

mod administration;
pub mod reports;
mod reshare;
mod types;
pub use reshare::{RingReshareRequest, ring_deployment_label};
pub use types::*;
pub use vera_crypto::threshold::ThresholdScheme;

use super::{Result, VeraError, VeraModule};
use crate::{
    acp::{
        AcpModule,
        delegated_operation::DelegatedOperation,
        types::{AccessRequest, Actor, Object, Operation, PolicyCmd},
    },
    kv_store::ModuleKvStore as _,
    types::{BlockExecCtx, TxExecCtx},
};
use identity::Did;

pub(super) fn invalid(error: impl std::fmt::Display) -> VeraError {
    VeraError::InvalidRingRequest {
        reason: error.to_string(),
    }
}

/// Native record key, including terminal rings retained to prevent identity reuse.
pub fn ring_key(id: &str) -> Result<Vec<u8>> {
    if id.len() != 64 || hex::decode(id).is_err() || id.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid("invalid ring identifier"));
    }
    Ok(format!("orbis/ring/v2/{id}").into_bytes())
}

impl VeraModule {
    /// Decode and validate a ring from stored state, distinguishing corruption from absence.
    pub fn threshold_ring(&self, id: &str) -> Result<Option<RingRecord>> {
        self.store
            .get(&ring_key(id)?)
            .map(|bytes| {
                if bytes.len() > MAX_RING_RECORD_BYTES {
                    return Err(invalid("ring record exceeds byte limit"));
                }
                let record: RingRecord = serde_json::from_slice(&bytes).map_err(invalid)?;
                record.validate(id)?;
                Ok(record)
            })
            .transpose()
    }

    /// Execute an ACP-authorized command with shared delegation revocation, rollback and retry handling.
    pub fn apply_ring_command(
        &mut self,
        acp: &mut AcpModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        command: &RingCommand,
    ) -> Result<RingRecord> {
        if serde_json::to_vec(command).map_err(invalid)?.len() > MAX_RING_REQUEST_BYTES {
            return Err(invalid("ring command exceeds byte limit"));
        }
        let operation = DelegatedOperation::RingCommand(command);
        acp.with_delegation(
            self,
            context,
            submission,
            token,
            (operation.scope(), operation.digest().map_err(invalid)?),
            |acp, vera, actor| {
                vera.ring_command(acp, context, actor, command)
                    .map_err(|error| crate::acp::error::AcpError::State(error.to_string()))
            },
        )
        .map_err(invalid)
    }

    fn ring_command(
        &mut self,
        acp: &mut AcpModule,
        context: &BlockExecCtx,
        actor: &Did,
        command: &RingCommand,
    ) -> Result<RingRecord> {
        let mut record = match command {
            RingCommand::Create(config) => {
                let id = config.id(context.genesis_id, actor.as_str())?;
                if self.threshold_ring(&id)?.is_some() {
                    return Err(invalid("ring identity already used"));
                }
                for key in config
                    .peer_node_keys
                    .iter()
                    .chain(&config.reporting.backup_node_keys)
                {
                    if self.threshold_node(key)?.is_none() {
                        return Err(invalid("ring node is not registered"));
                    }
                }
                let access = AccessRequest {
                    actor: Actor(actor.clone()),
                    operations: vec![Operation {
                        object: Object {
                            resource: "ring_policy".into(),
                            id: config.policy_id.clone(),
                        },
                        permission: "create_ring".into(),
                    }],
                };
                if !acp
                    .query_verify_access_request(&config.policy_id, &access)
                    .map_err(invalid)?
                {
                    return Err(invalid("actor cannot create a ring under this policy"));
                }
                RingRecord {
                    id,
                    deployment_root: context.genesis_id,
                    creator: actor.to_string(),
                    config: config.clone(),
                    state: RingState::Pending {
                        keys: None,
                        confirmations: Vec::new(),
                    },
                    revision: context.timestamp.clone(),
                    settings: None,
                    sequence: 0,
                }
            }
            RingCommand::Update {
                ring_id,
                expected_sequence,
                update,
            } => self.update_ring(acp, context, actor, ring_id, *expected_sequence, update)?,
            RingCommand::Cancel { ring_id } => {
                let mut record = self
                    .threshold_ring(ring_id)?
                    .ok_or_else(|| invalid("ring not found"))?;
                if record.creator != actor.as_str()
                    || !matches!(record.state, RingState::Pending { .. })
                {
                    return Err(invalid("only the creator can cancel a pending ring"));
                }
                record.state = RingState::Cancelled {
                    by: actor.to_string(),
                };
                record
            }
        };
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("ring sequence exhausted"))?;
        record.revision = context.timestamp.clone();
        let bytes = record_bytes(&record)?;
        if matches!(command, RingCommand::Create(_)) {
            acp.direct_policy_cmd(
                actor,
                &record.config.policy_id,
                PolicyCmd::RegisterObject(Object {
                    resource: "ring".into(),
                    id: record.id.clone(),
                }),
            )
            .map_err(invalid)?;
        }
        self.store.put(&ring_key(&record.id)?, bytes);
        Ok(record)
    }

    /// Record a participant's signed confirmation or cancellation without delegating its node key.
    pub fn apply_ring_participant_request(
        &mut self,
        context: &BlockExecCtx,
        signed: &SignedRingParticipantRequest,
    ) -> Result<RingRecord> {
        if serde_json::to_vec(signed).map_err(invalid)?.len() > MAX_RING_REQUEST_BYTES {
            return Err(invalid("ring request exceeds byte limit"));
        }
        let request = &signed.request;
        if request.deployment_root != context.genesis_id
            || request.deployment_id != context.deployment_id
            || request.expires_at < context.timestamp.seconds
        {
            return Err(invalid("ring request deployment or expiry"));
        }
        let mut record = self
            .threshold_ring(&request.ring_id)?
            .ok_or_else(|| invalid("ring not found"))?;
        if record.deployment_root != context.genesis_id
            || record
                .config
                .peer_node_keys
                .binary_search(&request.node_key)
                .is_err()
        {
            return Err(invalid("signer is not a ring participant"));
        }
        super::nodes::node_key(&request.node_key).map_err(invalid)?;
        if signed.signature.len() != 128 {
            return Err(invalid("invalid ring signature length"));
        }
        let signature = hex::decode(&signed.signature).map_err(invalid)?;
        if hex::encode(&signature) != signed.signature {
            return Err(invalid("noncanonical ring signature"));
        }
        vera_crypto::secp256k1::verify_digest(
            &hex::decode(&request.node_key).map_err(invalid)?,
            &request.signing_digest()?,
            &signature,
        )
        .map_err(invalid)?;
        let RingState::Pending {
            keys,
            confirmations,
        } = &mut record.state
        else {
            return Err(invalid("ring is not pending"));
        };
        match &request.command {
            RingParticipantCommand::Cancel => {
                record.state = RingState::Cancelled {
                    by: vera_crypto::secp256k1::did_from_secp256k1_pubkey(
                        &hex::decode(&request.node_key).map_err(invalid)?,
                    )
                    .map_err(invalid)?,
                };
            }
            RingParticipantCommand::Confirm(key) => {
                key.validate(record.config.requires_pet)?;
                let node = self
                    .threshold_node(&request.node_key)?
                    .ok_or_else(|| invalid("node not registered"))?;
                if !node.info.allows_ring(&record.config.policy_id, &record.id) {
                    return Err(invalid("node controller does not permit this ring"));
                }
                let position = confirmations
                    .binary_search(&request.node_key)
                    .err()
                    .ok_or_else(|| invalid("node already confirmed"))?;
                if let Some(first) = keys.as_ref().filter(|first| *first != key) {
                    record.state = RingState::Conflict {
                        first_keys: first.clone(),
                        conflicting_keys: key.clone(),
                        by: request.node_key.clone(),
                    };
                } else {
                    *keys = Some(key.clone());
                    confirmations.insert(position, request.node_key.clone());
                    if confirmations.len() == record.config.peer_node_keys.len() {
                        record.state = RingState::Active { keys: key.clone() };
                    }
                }
            }
        }
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("ring sequence exhausted"))?;
        record.revision = context.timestamp.clone();
        let bytes = record_bytes(&record)?;
        self.store.put(&ring_key(&record.id)?, bytes);
        Ok(record)
    }
}

fn record_bytes(record: &RingRecord) -> Result<Vec<u8>> {
    record.validate(&record.id)?;
    let bytes = serde_json::to_vec(record).map_err(invalid)?;
    if bytes.len() > MAX_RING_RECORD_BYTES {
        return Err(invalid("ring record exceeds byte limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
