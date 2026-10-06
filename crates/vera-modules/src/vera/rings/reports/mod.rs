//! Threshold-authorized fault reports and bounded replay accounting.
#![allow(missing_docs)]

mod evidence;
mod state;

use super::*;
use crate::types::Timestamp;
use orbis_reporting::REPORT_TTL_SECS;
use orbis_reporting::codec::*;
pub use orbis_reporting::{CommitteeScope, NodeOffline, ReportEnvelope};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const MAX_REPORT_REQUEST_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_REPORT_PAYLOAD_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_RETAINED_REPORTS: u32 = 4096;
const PRUNE_LIMIT: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReport {
    #[serde(with = "ReportJson")]
    pub report: ReportEnvelope,
    pub report_id: String,
    pub signature_scheme: String,
    pub signature: String,
}

// Preserve Orbis signing bytes while exposing service terminology in native JSON.
#[derive(Serialize, Deserialize)]
#[serde(remote = "ReportEnvelope", deny_unknown_fields)]
struct ReportJson {
    domain: String,
    report_type: String,
    #[serde(rename = "deployment")]
    chain_id: String,
    ring_id: String,
    ring_pk: String,
    ring_state_sha256: String,
    reporter_node_key: String,
    accused_node_key: String,
    accused_peer_id: String,
    observed_at: u64,
    expires_at: u64,
    payload: Vec<u8>,
    session_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDemerits {
    pub points: u64,
    pub window_started_at: u64,
    pub revision: Timestamp,
}
impl NodeDemerits {
    pub const fn effective_points(&self, now: u64, interval: u64) -> u64 {
        if now.saturating_sub(self.window_started_at) >= interval {
            0
        } else {
            self.points
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportOutcome {
    pub report_id: String,
    pub ring_id: String,
    pub accused_node_key: String,
    pub demerits: NodeDemerits,
    /// A replacement announcement; the serving committee changes only after finalization.
    pub replacement: Option<String>,
}

pub fn demerits_key(ring_id: &str, node_key: &str) -> Result<Vec<u8>> {
    ring_key(ring_id)?;
    super::super::nodes::node_key(node_key).map_err(invalid)?;
    Ok(format!("orbis/demerits/v1/{ring_id}/{node_key}").into_bytes())
}

impl RingRecord {
    /// Hash the same report snapshot consumed by existing Orbis signers.
    pub fn report_state_hash(&self) -> Result<String> {
        self.validate(&self.id)?;
        let RingState::Active { public_key } = &self.state else {
            return Err(invalid("ring is not active"));
        };
        let s = self.current_settings();
        let mut out = Vec::new();
        write_string(&mut out, public_key);
        write_string_vec(&mut out, &s.peer_node_keys);
        write_u32(&mut out, s.threshold);
        write_optional_string_vec(
            &mut out,
            s.pending_reshare
                .as_ref()
                .map(|p| p.peer_node_keys.as_slice()),
        );
        write_optional_u32(&mut out, s.pending_reshare.as_ref().map(|p| p.threshold));
        write_u64(&mut out, s.pss_interval);
        write_u64(&mut out, self.sequence);
        write_optional_string(&mut out, Some(&self.config.policy_id));
        write_bool(&mut out, s.trusted_auth_relay_dids.is_some());
        write_string_vec(
            &mut out,
            s.trusted_auth_relay_dids.as_deref().unwrap_or_default(),
        );
        write_u64(&mut out, s.current_version);
        write_optional_u64(&mut out, s.scheduled_upgrade.as_ref().map(|p| p.version));
        write_optional_u64(
            &mut out,
            s.scheduled_upgrade.as_ref().map(|p| p.activates_at),
        );
        write_u64(&mut out, s.reporting.node_offline_demerits);
        write_u64(&mut out, s.reporting.reset_interval_seconds);
        write_u64(&mut out, s.reporting.invalid_crypto_response_demerits);
        write_u64(&mut out, s.reporting.unauthorized_request_demerits);
        write_string_vec(&mut out, &s.reporting.backup_node_keys);
        write_u64(&mut out, s.reporting.kick_threshold);
        Ok(hex::encode(Sha256::digest(out)))
    }
}

impl VeraModule {
    pub fn node_demerits(&self, ring_id: &str, node_key: &str) -> Result<Option<NodeDemerits>> {
        self.store
            .get_ref(&demerits_key(ring_id, node_key)?)
            .map(|bytes| {
                if bytes.len() > 512 {
                    return Err(invalid("invalid demerit record length"));
                }
                let record: NodeDemerits = serde_json::from_slice(bytes).map_err(invalid)?;
                if record.window_started_at == 0
                    || record.points == 0
                    || record.revision.block_height == 0
                {
                    return Err(invalid("invalid demerit record"));
                }
                Ok(record)
            })
            .transpose()
    }

    pub fn submit_ring_report(
        &mut self,
        context: &BlockExecCtx,
        signed: &SignedReport,
    ) -> Result<ReportOutcome> {
        if serde_json::to_vec(signed).map_err(invalid)?.len() > MAX_REPORT_REQUEST_BYTES {
            return Err(invalid("report request exceeds byte limit"));
        }
        let report = &signed.report;
        let now = context.timestamp.seconds;
        report.validate_shape(now).map_err(invalid)?;
        if report.payload.is_empty()
            || report.payload.len() > MAX_REPORT_PAYLOAD_BYTES
            || report.chain_id != ring_deployment_label(context.genesis_id, context.deployment_id)
            || report.session_id.len() > 256
            || report.accused_peer_id.len() > 512
        {
            return Err(invalid("report deployment or field bounds"));
        }
        let record = self
            .threshold_ring(&report.ring_id)?
            .ok_or_else(|| invalid("ring not found"))?;
        let RingState::Active { public_key } = &record.state else {
            return Err(invalid("ring is not active"));
        };
        if record.deployment_root != context.genesis_id
            || report.ring_pk != *public_key
            || report.ring_state_sha256 != record.report_state_hash()?
        {
            return Err(invalid("report ring state is stale"));
        }
        let metadata = evidence::validate(report)?;
        let settings = record.current_settings();
        if metadata.version != settings.effective_version(report.observed_at) {
            return Err(invalid("report protocol version is not effective"));
        }
        let committee = |scope| -> Result<(&[String], u32)> {
            match scope {
                CommitteeScope::Current => Ok((&settings.peer_node_keys, settings.threshold)),
                CommitteeScope::PendingNew => settings
                    .pending_reshare
                    .as_ref()
                    .map(|p| (p.peer_node_keys.as_slice(), p.threshold))
                    .ok_or_else(|| invalid("report requires pending committee")),
            }
        };
        let (accused, _) = committee(metadata.accused)?;
        let (signers, threshold) = committee(metadata.signing)?;
        if accused.binary_search(&report.accused_node_key).is_err()
            || signers.binary_search(&report.reporter_node_key).is_err()
            || threshold < 2
            || threshold as usize
                > signers.len()
                    - usize::from(signers.binary_search(&report.accused_node_key).is_ok())
        {
            return Err(invalid(
                "report committee cannot authorize while excluding accused",
            ));
        }
        let node = self
            .threshold_node(&report.accused_node_key)?
            .ok_or_else(|| invalid("accused node not found"))?;
        if node.info.peer_id != report.accused_peer_id {
            return Err(invalid("accused endpoint changed"));
        }
        let id = report.report_id();
        if id != signed.report_id {
            return Err(invalid("report identifier mismatch"));
        }
        let session = metadata.session_id(report);
        let retention = self.report_retention(&record.id, &session, now)?;
        let scheme = match signed.signature_scheme.as_str() {
            "bls12_381_g1_pk_g2_sig_aug_v1" => ThresholdScheme::Bls12381AugV1,
            "jubjub_frost" => ThresholdScheme::JubjubFrost,
            _ => return Err(invalid("unsupported report signature scheme")),
        };
        let signature = hex::decode(&signed.signature).map_err(invalid)?;
        if hex::encode(&signature) != signed.signature {
            return Err(invalid("noncanonical report signature"));
        }
        vera_crypto::threshold::verify(
            scheme,
            &hex::decode(public_key).map_err(invalid)?,
            &report.canonical_bytes(),
            &signature,
        )
        .map_err(invalid)?;
        let amount = match report.report_type.as_str() {
            orbis_reporting::NODE_OFFLINE_REPORT_TYPE => settings.reporting.node_offline_demerits,
            orbis_reporting::INVALID_CRYPTO_RESPONSE_REPORT_TYPE => {
                settings.reporting.invalid_crypto_response_demerits
            }
            orbis_reporting::UNAUTHORIZED_REQUEST_REPORT_TYPE => {
                settings.reporting.unauthorized_request_demerits
            }
            _ => return Err(invalid("unsupported report type")),
        };
        let previous = self.node_demerits(&record.id, &report.accused_node_key)?;
        let (points, start) = match previous {
            Some(p) if now < p.window_started_at => {
                return Err(invalid("demerit window is in the future"));
            }
            Some(p) if p.effective_points(now, settings.reporting.reset_interval_seconds) > 0 => {
                (p.points, p.window_started_at)
            }
            _ => (0, now),
        };
        let demerits = NodeDemerits {
            points: points.saturating_add(amount),
            window_started_at: start,
            revision: context.timestamp.clone(),
        };
        let replacement = self.report_replacement(
            record,
            &report.accused_node_key,
            demerits.points,
            &context.timestamp,
        )?;
        let score_key = demerits_key(&report.ring_id, &report.accused_node_key)?;
        let score_bytes = serde_json::to_vec(&demerits).map_err(invalid)?;
        let expires = now
            .checked_add(REPORT_TTL_SECS)
            .ok_or_else(|| invalid("report expiry overflow"))?;
        retention.apply(&mut self.store, &session, &id, expires);
        self.store.put(&score_key, score_bytes);
        let replacement = replacement.map(|change| {
            self.store.put(&change.key, change.value);
            change.node
        });
        Ok(ReportOutcome {
            report_id: id,
            ring_id: report.ring_id.clone(),
            accused_node_key: report.accused_node_key.clone(),
            demerits,
            replacement,
        })
    }
}

#[cfg(test)]
mod tests;
