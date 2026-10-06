mod pet;

use super::*;
use orbis_reporting::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Metadata {
    pub origin: String,
    pub version: u64,
    pub accused: CommitteeScope,
    pub signing: CommitteeScope,
    pub attempt: Option<[u8; 32]>,
    pub pet_node_id: Option<u32>,
}
impl Metadata {
    pub(super) fn session_id(&self, report: &ReportEnvelope) -> String {
        let mut bytes = Vec::new();
        for value in [
            "orbis-mpc-fault-report-session",
            &report.chain_id,
            &report.ring_id,
            &report.report_type,
            &self.origin,
            &report.accused_node_key,
            &report.session_id,
        ] {
            write_string(&mut bytes, value);
        }
        write_bytes(
            &mut bytes,
            self.attempt.as_ref().map_or(&[], |id| id.as_slice()),
        );
        hex::encode(Sha256::digest(bytes))
    }
}

struct Binding<'a> {
    domain: &'a str,
    deployment: &'a str,
    ring: &'a str,
    key: &'a str,
    state: &'a str,
    version: u64,
    session: &'a str,
    signed_at: u64,
    accused: &'a str,
    origin: &'a str,
    accused_scope: CommitteeScope,
    signing_scope: CommitteeScope,
}
macro_rules! binding {
    ($s:ident, $key:ident, $accused:expr, $signing:expr) => {
        Binding {
            domain: &$s.domain,
            deployment: &$s.chain_id,
            ring: &$s.ring_id,
            key: &$s.ring_pk,
            state: &$s.ring_state_sha256,
            version: $s.protocol_version,
            session: &$s.request_id,
            signed_at: $s.signed_at,
            accused: &$s.$key,
            origin: &$s.origin_protocol,
            accused_scope: $accused,
            signing_scope: $signing,
        }
    };
}
impl Binding<'_> {
    fn validate(&self, report: &ReportEnvelope, domain: &str) -> Result<Metadata> {
        require(
            self.domain == domain
                && self.deployment == report.chain_id
                && self.ring == report.ring_id
                && self.key == report.ring_pk
                && self.state == report.ring_state_sha256
                && self.session == report.session_id
                && self.accused == report.accused_node_key
                && self.signed_at.checked_sub(CHAIN_BLOCK_GRACE_SECS) == Some(report.observed_at),
            "evidence binding does not match report",
        )?;
        Ok(Metadata {
            origin: self.origin.into(),
            version: self.version,
            accused: self.accused_scope,
            signing: self.signing_scope,
            attempt: None,
            pet_node_id: None,
        })
    }
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn blob(bytes: &[u8], max: usize) -> Result<()> {
    require(
        !bytes.is_empty() && bytes.len() <= max,
        "evidence field length out of bounds",
    )
}
fn signature(bytes: &[u8]) -> Result<()> {
    require(bytes.len() == 64, "evidence signature must be 64 bytes")
}
fn optional(bytes: &Option<Vec<u8>>, max: usize) -> Result<()> {
    require(
        bytes.as_ref().is_none_or(|b| b.len() <= max),
        "optional evidence field exceeds limit",
    )
}
fn current(metadata: &Metadata) -> Result<()> {
    require(
        metadata.accused == CommitteeScope::Current && metadata.signing == CommitteeScope::Current,
        "evidence requires current committee scopes",
    )
}
fn dkg(metadata: &Metadata, leader: bool) -> Result<()> {
    require(
        matches!(metadata.origin.as_str(), "pss_refresh" | "pss_reshare")
            && metadata.signing == CommitteeScope::Current
            && (metadata.origin != "pss_refresh" || metadata.accused == CommitteeScope::Current)
            && (!leader
                || metadata.origin != "pss_reshare"
                || metadata.accused == CommitteeScope::PendingNew),
        "invalid DKG evidence protocol or committee scope",
    )
}
fn phase(value: &str) -> Result<()> {
    require(
        matches!(
            value,
            "commitments" | "commitment_audit" | "refresh_health_check" | "reshare_participant_set"
        ),
        "invalid public DKG phase",
    )
}
fn endpoint(value: &EndpointSignedContribution, report: &ReportEnvelope) -> Result<()> {
    signature(&value.signature)?;
    blob(&value.data, 1024 * 1024)?;
    require(
        value.origin.len() == 32
            && hex::encode(&value.origin)
                == report
                    .accused_peer_id
                    .split('@')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
        "evidence endpoint does not match accused",
    )
}
fn artifact(value: &ControlMessageArtifact) -> Result<()> {
    signature(&value.signature)?;
    blob(&value.data, 1024 * 1024)
}
fn commitment(
    s: &DkgCommitmentStatement,
    report: &ReportEnvelope,
    signed_at: u64,
) -> Result<Metadata> {
    require(
        s.from_node_id > 0 && !s.crypto_backend.is_empty() && s.signed_at <= signed_at,
        "invalid DKG commitment metadata",
    )?;
    blob(&s.commitment, 1024 * 1024)?;
    let mut binding = binding!(
        s,
        responder_node_key,
        s.accused_committee_scope,
        s.signing_committee_scope
    );
    binding.signed_at = signed_at;
    let mut meta = binding.validate(report, DKG_COMMITMENT_DOMAIN)?;
    current(&meta)?;
    dkg(&meta, false)?;
    meta.attempt = Some(s.attempt_id);
    Ok(meta)
}

pub(super) fn validate(report: &ReportEnvelope) -> Result<Metadata> {
    use CommitteeScope::Current;
    match report.report_type.as_str() {
        NODE_OFFLINE_REPORT_TYPE => {
            let p = NodeOffline::from_canonical_bytes(&report.payload).map_err(invalid)?;
            require(
                matches!(
                    p.origin_protocol.as_str(),
                    "pre" | "sign" | "pet" | "pss_refresh" | "pss_reshare"
                ),
                "invalid offline origin",
            )?;
            let metadata = Metadata {
                origin: p.origin_protocol,
                version: p.origin_protocol_version,
                accused: p.accused_committee_scope,
                signing: p.signing_committee_scope,
                attempt: None,
                pet_node_id: None,
            };
            if metadata.origin == "pet" {
                current(&metadata)?;
            }
            Ok(metadata)
        }
        UNAUTHORIZED_REQUEST_REPORT_TYPE => {
            let p = UnauthorizedRequestPayload::from_canonical_bytes(&report.payload)
                .map_err(invalid)?;
            signature(&p.relay_signature)?;
            require(
                !p.checked_at_anchor.is_empty(),
                "missing authorization anchor",
            )?;
            let s = p.statement;
            require(
                matches!(s.origin_protocol.as_str(), "pre" | "sign")
                    && s.from_node_id > 0
                    && !s.actor_id.is_empty()
                    && !s.object_id.is_empty()
                    && s.valid_window_start.is_some() == s.valid_window_end.is_some()
                    && s.signed_at.abs_diff(s.user_signed_at) <= 30,
                "invalid relay evidence metadata",
            )?;
            let meta = binding!(
                s,
                relayer_node_key,
                s.accused_committee_scope,
                s.signing_committee_scope
            )
            .validate(report, RELAY_REQUEST_DOMAIN)?;
            current(&meta)?;
            Ok(meta)
        }
        INVALID_CRYPTO_RESPONSE_REPORT_TYPE => {
            let evidence =
                InvalidCryptoResponse::from_canonical_bytes(&report.payload).map_err(invalid)?;
            let attempt = evidence.attempt_id();
            let mut meta = match &evidence {
                InvalidCryptoResponse::Pre {
                    statement: s,
                    response_signature,
                } => {
                    signature(response_signature)?;
                    require(
                        s.origin_protocol == "pre"
                            && !s.object_id.is_empty()
                            && !s.crypto_backend.is_empty(),
                        "invalid PRE evidence metadata",
                    )?;
                    for field in [&s.rdr_pk, &s.share, &s.challenge, &s.proof] {
                        blob(field, 512)?;
                    }
                    optional(&s.derivation, 4096)?;
                    binding!(s, responder_node_key, Current, Current)
                        .validate(report, PRE_REENCRYPT_RESPONSE_DOMAIN)?
                }
                InvalidCryptoResponse::Sign {
                    statement: s,
                    response_signature,
                } => {
                    signature(response_signature)?;
                    require(
                        matches!(
                            s.origin_protocol.as_str(),
                            "sign" | "pss_refresh" | "pss_reshare" | "report"
                        ) && !s.crypto_backend.is_empty(),
                        "invalid signing evidence metadata",
                    )?;
                    blob(&s.message, 1024 * 1024)?;
                    require(
                        s.signing_commitments.len() <= 1024 * 1024,
                        "signing commitments exceed limit",
                    )?;
                    blob(&s.sig_share, 4096)?;
                    optional(&s.derivation, 4096)?;
                    optional(&s.metadata, 4096)?;
                    binding!(
                        s,
                        responder_node_key,
                        s.accused_committee_scope,
                        s.signing_committee_scope
                    )
                    .validate(report, SIGN_RESPONSE_DOMAIN)?
                }
                InvalidCryptoResponse::PetBlindReveal {
                    statement,
                    response_signature,
                } => pet::reveal(statement, response_signature, report)?,
                InvalidCryptoResponse::PetBlindDecrypt {
                    statement,
                    response_signature,
                } => pet::decrypt(statement, response_signature, report)?,
                InvalidCryptoResponse::DkgShare {
                    statement: s,
                    response_signature,
                } => {
                    signature(response_signature)?;
                    signature(&s.commitment_signature)?;
                    require(
                        s.from_node_id > 0
                            && s.to_node_id > 0
                            && !s.receiver_node_key.is_empty()
                            && !s.crypto_backend.is_empty()
                            && s.commitment_statement.from_node_id == s.from_node_id
                            && s.commitment_statement.crypto_backend == s.crypto_backend,
                        "invalid DKG share metadata",
                    )?;
                    blob(&s.share_value, 4096)?;
                    let mut meta = binding!(
                        s,
                        responder_node_key,
                        s.accused_committee_scope,
                        s.signing_committee_scope
                    )
                    .validate(report, DKG_SHARE_DOMAIN)?;
                    meta.attempt = attempt;
                    require(
                        meta == commitment(&s.commitment_statement, report, s.signed_at)?,
                        "nested commitment differs from share binding",
                    )?;
                    meta
                }
                InvalidCryptoResponse::DkgInvalidRefreshCommitment {
                    statement: s,
                    response_signature,
                } => {
                    signature(response_signature)?;
                    let meta = commitment(s, report, s.signed_at)?;
                    require(
                        meta.origin == "pss_refresh",
                        "invalid-refresh evidence requires refresh origin",
                    )?;
                    meta
                }
                InvalidCryptoResponse::DkgEquivocation {
                    commitment_a: a,
                    commitment_b: b,
                } => {
                    signature(&a.signature)?;
                    signature(&b.signature)?;
                    let time = a.statement.signed_at.max(b.statement.signed_at);
                    let meta = commitment(&a.statement, report, time)?;
                    require(
                        meta == commitment(&b.statement, report, time)?
                            && a.statement.crypto_backend == b.statement.crypto_backend
                            && a.statement.proves_equivocation_with(&b.statement),
                        "commitments do not prove equivocation",
                    )?;
                    meta
                }
                InvalidCryptoResponse::DkgPublicOriginFault { statement: s } => {
                    let meta = binding!(
                        s,
                        responder_node_key,
                        s.accused_committee_scope,
                        s.signing_committee_scope
                    )
                    .validate(report, DKG_PUBLIC_ORIGIN_FAULT_DOMAIN)?;
                    dkg(&meta, false)?;
                    phase(&s.phase)?;
                    endpoint(&s.contribution_a, report)?;
                    match (s.fault_kind, &s.contribution_b) {
                        (DkgPublicOriginFaultKind::InvalidPayload, None) => (),
                        (DkgPublicOriginFaultKind::OriginEquivocation, Some(b))
                            if s.phase != "commitments" =>
                        {
                            endpoint(b, report)?
                        }
                        _ => return Err(invalid("invalid public-origin evidence pair")),
                    }
                    meta
                }
                InvalidCryptoResponse::DkgLeaderEquivocation { statement: s }
                | InvalidCryptoResponse::DkgLeaderBatchMismatch { statement: s } => {
                    let domain = if matches!(
                        evidence,
                        InvalidCryptoResponse::DkgLeaderEquivocation { .. }
                    ) {
                        DKG_LEADER_EQUIVOCATION_DOMAIN
                    } else {
                        DKG_LEADER_BATCH_MISMATCH_DOMAIN
                    };
                    let meta = binding!(
                        s,
                        responder_node_key,
                        s.accused_committee_scope,
                        s.signing_committee_scope
                    )
                    .validate(report, domain)?;
                    dkg(&meta, true)?;
                    phase(&s.phase)?;
                    endpoint(&s.delivery_a, report)?;
                    endpoint(&s.delivery_b, report)?;
                    require(
                        s.delivery_id_a != s.delivery_id_b,
                        "delivery identifiers must differ",
                    )?;
                    meta
                }
                InvalidCryptoResponse::DkgLeaderPublicFault { statement: s } => {
                    let meta = binding!(
                        s,
                        responder_node_key,
                        s.accused_committee_scope,
                        s.signing_committee_scope
                    )
                    .validate(report, DKG_LEADER_PUBLIC_FAULT_DOMAIN)?;
                    dkg(&meta, true)?;
                    phase(&s.phase)?;
                    endpoint(&s.delivery, report)?;
                    meta
                }
                InvalidCryptoResponse::DkgControlMessageFault { statement: s } => {
                    let meta = binding!(
                        s,
                        responder_node_key,
                        s.accused_committee_scope,
                        s.signing_committee_scope
                    )
                    .validate(report, DKG_CONTROL_MESSAGE_FAULT_DOMAIN)?;
                    dkg(
                        &meta,
                        s.fault_kind != DkgControlMessageFaultKind::AckEquivocation,
                    )?;
                    artifact(&s.artifact_a)?;
                    match (s.fault_kind, &s.artifact_b) {
                        (DkgControlMessageFaultKind::LeaderPrepareFault, None)
                            if s.message_kind == "prepare" => {}
                        (DkgControlMessageFaultKind::OversizedRepairPage, None)
                            if s.message_kind == "public_phase_response" => {}
                        (DkgControlMessageFaultKind::AckEquivocation, Some(b))
                            if matches!(
                                s.message_kind.as_str(),
                                "prepared" | "activated" | "begun"
                            ) =>
                        {
                            artifact(b)?
                        }
                        _ => return Err(invalid("invalid control fault artifacts")),
                    }
                    meta
                }
            };
            meta.attempt = attempt;
            Ok(meta)
        }
        _ => Err(invalid("unsupported report type")),
    }
}
