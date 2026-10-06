use super::*;

macro_rules! pet_binding {
    ($s:ident, $report:ident, $domain:ident) => {{
        require(
            $s.from_node_id > 0 && !$s.attempt_id.is_empty() && $s.attempt_id.len() <= 256,
            "invalid PET evidence member or attempt",
        )?;
        let mut metadata = Binding {
            domain: &$s.domain,
            deployment: &$s.chain_id,
            ring: &$s.ring_id,
            key: &$s.ring_pk,
            state: &$s.ring_state_sha256,
            version: $s.protocol_version,
            session: &$s.attempt_id,
            signed_at: $s.signed_at,
            accused: &$s.responder_node_key,
            origin: "pet",
            accused_scope: CommitteeScope::Current,
            signing_scope: CommitteeScope::Current,
        }
        .validate($report, $domain)?;
        metadata.pet_node_id = Some($s.from_node_id);
        Ok(metadata)
    }};
}

pub(super) fn reveal(
    s: &PetBlindRevealStatement,
    response_signature: &[u8],
    report: &ReportEnvelope,
) -> Result<Metadata> {
    signature(response_signature)?;
    for field in [
        &s.commitment,
        &s.blinded_r,
        &s.blinded_diff,
        &s.challenge,
        &s.proof,
    ] {
        blob(field, 512)?;
    }
    pet_binding!(s, report, PET_BLIND_REVEAL_RESPONSE_DOMAIN)
}

pub(super) fn decrypt(
    s: &PetBlindDecryptStatement,
    response_signature: &[u8],
    report: &ReportEnvelope,
) -> Result<Metadata> {
    signature(response_signature)?;
    for field in [
        &s.aggregate_r,
        &s.aggregate_diff,
        &s.partial,
        &s.challenge,
        &s.proof,
    ] {
        blob(field, 512)?;
    }
    blob(&s.public_polynomial, 64 * 1024)?;
    pet_binding!(s, report, PET_BLIND_DECRYPT_RESPONSE_DOMAIN)
}
