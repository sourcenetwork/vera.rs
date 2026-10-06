use super::*;
use ::jubjub::{Fr, SubgroupPoint};
use group::{Group, GroupEncoding};
use orbis_reporting::{CommitteeScope, NodeOffline};
use reports::*;
use sha2::{Digest as _, Sha512};

#[test]
fn jubjub_report_verifies_and_rejects_the_obsolete_scheme_without_mutation() {
    let (mut vera, mut acp, config) = fixture_nodes(POLICY, &[2, 3, 4]);
    let signing_key = Fr::from(7u64);
    let key = (SubgroupPoint::generator() * signing_key).to_bytes();
    let ring_pk = hex::encode(key);
    let created = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    for node in [2, 3, 4] {
        vera.apply_ring_participant_request(&context(), &confirm(&created.id, node, &ring_pk))
            .unwrap();
    }
    let record = vera.threshold_ring(&created.id).unwrap().unwrap();
    let report = ReportEnvelope {
        domain: orbis_reporting::REPORT_DOMAIN.into(),
        report_type: orbis_reporting::NODE_OFFLINE_REPORT_TYPE.into(),
        chain_id: ring_deployment_label(context().genesis_id, context().deployment_id),
        ring_id: record.id.clone(),
        ring_pk,
        ring_state_sha256: record.report_state_hash().unwrap(),
        reporter_node_key: public(&secret(2)),
        accused_node_key: public(&secret(3)),
        accused_peer_id: public(&secret(3)),
        observed_at: 100,
        expires_at: 220,
        session_id: "jubjub-report".into(),
        payload: NodeOffline {
            origin_protocol: "pss_reshare".into(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes(),
    };
    // Fixed scalar/nonce only for this fixture; all curve arithmetic uses zkcrypto.
    let nonce = Fr::from(13u64);
    let r = (SubgroupPoint::generator() * nonce).to_bytes();
    let mut challenge = Sha512::new();
    challenge.update(b"FROST-jubjub-challenge");
    challenge.update(r);
    challenge.update(key);
    challenge.update(report.canonical_bytes());
    let z = nonce + Fr::from_bytes_wide(&challenge.finalize().into()) * signing_key;
    let signed = SignedReport {
        report_id: report.report_id(),
        report,
        signature_scheme: "jubjub_frost".into(),
        signature: hex::encode([r, z.to_bytes()].concat()),
    };
    let before = vera.store().serialize();
    let mut obsolete = signed.clone();
    obsolete.signature_scheme = "decaf377_frost".into();
    assert!(
        vera.submit_ring_report(&context(), &obsolete)
            .unwrap_err()
            .to_string()
            .contains("unsupported report signature scheme")
    );
    assert_eq!(vera.store().serialize(), before);
    let mut invalid = signed.clone();
    invalid.signature = "00".repeat(64);
    assert!(vera.submit_ring_report(&context(), &invalid).is_err());
    assert_eq!(vera.store().serialize(), before);
    let outcome = vera.submit_ring_report(&context(), &signed).unwrap();
    assert_eq!(outcome.report_id, signed.report_id);
    assert_eq!(outcome.demerits.points, 1);
    assert!(outcome.replacement.is_none());
}
