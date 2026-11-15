//! What a ring read checks, and what a participant request costs before it is authenticated.

use super::*;

#[test]
fn participant_requests_are_authenticated_before_the_ring_is_read() {
    let (mut vera, mut acp, config) = fixture(POLICY);
    let ring = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    vera.store.put(
        &ring_key(&ring.id).unwrap(),
        vec![0; MAX_RING_RECORD_BYTES + 1],
    );
    let signed = confirm(&ring.id, 2, "aa");
    let mut forged = signed.clone();
    forged.request.node_key = public(&secret(3));
    let mut malformed = signed.clone();
    malformed.request.node_key = public(&secret(2)).to_uppercase();
    for request in [forged, malformed] {
        let error = vera
            .apply_ring_participant_request(&context(), &request)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("ring record"), "{error}");
    }
    let error = vera
        .apply_ring_participant_request(&context(), &signed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("ring record exceeds byte limit"), "{error}");
}

#[test]
fn key_sets_require_the_one_compressed_spelling_and_registration_checks_the_curve() {
    let (mut vera, mut acp, config) = fixture(POLICY);
    let member = public(&secret(2));
    let uncompressed_prefix = format!("04{}", &member[2..]);
    for bad in [
        member.to_uppercase(),
        uncompressed_prefix,
        member[..64].to_owned(),
    ] {
        let mut keys = vec![bad, public(&secret(3))];
        keys.sort();
        let config = RingConfig {
            peer_node_keys: keys,
            ..config.clone()
        };
        assert!(config.validate().is_err());
    }
    let off_curve = (0u8..=255)
        .map(|x| format!("02{}", hex::encode([x; 32])))
        .find(|key| vera_crypto::secp256k1::decode_pubkey(&hex::decode(key).unwrap()).is_err())
        .unwrap();
    let mut keys = vec![off_curve, member];
    keys.sort();
    let config = RingConfig {
        peer_node_keys: keys,
        ..config
    };
    config.validate().unwrap();
    let before = (vera.store.serialize(), acp.store().serialize());
    assert!(apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).is_err());
    assert_eq!((vera.store.serialize(), acp.store().serialize()), before);
}
