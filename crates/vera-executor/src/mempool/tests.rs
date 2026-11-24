use alloy_primitives::{Address, Bytes, FixedBytes};

use super::*;
use crate::dispatch::VALIDATOR_REGISTRY_ADDRESS;

const CHAIN_ID: u64 = 9001;

fn test_config() -> ExecutionConfig {
    ExecutionConfig::new(CHAIN_ID)
}

fn test_bls_keypair() -> (ark_bls12_381::Fr, Vec<u8>) {
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;

    let mut rng = test_rng();
    let sk = Fr::rand(&mut rng);
    let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();
    let mut pk_bytes = Vec::with_capacity(48);
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    (sk, pk_bytes)
}

fn signed_native_tx(sk: &ark_bls12_381::Fr, pk_bytes: &[u8], nonce: u64) -> Vec<u8> {
    let mut tx = NativeTx {
        chain_id: CHAIN_ID,
        nonce,
        bls_pubkey: FixedBytes::from_slice(pk_bytes),
        target: Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
        ]),
        calldata: Bytes::new(),
        signature: FixedBytes::from([0x00; 96]),
    };
    let signing_data = tx.signing_data();
    let sig = bls::sign(sk, &signing_data).unwrap();
    tx.signature = FixedBytes::from_slice(&sig);
    tx.encode_wire()
}

#[test]
fn native_valid_tx() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let tx_bytes = signed_native_tx(&sk, &pk_bytes, 0);
    let result = validator.validate_tx(&tx_bytes).unwrap();
    assert_eq!(result.nonce, 0);
    assert!(result.sender.starts_with("did:key:"));
}

#[test]
fn native_sequential_nonces() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
    let r0 = validator.validate_tx(&tx0).unwrap();
    assert_eq!(r0.nonce, 0);

    let tx1 = signed_native_tx(&sk, &pk_bytes, 1);
    let r1 = validator.validate_tx(&tx1).unwrap();
    assert_eq!(r1.nonce, 1);
}

#[test]
fn native_nonce_replay_rejected() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
    validator.validate_tx(&tx0).unwrap();

    let tx0_replay = signed_native_tx(&sk, &pk_bytes, 0);
    let err = validator.validate_tx(&tx0_replay).unwrap_err();
    assert!(matches!(err, ExecutionError::NonceMismatch { .. }));
}

#[test]
fn native_wrong_chain_id() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let mut tx = NativeTx {
        chain_id: 999,
        nonce: 0,
        bls_pubkey: FixedBytes::from_slice(&pk_bytes),
        target: Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
        ]),
        calldata: Bytes::new(),
        signature: FixedBytes::from([0x00; 96]),
    };
    let signing_data = tx.signing_data();
    let sig = bls::sign(&sk, &signing_data).unwrap();
    tx.signature = FixedBytes::from_slice(&sig);
    let wire = tx.encode_wire();

    let err = validator.validate_tx(&wire).unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::ChainIdMismatch {
            expected: CHAIN_ID,
            got: 999,
        }
    ));
}

#[test]
fn native_invalid_bls_sig() {
    let mut validator = MempoolValidator::new(test_config());

    let tx = NativeTx {
        chain_id: CHAIN_ID,
        nonce: 0,
        bls_pubkey: FixedBytes::from([0xFF; 48]),
        target: Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
        ]),
        calldata: Bytes::new(),
        signature: FixedBytes::from([0xBB; 96]),
    };
    let wire = tx.encode_wire();

    let err = validator.validate_tx(&wire).unwrap_err();
    assert!(matches!(err, ExecutionError::BlsVerification(_)));
}

#[test]
fn native_garbage_bytes() {
    let mut validator = MempoolValidator::new(test_config());

    let err = validator.validate_tx(&[0x45, 0xFF, 0xFF]).unwrap_err();
    assert!(matches!(err, ExecutionError::TxDecode(_)));
}

#[test]
fn native_unknown_target_rejected() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let bad_target = Address::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
    ]);

    let mut tx = NativeTx {
        chain_id: CHAIN_ID,
        nonce: 0,
        bls_pubkey: FixedBytes::from_slice(&pk_bytes),
        target: bad_target,
        calldata: Bytes::new(),
        signature: FixedBytes::from([0x00; 96]),
    };
    let signing_data = tx.signing_data();
    let sig = bls::sign(&sk, &signing_data).unwrap();
    tx.signature = FixedBytes::from_slice(&sig);
    let wire = tx.encode_wire();

    let err = validator.validate_tx(&wire).unwrap_err();
    assert!(matches!(err, ExecutionError::UnknownNativeTarget(_)));
}

#[test]
fn native_membership_admission_and_recheck() {
    let (key, public) = test_bls_keypair();
    let mut request = NativeTx::decode_wire(&signed_native_tx(&key, &public, 0)).unwrap();
    request.target = VALIDATOR_REGISTRY_ADDRESS;
    request.signature = FixedBytes::from_slice(&bls::sign(&key, &request.signing_data()).unwrap());
    let wire = request.encode_wire();
    let mut validator = MempoolValidator::new(test_config());
    let validated = MempoolValidator::pre_validate_native(CHAIN_ID, &wire).unwrap();
    validator.admit_native(&validated).unwrap();
    validator.reset(NativeNonceStore::default());
    validator.recheck_pending_tx(&wire).unwrap();
    let mut direct = MempoolValidator::new(test_config());
    direct.validate_tx(&wire).unwrap();
    assert!(direct.validate_tx(&wire).is_err());
}

#[test]
fn native_recheck_preserves_deployment_target_key_and_nonce_checks() {
    let (key, public) = test_bls_keypair();
    let wire = signed_native_tx(&key, &public, 0);
    let original = NativeTx::decode_wire(&wire).unwrap();
    let mut validator = MempoolValidator::new(test_config());
    validator.validate_tx(&wire).unwrap();
    validator.reset(NativeNonceStore::default());

    let mut wrong_deployment = original.clone();
    wrong_deployment.chain_id += 1;
    assert!(matches!(
        validator.recheck_pending_tx(&wrong_deployment.encode_wire()),
        Err(ExecutionError::ChainIdMismatch { .. })
    ));
    let mut wrong_target = original.clone();
    wrong_target.target = Address::ZERO;
    assert!(matches!(
        validator.recheck_pending_tx(&wrong_target.encode_wire()),
        Err(ExecutionError::UnknownNativeTarget(_))
    ));
    let mut wrong_key = original;
    wrong_key.bls_pubkey = FixedBytes::ZERO;
    assert!(matches!(
        validator.recheck_pending_tx(&wrong_key.encode_wire()),
        Err(ExecutionError::BlsVerification(_))
    ));

    validator.recheck_pending_tx(&wire).unwrap();
    assert!(matches!(
        validator.recheck_pending_tx(&wire),
        Err(ExecutionError::NonceMismatch {
            expected: 1,
            got: 0,
            ..
        })
    ));
    let next = signed_native_tx(&key, &public, 1);
    assert_eq!(validator.validate_tx(&next).unwrap().nonce, 1);
}

#[test]
fn empty_tx_rejected() {
    let mut validator = MempoolValidator::new(test_config());

    let err = validator.validate_tx(&[]).unwrap_err();
    assert!(matches!(err, ExecutionError::TxDecode(_)));
}

#[test]
fn reset_clears_nonce_state() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
    validator.validate_tx(&tx0).unwrap();

    // After reset with empty nonces, nonce 0 should be accepted again.
    validator.reset(NativeNonceStore::default());

    let tx0_again = signed_native_tx(&sk, &pk_bytes, 0);
    let result = validator.validate_tx(&tx0_again).unwrap();
    assert_eq!(result.nonce, 0);
}

#[test]
fn reset_preserves_finalized_nonces() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
    validator.validate_tx(&tx0).unwrap();

    // Simulate finalization: pass the committed nonce store.
    let committed_nonces = validator.native_nonces.clone();
    validator.reset(committed_nonces);

    // Nonce 0 should now be rejected (already finalized).
    let tx0_replay = signed_native_tx(&sk, &pk_bytes, 0);
    let err = validator.validate_tx(&tx0_replay).unwrap_err();
    assert!(matches!(err, ExecutionError::NonceMismatch { .. }));

    // Nonce 1 should be accepted.
    let tx1 = signed_native_tx(&sk, &pk_bytes, 1);
    let result = validator.validate_tx(&tx1).unwrap();
    assert_eq!(result.nonce, 1);
}

#[test]
fn reset_recheck_preserves_pending_native_nonce_reservations() {
    let (key, public) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());
    let first = signed_native_tx(&key, &public, 0);
    validator.validate_tx(&first).unwrap();
    let finalized_nonces = validator.native_nonces.clone();
    let pending = signed_native_tx(&key, &public, 1);
    validator.validate_tx(&pending).unwrap();

    // The first request finalized; the second remains in the pending pool.
    validator.reset(finalized_nonces);
    assert!(matches!(
        validator.recheck_pending_tx(&first),
        Err(ExecutionError::NonceMismatch {
            expected: 1,
            got: 0,
            ..
        })
    ));
    validator.recheck_pending_tx(&pending).unwrap();
    let next = signed_native_tx(&key, &public, 2);
    assert_eq!(validator.validate_tx(&next).unwrap().nonce, 2);

    let mut conflicting = NativeTx::decode_wire(&pending).unwrap();
    conflicting.calldata = Bytes::from_static(b"different request");
    conflicting.signature =
        FixedBytes::from_slice(&bls::sign(&key, &conflicting.signing_data()).unwrap());
    assert!(matches!(
        validator.validate_tx(&conflicting.encode_wire()),
        Err(ExecutionError::NonceMismatch {
            expected: 3,
            got: 1,
            ..
        })
    ));
    let following = signed_native_tx(&key, &public, 3);
    assert_eq!(validator.validate_tx(&following).unwrap().nonce, 3);
}

#[test]
fn rejected_native_request_admits_after_peer_catches_up() {
    let (key, public) = test_bls_keypair();
    let predecessor = signed_native_tx(&key, &public, 0);
    let predecessor = MempoolValidator::pre_validate_native(CHAIN_ID, &predecessor).unwrap();
    let request = signed_native_tx(&key, &public, 1);
    let request = MempoolValidator::pre_validate_native(CHAIN_ID, &request).unwrap();
    let mut source = MempoolValidator::new(test_config());
    source.admit_native(&predecessor).unwrap();
    let finalized_nonces = source.native_nonces.clone();
    source.reset(finalized_nonces.clone());
    source.admit_native(&request).unwrap();

    let mut peer = MempoolValidator::new(test_config());
    assert!(matches!(
        peer.admit_native(&request),
        Err(ExecutionError::NonceMismatch {
            expected: 0,
            got: 1,
            ..
        })
    ));
    peer.admit_native(&predecessor).unwrap();
    peer.reset(finalized_nonces);
    assert_eq!(peer.admit_native(&request).unwrap().nonce, 1);
    assert!(matches!(
        peer.admit_native(&request),
        Err(ExecutionError::NonceMismatch {
            expected: 2,
            got: 1,
            ..
        })
    ));
}

#[test]
fn format_detection_native() {
    let (sk, pk_bytes) = test_bls_keypair();
    let mut validator = MempoolValidator::new(test_config());

    let tx = signed_native_tx(&sk, &pk_bytes, 0);
    assert_eq!(tx[0], 0x45);
    validator.validate_tx(&tx).unwrap();
}

#[test]
fn a_request_that_is_not_native_is_rejected() {
    let mut validator = MempoolValidator::new(test_config());
    for bytes in [&[0x02, 0xFF][..], &[0xF8, 0x01]] {
        assert!(matches!(
            validator.validate_tx(bytes),
            Err(ExecutionError::TxDecode(_))
        ));
        assert!(matches!(
            validator.recheck_pending_tx(bytes),
            Err(ExecutionError::TxDecode(_))
        ));
    }
}
