use commonware_cryptography::{Signer as _, ed25519};
use serde_json::json;

use super::{PeerSetError, load_peers};

fn key(seed: u64) -> String {
    let public = ed25519::PrivateKey::from_seed(seed).public_key();
    hex::encode(commonware_codec::Encode::encode(&public))
}

fn load(document: &serde_json::Value) -> Result<super::PeerSet, PeerSetError> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("peers.json");
    std::fs::write(&path, document.to_string()).unwrap();
    load_peers(&path)
}

#[test]
fn participants_keep_their_order_and_bootstrappers_their_addresses() {
    let peers = load(&json!({
        "participants": [key(2), key(1)],
        "bootstrappers": { key(1): "127.0.0.1:3001" },
    }))
    .unwrap();

    assert_eq!(
        peers.participants,
        [2, 1].map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
    );
    assert_eq!(
        peers.bootstrappers,
        [(
            ed25519::PrivateKey::from_seed(1).public_key(),
            "127.0.0.1:3001".parse().unwrap()
        )]
    );
}

#[test]
fn a_participant_that_is_not_a_string_is_rejected() {
    for entry in [json!(7), json!(null), json!({ "key": key(2) })] {
        let error = load(&json!({
            "participants": [key(1), entry],
            "bootstrappers": {},
        }))
        .unwrap_err();
        assert!(
            matches!(&error, PeerSetError::Invalid(reason) if reason == "participant is not a string"),
            "{error}"
        );
    }
}

#[test]
fn a_repeated_participant_is_rejected() {
    let error = load(&json!({
        "participants": [key(1), key(2), key(1)],
        "bootstrappers": {},
    }))
    .unwrap_err();
    assert!(
        matches!(&error, PeerSetError::Invalid(reason) if reason.starts_with("duplicate participant")),
        "{error}"
    );
}
