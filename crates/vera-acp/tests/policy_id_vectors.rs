//! acp's shared policy id vectors (`vectors/policy-id.json`, a byte-identical
//! copy of acp's `conformance/vectors/policy-id.json`): this engine derives
//! every policy hash and id as acp does.

use serde::Deserialize;
use vera_acp::policy_yaml::{
    build_policy, parse_policy_yaml, policy_hash, policy_id, PolicyNonce, POLICY_HASH_DOMAIN,
    POLICY_ID_DOMAIN,
};

#[derive(Deserialize)]
struct Vectors {
    format: u32,
    hash_domain: String,
    id_domain: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    policy: String,
    nonce: String,
    creator: String,
    policy_hash: String,
    id: String,
}

const VECTORS: &str = include_str!("vectors/policy-id.json");

#[test]
fn every_vector_is_reproduced() {
    let file: Vectors = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(file.format, 1);
    assert_eq!(file.hash_domain.as_bytes(), POLICY_HASH_DOMAIN);
    assert_eq!(file.id_domain.as_bytes(), POLICY_ID_DOMAIN);
    assert!(!file.vectors.is_empty());
    for vector in file.vectors {
        let parsed = parse_policy_yaml(&vector.policy)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        let hash = policy_hash(&parsed).unwrap();
        assert_eq!(hash.to_string(), vector.policy_hash, "{}", vector.name);
        let nonce: PolicyNonce = vector.nonce.parse().unwrap();
        let id = policy_id(&hash, &nonce, &vector.creator);
        assert_eq!(id, vector.id, "{}", vector.name);
        build_policy(&parsed, id).unwrap_or_else(|error| panic!("{}: {error}", vector.name));
    }
}

#[test]
fn untyped_relations_and_actor_relations_change_the_hash() {
    let hash = |text: &str| policy_hash(&parse_policy_yaml(text).unwrap()).unwrap();
    let typed = "name: p\nresources:\n  - name: doc\n    relations:\n      - name: reader\n        types: [actor]\n";
    let untyped = "name: p\nresources:\n  - name: doc\n    relations:\n      - name: reader\n";
    let roles = format!("{typed}actor:\n  relations:\n    - name: role\n");
    assert_ne!(hash(typed), hash(untyped));
    assert_ne!(hash(typed), hash(&roles));
}

#[test]
fn parent_registration_hash_matches_acp() {
    let policy = r#"name: agents
resources:
- name: agent
- name: session
  relations:
  - name: agent
    types: [agent]
  create:
    parent: agent
    requires: owner
"#;
    let parsed = parse_policy_yaml(policy).unwrap();
    // acp-playground compile derives this content ID from the same policy.
    assert_eq!(
        policy_hash(&parsed).unwrap().to_string(),
        "c3edc38de343983969a98e548ac7b09c98fc9c754bcb9b850860f70d9278618f"
    );
}

#[test]
fn nonces_and_hashes_are_64_hexadecimal_characters() {
    let nonce: PolicyNonce = "0A".repeat(32).parse().unwrap();
    assert_eq!(nonce.0, [10; 32]);
    assert_eq!(nonce.to_string(), "0a".repeat(32));
    assert_eq!(
        serde_json::to_string(&nonce).unwrap(),
        format!("\"{}\"", "0a".repeat(32))
    );
    for bad in [
        "",
        "0a",
        &"0g".repeat(32),
        &"+a".repeat(32),
        &"0a".repeat(33),
    ] {
        assert!(bad.parse::<PolicyNonce>().is_err(), "{bad:?}");
    }
}
