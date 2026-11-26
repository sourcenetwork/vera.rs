//! Membership commands, their bounds and consensus-key address updates.

use alloy_primitives::Address;
use ed25519_dalek::Signer as _;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use vera_identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        types::{Object, PolicyCmd, PolicyMarshalingType},
    },
    kv_store::ModuleKvStore as _,
    validator_registry::{
        MAX_P2P_ADDRESS_LEN, MembershipLimits, address_update_digest, error::ValidatorRegistryError,
    },
    vera::{VeraModule, administration::*},
};

const GENESIS: [u8; 32] = [7; 32];
const LIMITS: MembershipLimits = MembershipLimits {
    members: 4,
    active: 3,
};

fn consensus(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn key(seed: u8) -> [u8; 32] {
    consensus(seed).verifying_key().to_bytes()
}

fn manager() -> Did {
    "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        .parse()
        .unwrap()
}

/// Modules whose membership policy lets [`manager`] manage the registry.
fn managed() -> (VeraModule, AcpModule) {
    let did = manager();
    let mut acp = AcpModule::new();
    let policy = acp
        .create_policy(
            &did,
            "name: membership\nresources:\n  - name: registry\n    relations:\n      - name: admin\n    permissions:\n      - name: manage\n        expr: admin\n",
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string();
    acp.direct_policy_cmd(
        &did,
        &policy,
        PolicyCmd::RegisterObject(Object {
            resource: "registry".into(),
            id: "registry".into(),
        }),
    )
    .unwrap();
    acp.direct_policy_cmd(
        &did,
        &policy,
        PolicyCmd::SetRelationship(
            vera_modules::acp::relationship_values::actor_relationship(
                "registry", "registry", "admin", &did,
            )
            .unwrap(),
        ),
    )
    .unwrap();

    let operator = SigningKey::from_bytes(&[9; 32].into()).unwrap();
    let mut vera = VeraModule::new();
    vera.initialize_administration(OperatorPolicy {
        threshold: 1,
        keys: vec![hex::encode(operator.verifying_key().to_sec1_bytes())],
    })
    .unwrap();
    let request = AdministrativeRequest {
        genesis_id: GENESIS,
        sequence: 0,
        expires_at: 100,
        command: AdministrativeCommand::InitializeMembershipPolicy(
            hex::decode(&policy).unwrap().try_into().unwrap(),
        ),
    };
    let signature: Signature = operator
        .sign_prehash(&request.signing_digest().unwrap())
        .unwrap();
    vera.apply_administrative_request(
        &mut acp,
        GENESIS,
        100,
        &SignedAdministrativeRequest {
            request,
            approvals: vec![OperatorApproval {
                signer: 0,
                signature: hex::encode(signature.to_bytes()),
                webauthn: None,
            }],
        },
    )
    .unwrap();
    (vera, acp)
}

const fn address(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

fn add(vera: &mut VeraModule, acp: &AcpModule, member: u8) -> Result<(), ValidatorRegistryError> {
    vera.add_validator(
        acp,
        &manager(),
        LIMITS,
        address(member),
        key(member),
        "127.0.0.1:3000",
    )
}

#[test]
fn members_are_added_once_within_the_registry_and_committee_bounds() {
    let (mut vera, acp) = managed();
    add(&mut vera, &acp, 1).unwrap();
    assert!(matches!(
        add(&mut vera, &acp, 1),
        Err(ValidatorRegistryError::ValidatorAlreadyExists(_))
    ));
    assert!(matches!(
        vera.add_validator(&acp, &manager(), LIMITS, address(2), key(1), "127.0.0.1:1"),
        Err(ValidatorRegistryError::DuplicateConsensusKey)
    ));
    assert!(matches!(
        vera.add_validator(
            &acp,
            &manager(),
            LIMITS,
            Address::ZERO,
            key(2),
            "127.0.0.1:1"
        ),
        Err(ValidatorRegistryError::InvalidAddress(_))
    ));
    assert!(matches!(
        vera.add_validator(&acp, &manager(), LIMITS, address(2), [0; 32], "127.0.0.1:1"),
        Err(ValidatorRegistryError::InvalidPublicKey)
    ));
    for invalid in ["", "127.0.0.1", "host:1"] {
        assert!(matches!(
            vera.add_validator(&acp, &manager(), LIMITS, address(2), key(2), invalid),
            Err(ValidatorRegistryError::InvalidP2PAddress(_))
        ));
    }
    add(&mut vera, &acp, 2).unwrap();
    add(&mut vera, &acp, 3).unwrap();
    assert!(matches!(
        add(&mut vera, &acp, 4),
        Err(ValidatorRegistryError::EpochCapacity(3))
    ));
    vera.set_validator_status(&acp, &manager(), LIMITS, address(3), false)
        .unwrap();
    add(&mut vera, &acp, 4).unwrap();
    assert!(matches!(
        vera.set_validator_status(&acp, &manager(), LIMITS, address(3), true),
        Err(ValidatorRegistryError::EpochCapacity(3))
    ));
    vera.set_validator_status(&acp, &manager(), LIMITS, address(4), false)
        .unwrap();
    assert!(matches!(
        add(&mut vera, &acp, 5),
        Err(ValidatorRegistryError::MembershipLimit(4))
    ));

    let members = vera.registry_members().unwrap();
    assert_eq!(
        members.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
        [1, 2, 3, 4].map(address)
    );
    let mut expected = vec![key(1), key(2)];
    expected.sort_unstable();
    assert_eq!(vera.active_consensus_keys().unwrap(), expected);
}

#[test]
fn an_inactive_members_consensus_key_cannot_be_registered_again() {
    let (mut vera, acp) = managed();
    add(&mut vera, &acp, 1).unwrap();
    add(&mut vera, &acp, 2).unwrap();
    vera.set_validator_status(&acp, &manager(), LIMITS, address(2), false)
        .unwrap();
    assert!(matches!(
        vera.add_validator(&acp, &manager(), LIMITS, address(3), key(2), "127.0.0.1:1"),
        Err(ValidatorRegistryError::DuplicateConsensusKey)
    ));
}

#[test]
fn the_last_active_member_stays() {
    let (mut vera, acp) = managed();
    add(&mut vera, &acp, 1).unwrap();
    add(&mut vera, &acp, 2).unwrap();
    vera.set_validator_status(&acp, &manager(), LIMITS, address(2), false)
        .unwrap();
    assert!(matches!(
        vera.remove_validator(&acp, &manager(), address(1)),
        Err(ValidatorRegistryError::EmptyCommittee)
    ));
    assert!(matches!(
        vera.set_validator_status(&acp, &manager(), LIMITS, address(1), false),
        Err(ValidatorRegistryError::EmptyCommittee)
    ));
    vera.remove_validator(&acp, &manager(), address(2)).unwrap();
    assert!(matches!(
        vera.remove_validator(&acp, &manager(), address(2)),
        Err(ValidatorRegistryError::ValidatorNotFound(_))
    ));
    assert_eq!(vera.registry_members().unwrap().len(), 1);
}

#[test]
fn commands_need_the_membership_policys_manage_permission() {
    let (mut vera, acp) = managed();
    let stranger: Did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        .parse()
        .unwrap();
    assert!(matches!(
        vera.add_validator(&acp, &stranger, LIMITS, address(1), key(1), "127.0.0.1:1"),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));
    add(&mut vera, &acp, 1).unwrap();
    add(&mut vera, &acp, 2).unwrap();
    assert!(matches!(
        vera.remove_validator(&acp, &stranger, address(1)),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));
    assert!(matches!(
        vera.set_validator_status(&acp, &stranger, LIMITS, address(1), false),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));

    let mut unconfigured = VeraModule::new();
    assert!(matches!(
        unconfigured.add_validator(
            &AcpModule::new(),
            &manager(),
            LIMITS,
            address(1),
            key(1),
            "127.0.0.1:1"
        ),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));
}

fn signed_under(
    signer: u8,
    genesis: &[u8; 32],
    member: u8,
    admission: u64,
    sequence: u64,
    to: &str,
) -> Vec<u8> {
    consensus(signer)
        .sign(&address_update_digest(
            genesis,
            address(member),
            admission,
            sequence,
            to,
        ))
        .to_bytes()
        .to_vec()
}

/// A signature for a member admitted first, as member 1 is in these tests.
fn signed(signer: u8, genesis: &[u8; 32], member: u8, sequence: u64, to: &str) -> Vec<u8> {
    signed_under(signer, genesis, member, 0, sequence, to)
}

#[test]
fn a_consensus_key_moves_its_own_member_once_per_signature() {
    let (mut vera, acp) = managed();
    add(&mut vera, &acp, 1).unwrap();
    add(&mut vera, &acp, 2).unwrap();
    let to = "[2001:db8::1]:30300";
    let signature = signed(1, &GENESIS, 1, 0, to);

    for (member, sequence, signature) in [
        // Signed for another deployment, replayed on another member's record,
        // signed under a later sequence, and signed by another member's key.
        (1, 0, signed(1, &[8; 32], 1, 0, to)),
        (2, 0, signature.clone()),
        (1, 1, signed(1, &GENESIS, 1, 1, to)),
        (1, 0, signed(2, &GENESIS, 1, 0, to)),
    ] {
        assert!(matches!(
            vera.update_p2p_address(&GENESIS, address(member), to, sequence, &signature),
            Err(ValidatorRegistryError::Unauthorized(_))
        ));
    }
    assert!(matches!(
        vera.update_p2p_address(&[0; 32], address(1), to, 0, &signature),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));
    assert!(matches!(
        vera.update_p2p_address(&GENESIS, address(9), to, 0, &signature),
        Err(ValidatorRegistryError::ValidatorNotFound(_))
    ));
    assert!(matches!(
        vera.update_p2p_address(&GENESIS, address(1), "127.0.0.1:1", 0, &signature),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));

    vera.update_p2p_address(&GENESIS, address(1), to, 0, &signature)
        .unwrap();
    let member = vera.registry_member(address(1)).unwrap().unwrap();
    assert_eq!(
        (member.p2p_address.as_str(), member.address_sequence),
        (to, 1)
    );
    assert!(matches!(
        vera.update_p2p_address(&GENESIS, address(1), to, 0, &signature),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));

    // A deactivated member still announces where it listens.
    vera.set_validator_status(&acp, &manager(), LIMITS, address(1), false)
        .unwrap();
    let next = signed(1, &GENESIS, 1, 1, "127.0.0.1:9");
    vera.update_p2p_address(&GENESIS, address(1), "127.0.0.1:9", 1, &next)
        .unwrap();
    let long = format!("[{}]:1", "1:".repeat(MAX_P2P_ADDRESS_LEN));
    assert!(matches!(
        vera.update_p2p_address(&GENESIS, address(1), &long, 2, &[0; 64]),
        Err(ValidatorRegistryError::InvalidP2PAddress(_))
    ));
}

#[test]
fn an_update_signed_before_removal_does_not_apply_after_readmission() {
    let (mut vera, acp) = managed();
    add(&mut vera, &acp, 1).unwrap();
    add(&mut vera, &acp, 2).unwrap();
    let old = signed(1, &GENESIS, 1, 0, "10.0.0.1:1");
    vera.update_p2p_address(&GENESIS, address(1), "10.0.0.1:1", 0, &old)
        .unwrap();
    vera.remove_validator(&acp, &manager(), address(1)).unwrap();
    add(&mut vera, &acp, 1).unwrap();
    let readmitted = vera.registry_member(address(1)).unwrap().unwrap();
    assert_eq!(
        (
            readmitted.p2p_address.as_str(),
            readmitted.admission,
            readmitted.address_sequence
        ),
        ("127.0.0.1:3000", 2, 0)
    );

    assert!(matches!(
        vera.update_p2p_address(&GENESIS, address(1), "10.0.0.1:1", 0, &old),
        Err(ValidatorRegistryError::Unauthorized(_))
    ));
    assert_eq!(
        vera.registry_member(address(1)).unwrap().unwrap(),
        readmitted
    );

    let fresh = signed_under(1, &GENESIS, 1, 2, 0, "10.0.0.1:1");
    vera.update_p2p_address(&GENESIS, address(1), "10.0.0.1:1", 0, &fresh)
        .unwrap();
    let moved = vera.registry_member(address(1)).unwrap().unwrap();
    assert_eq!(
        (moved.p2p_address.as_str(), moved.address_sequence),
        ("10.0.0.1:1", 1)
    );
}

#[test]
fn every_admission_takes_a_new_number() {
    let (mut vera, acp) = managed();
    vera.seed_validators([
        (address(3), key(3), "127.0.0.1:1".to_owned()),
        (address(1), key(1), "127.0.0.1:1".to_owned()),
    ])
    .unwrap();
    add(&mut vera, &acp, 2).unwrap();
    vera.remove_validator(&acp, &manager(), address(2)).unwrap();
    add(&mut vera, &acp, 2).unwrap();
    let admissions: Vec<_> = vera
        .registry_members()
        .unwrap()
        .into_iter()
        .map(|(member, record)| (member, record.admission))
        .collect();
    assert_eq!(
        admissions,
        [(address(1), 1), (address(2), 3), (address(3), 0)]
    );
}

#[test]
fn genesis_members_are_validated_and_seeded_once() {
    let mut vera = VeraModule::new();
    let seed = |byte: u8| (address(byte), key(byte), "127.0.0.1:1".to_owned());
    assert!(matches!(
        VeraModule::new().seed_validators([seed(1), seed(1)]),
        Err(ValidatorRegistryError::ValidatorAlreadyExists(_))
    ));
    assert!(matches!(
        VeraModule::new().seed_validators([seed(1), (address(2), key(1), "127.0.0.1:1".into())]),
        Err(ValidatorRegistryError::DuplicateConsensusKey)
    ));
    vera.seed_validators([seed(2), seed(1)]).unwrap();
    assert_eq!(vera.registry_members().unwrap().len(), 2);
    assert!(vera.seed_validators([seed(3)]).is_err());
}

#[test]
fn a_record_that_does_not_read_back_is_the_nodes_fault() {
    let (mut vera, acp) = managed();
    add(&mut vera, &acp, 1).unwrap();
    let mut store = vera.store().clone();
    let (stored, _) = store
        .prefix_scan(b"registry/member/")
        .into_iter()
        .next()
        .unwrap();
    store.put(&stored, vec![0xff]);
    let vera = VeraModule::from_store(store);
    assert!(matches!(
        vera.registry_members(),
        Err(ValidatorRegistryError::Corrupt(_))
    ));
    assert!(matches!(
        vera.active_consensus_keys(),
        Err(ValidatorRegistryError::Corrupt(_))
    ));
}
