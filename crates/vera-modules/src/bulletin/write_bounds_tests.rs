use super::*;
use crate::acp::AcpModule;

fn owner() -> Did {
    Did::new("did:key:owner").unwrap()
}

fn tx() -> TxExecCtx {
    TxExecCtx {
        sequence: 0,
        tx_hash: vec![],
        signer: owner().to_string(),
    }
}

fn registered(namespace: &str) -> (BulletinModule, AcpModule) {
    let mut module = BulletinModule::new();
    let mut acp = AcpModule::new();
    module
        .register_namespace(
            &mut acp,
            &BlockExecCtx::default(),
            &tx(),
            &owner(),
            namespace,
        )
        .unwrap();
    (module, acp)
}

#[test]
fn namespace_identifiers_are_bounded_in_both_spellings() {
    let longest = "n".repeat(MAX_NAMESPACE_ID_BYTES - "bulletin/".len());
    let (mut module, mut acp) = registered(&longest);
    let stored = module.query_namespace(&longest).unwrap().id;
    assert_eq!(stored.len(), MAX_NAMESPACE_ID_BYTES);
    module
        .create_post(&acp, &tx(), &owner(), &stored, b"payload", &[], "")
        .unwrap();
    let before = (module.store().serialize(), acp.store().serialize());
    for namespace in [format!("{longest}n"), format!("{stored}n")] {
        assert!(matches!(
            module.register_namespace(
                &mut acp,
                &BlockExecCtx::default(),
                &tx(),
                &owner(),
                &namespace
            ),
            Err(BulletinError::NamespaceTooLong(MAX_NAMESPACE_ID_BYTES))
        ));
        assert!(matches!(
            module.create_post(&acp, &tx(), &owner(), &namespace, b"other", &[], ""),
            Err(BulletinError::NamespaceTooLong(_))
        ));
        assert!(matches!(
            module.add_collaborator(&mut acp, &tx(), &owner(), &namespace, "did:key:writer"),
            Err(BulletinError::NamespaceTooLong(_))
        ));
        assert!(matches!(
            module.remove_collaborator(&mut acp, &tx(), &owner(), &namespace, "did:key:writer"),
            Err(BulletinError::NamespaceTooLong(_))
        ));
    }
    assert_eq!(
        (module.store().serialize(), acp.store().serialize()),
        before
    );
}

#[test]
fn post_fields_are_bounded_so_one_post_cannot_exhaust_the_read_budget() {
    let (mut module, acp) = registered("ns");
    let before = module.store().serialize();
    assert!(matches!(
        module.create_post(
            &acp,
            &tx(),
            &owner(),
            "ns",
            &vec![1; MAX_POST_PAYLOAD_BYTES + 1],
            &[],
            ""
        ),
        Err(BulletinError::PostPayloadTooLarge(_))
    ));
    assert!(matches!(
        module.create_post(
            &acp,
            &tx(),
            &owner(),
            "ns",
            b"payload",
            &vec![1; MAX_POST_PROOF_BYTES + 1],
            ""
        ),
        Err(BulletinError::PostProofTooLarge(MAX_POST_PROOF_BYTES))
    ));
    assert!(matches!(
        module.create_post(
            &acp,
            &tx(),
            &owner(),
            "ns",
            b"payload",
            &[],
            &"a".repeat(MAX_POST_ARTIFACT_BYTES + 1)
        ),
        Err(BulletinError::PostArtifactTooLarge(MAX_POST_ARTIFACT_BYTES))
    ));
    assert_eq!(module.store().serialize(), before);
    module
        .create_post(
            &acp,
            &tx(),
            &owner(),
            "ns",
            &vec![1; MAX_POST_PAYLOAD_BYTES],
            &vec![2; MAX_POST_PROOF_BYTES],
            &"a".repeat(MAX_POST_ARTIFACT_BYTES),
        )
        .unwrap();
    assert_eq!(module.query_namespace_posts("ns").unwrap().len(), 1);
    assert_eq!(module.query_posts().unwrap().len(), 1);
}
