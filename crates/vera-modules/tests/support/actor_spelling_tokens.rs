//! Token records, revocation and bulletin collaborators under each spelling.

use super::*;
use vera_modules::{bulletin::BulletinModule, vera::keys::hash_jws_token};

const DEFINITION: &str = "name: files\nresources:\n  - name: file\n";

#[test]
fn a_token_is_recorded_and_revoked_under_its_issuers_canonical_did() {
    let (key, stranger, worker) = (Key::new(42), Key::new(43), worker(7));
    for (written, issuer) in key.spellings().into_iter().enumerate() {
        let token = key.token(&issuer, &worker, DelegationScope::CreatePolicy);
        let hash = hash_jws_token(&token);
        let create = |acp: &mut AcpModule, vera: &mut VeraModule| {
            acp.bearer_create_policy(vera, &context(100), &worker, &token, DEFINITION, FORMAT)
        };

        let (mut acp, mut vera) = (AcpModule::new(), VeraModule::new());
        for other in stranger.dids() {
            assert!(
                vera.revoke_delegation(&context(100), &other, &token)
                    .is_err()
            );
        }
        let revoked = vera
            .revoke_delegation(&context(100), &key.dids()[(written + 1) % 4], &token)
            .unwrap();
        assert_eq!(revoked.issuer_did, key.canonical());
        assert_eq!(revoked.invalidated_by, key.canonical());
        assert!(create(&mut acp, &mut vera).is_err());

        let (mut acp, mut vera) = (AcpModule::new(), VeraModule::new());
        create(&mut acp, &mut vera).unwrap();
        let stored = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(stored.issuer_did, key.canonical());
        assert_eq!(stored.authorized_account, worker.signer);
        for (issued, other) in key.dids().into_iter().zip(stranger.dids()) {
            let listed = vera.get_jws_tokens_by_did(&issued).unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].token_hash, hash);
            assert!(vera.get_jws_tokens_by_did(&other).unwrap().is_empty());
        }
        let submission = TxExecCtx {
            signer: key.spellings()[(written + 2) % 4].clone(),
            tx_hash: vec![1; 32],
            sequence: 0,
        };
        let invalidated = vera
            .invalidate_jws(
                &context(101),
                &submission,
                &key.dids()[(written + 3) % 4],
                &hash,
            )
            .unwrap();
        assert_eq!(invalidated.invalidated_by, key.canonical());
        assert!(create(&mut acp, &mut vera).is_err());
        vera.validate_restored_tokens().unwrap();
    }
}

#[test]
fn a_delegation_names_its_worker_in_any_spelling() {
    let (key, signer, other) = (Key::new(42), Key::new(9), Key::new(10));
    let submission = TxExecCtx {
        signer: signer.canonical(),
        tx_hash: vec![9; 32],
        sequence: 0,
    };
    for subject in signer.spellings() {
        let (mut acp, mut vera) = (AcpModule::new(), VeraModule::new());
        let token = key.token_for(&subject, DelegationScope::CreatePolicy);
        let created = acp
            .bearer_create_policy(
                &mut vera,
                &context(100),
                &submission,
                &token,
                DEFINITION,
                FORMAT,
            )
            .unwrap();
        assert_eq!(created.metadata.owner_did, key.canonical());
        assert_eq!(created.metadata.tx_signer, signer.canonical());
        let stored = vera
            .get_jws_token(&hash_jws_token(&token))
            .unwrap()
            .unwrap();
        assert_eq!(stored.authorized_account, signer.canonical());
        for account in signer.spellings() {
            assert_eq!(vera.get_jws_tokens_by_account(&account).unwrap().len(), 1);
        }
        vera.validate_restored_tokens().unwrap();
        let mut invalidating = vera.clone();
        let respelled = TxExecCtx {
            signer: signer.spellings()[3].clone(),
            ..submission.clone()
        };
        let invalidated = invalidating
            .invalidate_jws(
                &context(101),
                &respelled,
                &signer.dids()[3],
                &hash_jws_token(&token),
            )
            .unwrap();
        assert_eq!(invalidated.invalidated_by, signer.canonical());
        let revoked = vera
            .revoke_delegation(&context(101), &signer.dids()[1], &token)
            .unwrap();
        assert_eq!(revoked.invalidated_by, signer.canonical());
    }
    for subject in other.spellings() {
        let (mut acp, mut vera) = (AcpModule::new(), VeraModule::new());
        let token = key.token_for(&subject, DelegationScope::CreatePolicy);
        assert!(
            acp.bearer_create_policy(
                &mut vera,
                &context(100),
                &submission,
                &token,
                DEFINITION,
                FORMAT
            )
            .is_err()
        );
    }
}

#[test]
fn a_bulletin_collaborator_is_one_actor() {
    let collaborator = Key::new(43);
    let owner = Did::new("did:key:owner").unwrap();
    let submission = TxExecCtx {
        signer: owner.to_string(),
        tx_hash: vec![1; 32],
        sequence: 0,
    };
    let mut states = Vec::new();
    for written in 0..4 {
        let (mut acp, mut bulletin) = (AcpModule::new(), BulletinModule::new());
        let namespace = bulletin
            .register_namespace(&mut acp, &context(100), &submission, &owner, "notes")
            .unwrap()
            .id;
        let added = bulletin
            .add_collaborator(
                &mut acp,
                &submission,
                &owner,
                &namespace,
                &collaborator.spellings()[written],
            )
            .unwrap();
        assert_eq!(added, collaborator.canonical());
        let recorded = (acp.store().serialize(), bulletin.store().serialize());
        for (spelled, author) in collaborator.spellings().iter().zip(collaborator.dids()) {
            assert!(
                bulletin
                    .add_collaborator(&mut acp, &submission, &owner, &namespace, spelled)
                    .is_err()
            );
            let mut posting = bulletin.clone();
            posting
                .create_post(&acp, &submission, &author, &namespace, b"payload", &[], "")
                .unwrap();
            let posts = posting.query_namespace_posts(&namespace).unwrap();
            assert_eq!(posts[0].creator_did, collaborator.canonical());
        }
        assert_eq!(
            (acp.store().serialize(), bulletin.store().serialize()),
            recorded
        );
        let listed = bulletin.query_namespace_collaborators(&namespace).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].did, collaborator.canonical());
        states.push(recorded);

        let removed = bulletin
            .remove_collaborator(
                &mut acp,
                &submission,
                &owner,
                &namespace,
                &collaborator.spellings()[(written + 1) % 4],
            )
            .unwrap();
        assert_eq!(removed, collaborator.canonical());
        assert!(
            bulletin
                .query_namespace_collaborators(&namespace)
                .unwrap()
                .is_empty()
        );
        assert!(
            bulletin
                .create_post(
                    &acp,
                    &submission,
                    &collaborator.dids()[0],
                    &namespace,
                    b"payload",
                    &[],
                    ""
                )
                .is_err()
        );
    }
    assert!(states.windows(2).all(|pair| pair[0] == pair[1]));
}
