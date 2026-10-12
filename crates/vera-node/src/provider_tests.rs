use super::*;
use commonware_cryptography::Signer as _;
use commonware_utils::Participant;

#[test]
fn signing_material_is_bound_to_the_local_participant() {
    let local = ed25519::PrivateKey::from_seed(0).public_key();
    let other = ed25519::PrivateKey::from_seed(1).public_key();
    let participants = (0..4).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key());
    let (info, shares) = crate::trusted_setup(9031, participants).unwrap();
    let sharing = info.output.public().clone();
    let own = shares.get_value(&local).unwrap().clone();
    let foreign = shares.get_value(&other).unwrap().clone();
    let mut forged = own.clone();
    forged.private = foreign.private.clone();

    assert!(
        Scheme::signer(
            crate::NAMESPACE,
            info.players.clone(),
            sharing.clone(),
            foreign.clone(),
        )
        .is_some()
    );
    assert!(matches!(
        signer_scheme(&local, info.players.clone(), sharing.clone(), foreign),
        Err(ShareError::WrongParticipant)
    ));
    assert!(signer_scheme(&local, info.players.clone(), sharing.clone(), own.clone()).is_ok());
    assert!(matches!(
        signer_scheme(&local, info.players.clone(), sharing.clone(), forged),
        Err(ShareError::InvalidShare)
    ));
    let outsider = ed25519::PrivateKey::from_seed(4).public_key();
    assert!(matches!(
        signer_scheme(
            &outsider,
            info.players.clone(),
            sharing.clone(),
            own.clone()
        ),
        Err(ShareError::WrongParticipant)
    ));
    let mut invalid = own;
    invalid.index = Participant::new(u32::MAX);
    assert!(matches!(
        signer_scheme(&local, info.players, sharing, invalid),
        Err(ShareError::WrongParticipant)
    ));
}

#[tokio::test]
async fn registrar_rejects_a_valid_share_for_another_member() {
    let local = ed25519::PrivateKey::from_seed(0).public_key();
    let other = ed25519::PrivateKey::from_seed(1).public_key();
    let participants = (0..4).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key());
    let (info, shares) = crate::trusted_setup(9032, participants).unwrap();
    let own = shares.get_value(&local).unwrap().clone();
    let provider = DynamicProvider::default();
    let registrar = Registrar::new(provider.clone(), local.clone());
    let epoch = Epoch::new(7);
    let foreign = SchemeInfo::Signer {
        participants: info.players.clone(),
        sharing: info.output.public().clone(),
        share: shares.get_value(&other).unwrap().clone(),
    };
    let rejected = tokio::spawn(async move { registrar.register(epoch, foreign).await })
        .await
        .unwrap_err();
    assert!(rejected.is_panic());
    assert!(provider.scheme(epoch).is_none());

    Registrar::new(provider.clone(), local)
        .register(
            epoch,
            SchemeInfo::Signer {
                participants: info.players,
                sharing: info.output.public().clone(),
                share: own,
            },
        )
        .await;
    assert!(provider.scheme(epoch).is_some());
}
