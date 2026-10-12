use super::*;
use commonware_consensus::{
    simplex::types::{Proposal, Subject},
    types::{Round, View},
};
use commonware_cryptography::{
    Signer as _,
    certificate::{Scheme as _, Verifier as _},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, non_empty};

fn schemes(seed: u64) -> Vec<Scheme> {
    let participants = (0..4).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key());
    let (info, shares) = crate::trusted_setup(seed, participants).unwrap();
    info.players
        .iter()
        .map(|participant| {
            Scheme::signer(
                crate::NAMESPACE,
                info.players.clone(),
                info.output.public().clone(),
                shares.get_value(participant).unwrap().clone(),
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn consensus_entry_retires_old_schemes_without_losing_future_material() {
    let provider = DynamicProvider::default();
    let consensus = provider.for_consensus();
    assert!(provider.scoped(Epoch::zero()).is_none());
    let signer = schemes(9033).remove(0);
    for epoch in 0..3 {
        provider.register(Epoch::new(epoch), signer.clone());
    }
    let old = Arc::downgrade(&provider.scheme(Epoch::zero()).unwrap());
    assert!(provider.scheme(Epoch::new(2)).is_some());
    assert!(provider.scheme(Epoch::zero()).is_some());
    assert!(consensus.scheme(Epoch::new(3)).is_none());
    assert!(provider.scheme(Epoch::zero()).is_some());

    let current = consensus.scheme(Epoch::new(1)).unwrap();
    assert!(current.share().is_some());
    assert!(old.upgrade().is_none());
    assert!(provider.scheme(Epoch::zero()).is_none());
    assert!(provider.scheme(Epoch::new(1)).is_some());
    assert!(provider.scheme(Epoch::new(2)).is_some());
    assert!(
        provider
            .scoped(Epoch::zero())
            .unwrap()
            .into_scheme()
            .is_none()
    );
    let mut previous = Arc::downgrade(&current);
    drop(current);

    for epoch in 2..66 {
        provider.register(Epoch::new(epoch + 1), signer.clone());
        let current = consensus.scheme(Epoch::new(epoch)).unwrap();
        assert!(previous.upgrade().is_none());
        assert!(provider.scheme(Epoch::new(epoch + 1)).is_some());
        assert_eq!(provider.state.lock().schemes.len(), 2);
        previous = Arc::downgrade(&current);
    }
}

#[test]
fn retired_epochs_still_authenticate_certificates_and_reject_wrong_subjects() {
    let signers = schemes(9034);
    let provider = DynamicProvider::default();
    provider.register(Epoch::zero(), signers[0].clone());
    provider.register(Epoch::new(1), signers[0].clone());
    let scope = provider.scoped(Epoch::zero()).unwrap();
    let proposal = Proposal::new(
        Round::new(Epoch::zero(), View::new(1)),
        View::zero(),
        Digest::from([8; 32]),
    );
    let votes: Vec<_> = signers
        .iter()
        .take(3)
        .map(|scheme| {
            scheme
                .sign(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap()
        })
        .collect();
    let certificate = signers[0]
        .assemble(non_empty![@votes], &Sequential)
        .unwrap();
    provider.for_consensus().scheme(Epoch::new(1)).unwrap();
    assert!(provider.scheme(Epoch::zero()).is_none());
    assert!(scope.clone().into_scheme().is_none());
    let mut rng = TestRng::new(9034);
    assert!(scope.verify_certificate::<_, Digest>(
        &mut rng,
        Subject::Finalize {
            proposal: &proposal
        },
        &certificate,
        &Sequential,
    ));
    let unrelated = schemes(9037);
    let votes: Vec<_> = unrelated
        .iter()
        .take(3)
        .map(|scheme| {
            scheme
                .sign(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap()
        })
        .collect();
    let foreign_certificate = unrelated[0]
        .assemble(non_empty![@votes], &Sequential)
        .unwrap();
    assert!(!scope.verify_certificate::<_, Digest>(
        &mut rng,
        Subject::Finalize {
            proposal: &proposal,
        },
        &foreign_certificate,
        &Sequential,
    ));
    let mut changed = proposal.clone();
    changed.round = Round::new(Epoch::new(1), View::new(1));
    assert!(!scope.verify_certificate::<_, Digest>(
        &mut rng,
        Subject::Finalize { proposal: &changed },
        &certificate,
        &Sequential,
    ));
    changed = proposal;
    changed.payload = Digest::from([9; 32]);
    assert!(!scope.verify_certificate::<_, Digest>(
        &mut rng,
        Subject::Finalize { proposal: &changed },
        &certificate,
        &Sequential,
    ));
}

#[test]
fn registration_rejects_a_changed_group_identity_without_publication() {
    let provider = DynamicProvider::default();
    let signer = schemes(9035).remove(0);
    provider.register(Epoch::zero(), signer.clone());
    let different_group = schemes(9036).remove(0);
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        provider.register(Epoch::new(1), different_group);
    }));
    assert!(rejected.is_err());
    assert!(provider.scheme(Epoch::new(1)).is_none());
    assert_eq!(
        *provider.scheme(Epoch::zero()).unwrap().identity(),
        *signer.identity()
    );
}
