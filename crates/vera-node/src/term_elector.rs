//! Round-robin leader election in bounded terms.

use commonware_consensus::{
    simplex::elector::RoundRobin,
    types::{TermLength, ViewDelta},
};
use commonware_cryptography::Sha256;
use std::{num::NonZeroU32, time::Duration};
use vera_domain::SimplexParameters;

/// Certificate-independent leader schedule in terms of `term_length` views.
pub(crate) fn term_elector(parameters: SimplexParameters) -> RoundRobin<Sha256> {
    parameters
        .validate()
        .expect("validated genesis Simplex parameters");
    RoundRobin::default().with_term(
        TermLength::new(
            NonZeroU32::new(u32::try_from(parameters.term_length).expect("bounded term length"))
                .unwrap(),
        ),
        Duration::from_millis(parameters.stall_timeout_ms),
        ViewDelta::new(parameters.optimistic_views),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::elector::{Config, Elector as _},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_utils::ordered::Set;
    use vera_app::ConsensusScheme;

    #[test]
    fn terms_rotate_and_bound_optimistic_work() {
        let participants = Set::from_iter_dedup(
            (0..4).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        );
        let parameters = SimplexParameters::default();
        let elector = <RoundRobin<Sha256> as Config<ConsensusScheme>>::build(
            term_elector(parameters),
            &participants,
        );
        assert_eq!(
            elector.terms().optimistic_views().get(),
            parameters.optimistic_views
        );
        for epoch in 0..3 {
            let round = |view| Round::new(Epoch::new(epoch), View::new(view));
            let first = elector.elect(round(1), ());
            for view in 2..=parameters.term_length {
                assert_eq!(elector.elect(round(view), ()), first);
            }
            assert_ne!(elector.elect(round(parameters.term_length + 1), ()), first);
        }
    }
}
