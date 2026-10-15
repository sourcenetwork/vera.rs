//! Bounded leader terms, with VRF delivery for legacy rotating deployments.

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::{
        elector::{Config, Dynamic, Elector, RoundRobin, RoundRobinElector, Terms},
        scheme::bls12381_threshold::vrf::Certificate,
    },
    types::{Participant, Round, TermLength, ViewDelta},
};
use commonware_cryptography::{Hasher as _, Sha256, bls12381::primitives::variant::MinSig};
use commonware_utils::ordered::Set;
use std::{num::NonZeroU32, time::Duration};
use vera_app::{ConsensusScheme, VrfSeedCache};
use vera_domain::{PublicKey, SimplexParameters};

/// Rotating leader election that delivers certificate-derived EVM randomness.
#[derive(Clone, Debug)]
pub(crate) struct VrfElectorConfig {
    seeds: VrfSeedCache,
}

impl VrfElectorConfig {
    pub(crate) const fn new(seeds: VrfSeedCache) -> Self {
        Self { seeds }
    }
}

impl Config<ConsensusScheme> for VrfElectorConfig {
    type Elector = VrfElector;

    fn build(self, participants: &Set<PublicKey>) -> Self::Elector {
        let election = RoundRobin::<Sha256>::default();
        let inner = <RoundRobin<Sha256> as Config<ConsensusScheme>>::build(election, participants);
        VrfElector {
            seeds: self.seeds,
            inner,
        }
    }
}

/// Initialized rotating elector for compatibility execution.
#[derive(Clone, Debug)]
pub(crate) struct VrfElector {
    seeds: VrfSeedCache,
    inner: RoundRobinElector<ConsensusScheme>,
}

impl Elector<ConsensusScheme> for VrfElector {
    type Mode = Dynamic;

    fn terms(&self) -> Terms {
        self.inner.terms()
    }

    fn elect(&self, round: Round, certificate: Option<&Certificate<MinSig>>) -> Participant {
        if let Some(signature) = certificate.and_then(Certificate::get) {
            // EVM exposes a 32-byte PREVRANDAO while the MinSig seed is a
            // canonical 48-byte G1 point. Hashing the encoding preserves all
            // of its entropy and gives every validator the same B256.
            let encoded = signature.seed_signature.encode();
            let digest = Sha256::hash(&[encoded.as_ref()]);
            self.seeds.insert(round, B256::from(digest.0));
        }
        self.inner.elect(round, ())
    }
}

/// Certificate-independent leader schedule for native pipelined deployments.
pub(crate) fn pipelined_elector(parameters: SimplexParameters) -> RoundRobin<Sha256> {
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
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::{Signer as _, ed25519};

    #[test]
    fn pipelined_terms_rotate_and_bound_optimistic_work() {
        let participants = Set::from_iter_dedup(
            (0..4).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        );
        let parameters = SimplexParameters::default();
        let elector = <RoundRobin<Sha256> as Config<ConsensusScheme>>::build(
            pipelined_elector(parameters),
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
        let legacy = VrfElectorConfig::new(VrfSeedCache::default()).build(&participants);
        assert_eq!(legacy.terms(), Terms::rotating());
    }
}
