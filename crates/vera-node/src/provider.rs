//! Certificate provider whose per-epoch schemes are registered as ceremonies complete.

use std::{collections::HashMap, sync::Arc};

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{group::Share, sharing::Sharing, variant::MinSig},
    certificate::{Provider, Scoped},
    ed25519,
};
use commonware_glue::dkg::{Registrar as RegistrarTrait, types::SchemeInfo};
use commonware_utils::{
    N3f1,
    ordered::{Quorum as _, Set},
};
use parking_lot::Mutex;
use vera_app::ConsensusScheme;

type Scheme = ConsensusScheme;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ShareError {
    #[error("threshold share does not belong to the local validator")]
    WrongParticipant,
    #[error("threshold sharing does not match the participant set")]
    InvalidCommittee,
    #[error("threshold share does not match the public sharing")]
    InvalidShare,
}

pub(crate) fn signer_scheme(
    local: &ed25519::PublicKey,
    participants: Set<ed25519::PublicKey>,
    sharing: Sharing<MinSig>,
    share: Share,
) -> Result<Scheme, ShareError> {
    let index = usize::try_from(share.index.get()).map_err(|_| ShareError::WrongParticipant)?;
    if participants.get(index) != Some(local) {
        return Err(ShareError::WrongParticipant);
    }
    if usize::try_from(sharing.total().get()).map_err(|_| ShareError::InvalidCommittee)?
        != participants.len()
        || sharing.required() != participants.quorum::<N3f1>()
    {
        return Err(ShareError::InvalidCommittee);
    }
    Scheme::signer(crate::NAMESPACE, participants, sharing, share).ok_or(ShareError::InvalidShare)
}

/// Epoch signing material and a fixed group verifier for historical certificates.
#[derive(Clone, Default)]
pub struct DynamicProvider {
    state: Arc<Mutex<ProviderState>>,
}

#[derive(Default)]
struct ProviderState {
    schemes: HashMap<Epoch, Arc<Scheme>>,
    verifier: Option<Arc<Scheme>>,
}

impl std::fmt::Debug for DynamicProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicProvider")
            .field("schemes", &self.state.lock().schemes.len())
            .finish_non_exhaustive()
    }
}

impl DynamicProvider {
    /// Register the certificate scheme for `epoch`.
    ///
    /// # Panics
    ///
    /// Panics if the scheme changes the deployment's fixed group identity.
    pub fn register(&self, epoch: Epoch, scheme: Scheme) {
        let mut state = self.state.lock();
        if let Some(verifier) = &state.verifier {
            assert!(
                verifier.identity() == scheme.identity(),
                "registered scheme must retain the deployment group identity"
            );
        } else {
            state.verifier = Some(Arc::new(Scheme::certificate_verifier(
                crate::NAMESPACE,
                *scheme.identity(),
            )));
        }
        state.schemes.insert(epoch, Arc::new(scheme));
    }

    pub(crate) fn for_consensus(&self) -> ConsensusProvider {
        ConsensusProvider(self.clone())
    }
}

impl Provider for DynamicProvider {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, _: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.state.lock().verifier.clone().map(Scoped::verifier)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.state.lock().schemes.get(&scope).cloned()
    }
}

/// Retires full schemes only when the orchestrator enters a registered epoch.
#[derive(Clone, Debug)]
pub(crate) struct ConsensusProvider(DynamicProvider);

impl Provider for ConsensusProvider {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.0.scoped(scope)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        let mut state = self.0.state.lock();
        let scheme = state.schemes.get(&scope).cloned()?;
        // Marshal may look up other epochs while serving retained history.
        // Only the orchestrator's successful entry can retire signing material.
        state.schemes.retain(|epoch, _| *epoch >= scope);
        Some(scheme)
    }
}

/// Adapter that registers reshare outputs with the [`DynamicProvider`].
#[derive(Clone, Debug)]
pub struct Registrar {
    provider: DynamicProvider,
    local: ed25519::PublicKey,
}

impl Registrar {
    /// Bind registration to this validator's identity in each epoch's committee.
    pub const fn new(provider: DynamicProvider, local: ed25519::PublicKey) -> Self {
        Self { provider, local }
    }
}

impl RegistrarTrait for Registrar {
    type Variant = MinSig;
    type PublicKey = ed25519::PublicKey;

    async fn register(&self, epoch: Epoch, info: SchemeInfo<Self::Variant, Self::PublicKey>) {
        let scheme = match info {
            SchemeInfo::Verifier {
                participants,
                sharing,
            } => Scheme::verifier(crate::NAMESPACE, participants, sharing),
            SchemeInfo::Signer {
                participants,
                sharing,
                share,
            } => signer_scheme(&self.local, participants, sharing, share)
                .expect("registered share must match the local participant and sharing"),
        };
        self.provider.register(epoch, scheme);
    }
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "provider_retention_tests.rs"]
mod retention_tests;
