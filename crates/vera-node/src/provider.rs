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

/// Certificate provider whose per-epoch schemes are registered as ceremonies complete.
#[derive(Clone, Debug, Default)]
pub struct DynamicProvider {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<Scheme>>>>,
}

impl DynamicProvider {
    /// Register the certificate scheme for `epoch`.
    pub fn register(&self, epoch: Epoch, scheme: Scheme) {
        self.schemes.lock().insert(epoch, Arc::new(scheme));
    }
}

impl Provider for DynamicProvider {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned().map(Scoped::scheme)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned()
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
