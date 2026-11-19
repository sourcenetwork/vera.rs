//! The committed kind of each refusal a module call can produce.
//!
//! A module error's variant decides its kind. A refusal raised as a
//! precompile error carries its kind in a sentinel prefix, as an internal
//! fault does, because revm's error has no field for it. The prefix never
//! reaches a caller: [`super::recoverable_message`] removes it.

use revm::precompile::PrecompileError;
use vera_domain::RefusalKind;
use vera_modules::acp::error::AcpError;
use vera_modules::bulletin::error::BulletinError;
use vera_modules::validator_registry::error::ValidatorRegistryError;
use vera_modules::vera::error::VeraError;

const REFUSAL: &str = "\u{0}refusal:";

/// A caller-facing refusal of a module call.
pub(crate) trait Refuse: core::fmt::Display {
    /// The committed kind of this refusal.
    fn refusal_kind(&self) -> RefusalKind;
}

/// A refusal raised as an error rather than returned as a revert.
pub(crate) fn refused(kind: RefusalKind, reason: impl core::fmt::Display) -> PrecompileError {
    PrecompileError::Fatal(format!("{REFUSAL}{}:{reason}", kind.code()))
}

/// The kind and message of a refusal raised as an error. An untagged error
/// is a request the call could not use, so it is an invalid argument.
pub(crate) fn split(message: &str) -> (RefusalKind, &str) {
    message
        .strip_prefix(REFUSAL)
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(code, message)| {
            let kind = RefusalKind::from_code(code.parse().ok()?)?;
            Some((kind, message))
        })
        .unwrap_or((RefusalKind::InvalidArgument, message))
}

/// The kind of a refusal raised as an error.
pub(crate) fn kind_of(error: &PrecompileError) -> RefusalKind {
    match error {
        PrecompileError::Fatal(message) => split(message).0,
        PrecompileError::FatalAny(_) => RefusalKind::InvalidArgument,
    }
}

/// Prefix a refusal raised as an error with `context`, keeping its kind.
pub(crate) fn with_context(error: PrecompileError, context: &str) -> PrecompileError {
    match error {
        PrecompileError::Fatal(message) => {
            let (kind, message) = split(&message);
            refused(kind, format!("{context}{message}"))
        }
        other => other,
    }
}

impl Refuse for AcpError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::PolicyNotFound { .. } | Self::CommitmentNotFound { .. } => RefusalKind::NotFound,
            Self::InvalidPolicy { .. } => RefusalKind::InvalidPolicy,
            Self::InvalidAccessRequest { .. } | Self::InvalidCommandList { .. } => {
                RefusalKind::InvalidArgument
            }
            Self::ObjectNotRegistered { .. } => RefusalKind::ObjectNotRegistered,
            Self::ObjectAlreadyRegistered { .. } => RefusalKind::AlreadyExists,
            Self::CommitmentExpired { .. } => RefusalKind::Expired,
            Self::InvalidProof { .. } => RefusalKind::InvalidProof,
            Self::Unauthorized { .. } => RefusalKind::Unauthorized,
            Self::InvalidBearerToken { .. } => RefusalKind::InvalidToken,
            Self::PolicyCreateBudgetExceeded
            | Self::PolicyEditBudgetExceeded
            | Self::QueryBudgetExceeded
            | Self::CommandBudgetExceeded
            | Self::PermissionBudgetExceeded => RefusalKind::OutOfGas,
            Self::State(_) => RefusalKind::StateError,
        }
    }
}

impl Refuse for BulletinError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::InvalidNamespace | Self::InvalidPostPayload | Self::InvalidGlob { .. } => {
                RefusalKind::InvalidArgument
            }
            Self::NamespaceTooLong(_)
            | Self::CollaboratorTooLong(_)
            | Self::PostPayloadTooLarge(_)
            | Self::PostProofTooLarge(_)
            | Self::PostArtifactTooLarge(_) => RefusalKind::ArgumentOutOfBounds,
            Self::NamespaceNotFound { .. }
            | Self::PostNotFound { .. }
            | Self::CollaboratorNotFound { .. }
            | Self::PolicyNotInitialized => RefusalKind::NotFound,
            Self::NamespaceAlreadyExists { .. }
            | Self::PostAlreadyExists { .. }
            | Self::CollaboratorAlreadyExists { .. } => RefusalKind::AlreadyExists,
            Self::NotCollaborator { .. } | Self::Unauthorized { .. } => RefusalKind::Unauthorized,
            Self::QueryLimit => RefusalKind::WorkLimitExceeded,
            Self::PolicyInitFailed(_) | Self::State(_) => RefusalKind::StateError,
        }
    }
}

impl Refuse for VeraError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::InvalidThresholdObject { .. }
            | Self::InvalidRingRequest { .. }
            | Self::InvalidNodeRequest { .. }
            | Self::InvalidAdministrativeRequest { .. } => RefusalKind::InvalidArgument,
            Self::TokenNotFound { .. } => RefusalKind::NotFound,
            Self::TokenAlreadyInvalidated { .. } | Self::InvalidJws { .. } => {
                RefusalKind::InvalidToken
            }
            Self::Unauthorized { .. } => RefusalKind::Unauthorized,
            Self::State(_) => RefusalKind::StateError,
        }
    }
}

impl Refuse for ValidatorRegistryError {
    fn refusal_kind(&self) -> RefusalKind {
        match self {
            Self::ValidatorAlreadyExists(_) | Self::DuplicateConsensusKey => {
                RefusalKind::AlreadyExists
            }
            Self::ValidatorNotFound(_) => RefusalKind::NotFound,
            Self::Unauthorized(_) => RefusalKind::Unauthorized,
            Self::InvalidPublicKey | Self::InvalidAddress(_) | Self::InvalidP2PAddress(_) => {
                RefusalKind::InvalidArgument
            }
            Self::EmptyCommittee | Self::MembershipLimit(_) | Self::EpochCapacity(_) => {
                RefusalKind::MembershipConstraint
            }
            Self::State(_) => RefusalKind::StateError,
        }
    }
}

/// A refusal the dispatch layer states itself, with its kind.
pub(crate) struct Stated<M>(pub(crate) RefusalKind, pub(crate) M);

impl<M: core::fmt::Display> core::fmt::Display for Stated<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.1.fmt(f)
    }
}

impl<M: core::fmt::Display> Refuse for Stated<M> {
    fn refusal_kind(&self) -> RefusalKind {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tagged_error_keeps_its_kind_through_context_and_an_untagged_one_is_an_argument() {
        let error = refused(RefusalKind::UndecodableInput, "ABI decode: short");
        let error = with_context(error, "batch call 2: ");
        assert_eq!(kind_of(&error), RefusalKind::UndecodableInput);
        assert_eq!(
            super::super::recoverable_message(&error),
            "batch call 2: ABI decode: short"
        );
        let untagged = PrecompileError::Fatal("array length mismatch".into());
        assert_eq!(kind_of(&untagged), RefusalKind::InvalidArgument);
        let forged = PrecompileError::Fatal("\u{0}refusal:99:x".into());
        assert_eq!(split("\u{0}refusal:99:x").1, "\u{0}refusal:99:x");
        assert_eq!(kind_of(&forged), RefusalKind::InvalidArgument);
    }
}
