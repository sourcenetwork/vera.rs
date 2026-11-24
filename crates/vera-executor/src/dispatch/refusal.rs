//! The committed kind of each refusal a module call can produce.
//!
//! A module error's variant decides its kind.

use vera_domain::RefusalKind;
use vera_modules::acp::error::AcpError;
use vera_modules::bulletin::error::BulletinError;
use vera_modules::validator_registry::error::ValidatorRegistryError;
use vera_modules::vera::error::VeraError;

use super::ModuleError;

/// A caller-facing refusal of a module call.
pub(crate) trait Refuse: core::fmt::Display {
    /// The committed kind of this refusal.
    fn refusal_kind(&self) -> RefusalKind;
}

/// A refusal raised as an error rather than returned as a revert.
pub(crate) fn refused(kind: RefusalKind, reason: impl core::fmt::Display) -> ModuleError {
    ModuleError::Refused {
        kind,
        message: reason.to_string(),
    }
}

/// The kind of a refusal raised as an error.
pub(crate) const fn kind_of(error: &ModuleError) -> RefusalKind {
    match error {
        ModuleError::Refused { kind, .. } => *kind,
        ModuleError::OutOfGas => RefusalKind::OutOfGas,
        ModuleError::Fault(_) => RefusalKind::ModuleFailed,
    }
}

/// Prefix a refusal raised as an error with `context`, keeping its kind.
pub(crate) fn with_context(error: ModuleError, context: &str) -> ModuleError {
    match error {
        ModuleError::Refused { kind, message } => refused(kind, format!("{context}{message}")),
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
            Self::ObjectAlreadyRegistered { .. } | Self::PolicyAlreadyExists { .. } => {
                RefusalKind::AlreadyExists
            }
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
            Self::State(_) | Self::Corrupt(_) => RefusalKind::StateError,
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
    fn a_refusal_keeps_its_kind_through_context() {
        let error = refused(RefusalKind::UndecodableInput, "ABI decode: short");
        let error = with_context(error, "batch call 2: ");
        assert_eq!(kind_of(&error), RefusalKind::UndecodableInput);
        assert_eq!(error.to_string(), "batch call 2: ABI decode: short");
        let unqualified = ModuleError::invalid("array length mismatch");
        assert_eq!(kind_of(&unqualified), RefusalKind::InvalidArgument);
    }
}
