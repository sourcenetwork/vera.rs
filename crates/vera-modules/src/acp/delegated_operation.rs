//! Canonical operation commitments for relay assertions.

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use vera_crypto::jwt::DelegationScope;

use super::{
    AcpError, Result,
    types::{AccessRequest, PolicyCmd, PolicyMarshalingType},
};

/// Exact semantic arguments authorized by a relay, excluding the assertion itself.
#[derive(Debug, Serialize)]
pub enum DelegatedOperation<'a> {
    /// Complete encrypted document or signing derivation binding.
    StoreThresholdObject(&'a crate::vera::objects::ThresholdObject),
    /// Complete ring command, including all creation parameters.
    RingCommand(&'a crate::vera::rings::RingCommand),
    /// Policy definition and serialization format.
    CreatePolicy(&'a str, &'a PolicyMarshalingType),
    /// Policy identifier, replacement definition and serialization format.
    EditPolicy(&'a str, &'a str, &'a PolicyMarshalingType),
    /// Policy identifier and the complete graph command.
    PolicyCommand(&'a str, &'a PolicyCmd),
    /// Ordered policy identifiers and graph commands, applied in order, all or none.
    PolicyCommandList(&'a [(String, PolicyCmd)]),
    /// Policy identifier, target actor and ordered permission operations.
    CheckAccess(&'a str, &'a AccessRequest),
}

impl DelegatedOperation<'_> {
    /// Required delegation scope.
    pub const fn scope(&self) -> DelegationScope {
        match self {
            Self::CreatePolicy(..) => DelegationScope::CreatePolicy,
            Self::EditPolicy(..) => DelegationScope::EditPolicy,
            Self::PolicyCommand(..) | Self::PolicyCommandList(..) => {
                DelegationScope::PolicyCommands
            }
            Self::CheckAccess(..) => DelegationScope::RecordAccessDecision,
            Self::RingCommand(..) => DelegationScope::ManageRings,
            Self::StoreThresholdObject(..) => DelegationScope::StoreThresholdObject,
        }
    }

    /// SHA-256 of `vera/acp-operation/v1\0` and compact serde JSON for this typed value.
    /// Struct fields and tuple arguments retain declaration order; inputs contain no maps.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"vera/acp-operation/v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| AcpError::State(error.to_string()))?);
        Ok(hash.finalize().into())
    }
}
