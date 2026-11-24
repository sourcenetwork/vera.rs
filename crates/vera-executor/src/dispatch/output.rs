//! What a module call returns to the dispatch that ran it.

use alloy_primitives::Bytes;
use thiserror::Error;
use vera_domain::RefusalKind;

/// How a module call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleStatus {
    /// The call ran to completion.
    Success,
    /// The module refused the call; its output is the refusal's message.
    Revert,
    /// The call's gas allowance did not cover it.
    OutOfGas,
}

impl ModuleStatus {
    /// Whether the call ran to completion.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Whether the module refused the call.
    #[must_use]
    pub const fn is_revert(self) -> bool {
        matches!(self, Self::Revert)
    }
}

/// Status, gas and return data of one module call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleOutput {
    /// How the call ended.
    pub status: ModuleStatus,
    /// Gas the call reports having used.
    pub gas_used: u64,
    /// Return data of a completed call, or the message of a refusal.
    pub bytes: Bytes,
}

impl ModuleOutput {
    /// A completed call.
    #[must_use]
    pub const fn success(gas_used: u64, bytes: Bytes) -> Self {
        Self {
            status: ModuleStatus::Success,
            gas_used,
            bytes,
        }
    }

    /// A refused call carrying its message.
    #[must_use]
    pub const fn revert(gas_used: u64, bytes: Bytes) -> Self {
        Self {
            status: ModuleStatus::Revert,
            gas_used,
            bytes,
        }
    }

    /// A call whose allowance ran out; it reports no usage.
    #[must_use]
    pub const fn out_of_gas() -> Self {
        Self {
            status: ModuleStatus::OutOfGas,
            gas_used: 0,
            bytes: Bytes::new(),
        }
    }
}

/// A module call that did not produce an output.
///
/// Only [`Self::Fault`] fails the block. Every other error rejects the request
/// that caused it: its sender gets a failed receipt and the block goes on.
/// Calldata is the caller's to choose, and a request that failed its block
/// would fail every block proposed while it waits in the pool.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ModuleError {
    /// The node's own fault: stored state that does not read back as what was
    /// written, or a value the executor derived that is not what it must be.
    #[error("{0}")]
    Fault(String),
    /// A refusal of what the caller sent.
    #[error("{message}")]
    Refused {
        /// The committed kind of the refusal.
        kind: RefusalKind,
        /// The caller-facing reason.
        message: String,
    },
    /// The call's gas allowance did not cover it.
    #[error("out of gas")]
    OutOfGas,
}

impl ModuleError {
    /// A request the call could not use.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Refused {
            kind: RefusalKind::InvalidArgument,
            message: message.into(),
        }
    }
}
