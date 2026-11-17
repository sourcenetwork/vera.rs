//! Why a module refused a native request.
//!
//! The module and kind are part of the receipt commitment. The message is the
//! module's own text for a person; it is bounded and not committed, because
//! its wording comes from module and library error text that may differ
//! between releases.

use serde::{Deserialize, Serialize};

/// Longest refusal message a receipt carries, in bytes.
pub const MAX_REFUSAL_MESSAGE_BYTES: usize = 1024;

/// The module a refused native request was addressed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RefusingModule {
    /// Access control policies (`0x0810`).
    Acp = 1,
    /// Bulletin (`0x0811`).
    Bulletin = 2,
    /// Identity, tokens, threshold objects and administration (`0x0812`).
    Vera = 3,
    /// Validator membership (`0x0813`).
    ValidatorRegistry = 4,
}

impl RefusingModule {
    /// The committed one-byte code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The module with this committed code.
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Acp,
            2 => Self::Bulletin,
            3 => Self::Vera,
            4 => Self::ValidatorRegistry,
            _ => return None,
        })
    }
}

/// What a module refused about a native request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RefusalKind {
    /// The calldata names no method of the module.
    UnknownSelector = 1,
    /// The calldata or an encoded argument does not decode.
    UndecodableInput = 2,
    /// An argument exceeds a size or count limit.
    ArgumentOutOfBounds = 3,
    /// An argument decodes but is not acceptable.
    InvalidArgument = 4,
    /// The policy definition was refused by the policy parser or validator.
    InvalidPolicy = 5,
    /// The method needs a signer and the call has none.
    Unauthenticated = 6,
    /// The signer may not perform the operation.
    Unauthorized = 7,
    /// A bearer token or JWS is invalid, or was already invalidated.
    InvalidToken = 8,
    /// A supplied proof does not verify.
    InvalidProof = 9,
    /// A named policy, commitment, namespace, post, collaborator, token or validator does not exist.
    NotFound = 10,
    /// The object is not registered.
    ObjectNotRegistered = 11,
    /// The object, namespace, post, collaborator or validator already exists.
    AlreadyExists = 12,
    /// The named commitment has expired.
    Expired = 13,
    /// The membership change would break a committee limit.
    MembershipConstraint = 14,
    /// A module work limit not drawn from the gas allowance was exceeded.
    WorkLimitExceeded = 15,
    /// A record the call wrote exceeds the native storage bounds.
    StorageBounds = 16,
    /// The call exhausted its gas allowance.
    OutOfGas = 17,
    /// Module state the call needed could not be used.
    StateError = 18,
    /// The module failed while executing the call.
    ModuleFailed = 19,
}

impl RefusalKind {
    /// The committed one-byte code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The kind with this committed code.
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::UnknownSelector,
            2 => Self::UndecodableInput,
            3 => Self::ArgumentOutOfBounds,
            4 => Self::InvalidArgument,
            5 => Self::InvalidPolicy,
            6 => Self::Unauthenticated,
            7 => Self::Unauthorized,
            8 => Self::InvalidToken,
            9 => Self::InvalidProof,
            10 => Self::NotFound,
            11 => Self::ObjectNotRegistered,
            12 => Self::AlreadyExists,
            13 => Self::Expired,
            14 => Self::MembershipConstraint,
            15 => Self::WorkLimitExceeded,
            16 => Self::StorageBounds,
            17 => Self::OutOfGas,
            18 => Self::StateError,
            19 => Self::ModuleFailed,
            _ => return None,
        })
    }

    /// Whether a refusal of this kind is charged the whole native allowance
    /// rather than what the call used.
    pub const fn charges_full_allowance(self) -> bool {
        matches!(self, Self::OutOfGas | Self::ModuleFailed)
    }
}

/// Why a module refused a native request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RefusalFields")]
pub struct Refusal {
    /// The module the request was addressed to.
    pub module: RefusingModule,
    /// What the module refused; committed by the receipt.
    pub kind: RefusalKind,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalFields {
    module: RefusingModule,
    kind: RefusalKind,
    message: String,
}

/// A refusal message longer than [`MAX_REFUSAL_MESSAGE_BYTES`].
#[derive(Debug, thiserror::Error)]
#[error("refusal message exceeds {MAX_REFUSAL_MESSAGE_BYTES} bytes")]
pub struct RefusalMessageTooLong;

impl TryFrom<RefusalFields> for Refusal {
    type Error = RefusalMessageTooLong;

    fn try_from(fields: RefusalFields) -> Result<Self, Self::Error> {
        Self::with_message(fields.module, fields.kind, fields.message)
    }
}

impl Refusal {
    /// A refusal whose message is cut to at most [`MAX_REFUSAL_MESSAGE_BYTES`]
    /// at a character boundary.
    pub fn new(module: RefusingModule, kind: RefusalKind, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_REFUSAL_MESSAGE_BYTES {
            let end = (0..=MAX_REFUSAL_MESSAGE_BYTES)
                .rev()
                .find(|&end| message.is_char_boundary(end))
                .unwrap_or(0);
            message.truncate(end);
        }
        Self {
            module,
            kind,
            message,
        }
    }

    /// A refusal carrying exactly `message`, which must fit the bound.
    pub fn with_message(
        module: RefusingModule,
        kind: RefusalKind,
        message: String,
    ) -> Result<Self, RefusalMessageTooLong> {
        if message.len() > MAX_REFUSAL_MESSAGE_BYTES {
            return Err(RefusalMessageTooLong);
        }
        Ok(Self {
            module,
            kind,
            message,
        })
    }

    /// The module's message for a person. It is reported by the node that
    /// executed or imported the receipt and is not covered by the receipt
    /// commitment.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let module = match self.module {
            RefusingModule::Acp => "ACP",
            RefusingModule::Bulletin => "Bulletin",
            RefusingModule::Vera => "Vera",
            RefusingModule::ValidatorRegistry => "ValidatorRegistry",
        };
        write!(f, "{module} refused ({:?}): {}", self.kind, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_unknown_codes_are_refused() {
        for code in 0..=u8::MAX {
            if let Some(kind) = RefusalKind::from_code(code) {
                assert_eq!(kind.code(), code);
            } else {
                assert!(code == 0 || code > 19);
            }
            if let Some(module) = RefusingModule::from_code(code) {
                assert_eq!(module.code(), code);
            } else {
                assert!(code == 0 || code > 4);
            }
        }
    }

    #[test]
    fn messages_are_bounded_on_construction_and_decoding() {
        let long = "é".repeat(MAX_REFUSAL_MESSAGE_BYTES);
        let refusal = Refusal::new(
            RefusingModule::Acp,
            RefusalKind::InvalidPolicy,
            long.clone(),
        );
        assert!(refusal.message().len() <= MAX_REFUSAL_MESSAGE_BYTES);
        assert!(long.starts_with(refusal.message()));

        let json = serde_json::json!({"module": "acp", "kind": "invalid_policy", "message": long});
        assert!(serde_json::from_value::<Refusal>(json).is_err());
        let json = serde_json::json!({"module": "acp", "kind": "invalid_policy", "message": "no"});
        let decoded: Refusal = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.kind, RefusalKind::InvalidPolicy);
        assert_eq!(decoded.message(), "no");
        let unknown = serde_json::json!({"module": "acp", "kind": "success", "message": ""});
        assert!(serde_json::from_value::<Refusal>(unknown).is_err());
    }
}
