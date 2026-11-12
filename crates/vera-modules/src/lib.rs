//! Vera module implementations — ACP, Bulletin, and Vera.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives as _;

/// Canonical actor spelling shared by every module and its verifiers.
pub mod actor;
mod borsh_did;
/// Shared key encoding helpers (length prefix, sanitization).
pub mod key_encoding;
/// Module-level KV store trait and in-memory implementation.
pub mod kv_store;
/// Shared module state container.
pub mod module_state;
/// Shared types used across modules (Timestamp, Duration).
pub mod types;

/// Access Control Policy module (precompile `0x0810`).
pub mod acp;
/// Bulletin module (precompile `0x0811`).
pub mod bulletin;
/// Native account state (DID-keyed nonce tracking).
pub mod native_account;
/// ValidatorRegistry module (precompile `0x0813`).
pub mod validator_registry;
/// Vera module (precompile `0x0812`).
pub mod vera;

pub use module_state::{ModuleState, SharedModuleState};
