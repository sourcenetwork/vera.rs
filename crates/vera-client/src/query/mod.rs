//! Read-only query methods for vera precompile modules.

/// ACP queries (precompile `0x0810`).
pub(crate) mod acp;
/// Bulletin queries (precompile `0x0811`).
pub(crate) mod bulletin;
/// Vera queries (precompile `0x0812`).
pub(crate) mod vera;

mod acp_lifecycle;
