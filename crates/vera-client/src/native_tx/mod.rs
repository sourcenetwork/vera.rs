//! State-changing native BLS transaction methods for vera precompile modules.

/// ACP native write methods (precompile `0x0810`).
pub(crate) mod acp;
/// Bulletin native write methods (precompile `0x0811`).
pub(crate) mod bulletin;
/// Vera native write methods (precompile `0x0812`).
pub(crate) mod vera;

mod acp_lifecycle;
