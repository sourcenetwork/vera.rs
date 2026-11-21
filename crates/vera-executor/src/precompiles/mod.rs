//! Vera precompiles — ABI dispatch for ACP, Bulletin, Vera, and ValidatorRegistry modules.
//!
//! L2-convention addresses:
//! - `0x0810` — ACP (access control policies)
//! - `0x0811` — Bulletin (coordination / DKG messages)
//! - `0x0812` — Vera (identity / JWS token lifecycle)
//! - `0x0813` — ValidatorRegistry (validator identity management)
//! - `0x0814` — Anchor (finalized revisions of other deployments)

mod acp;
mod anchor;
mod bulletin;
pub(crate) mod refusal;
pub(crate) mod validator_registry;
mod vera;

use refusal::{Refuse, Stated};
use vera_domain::RefusalKind;

use alloy_primitives::{Address, Bytes, Log};
use revm::precompile::{PrecompileError, PrecompileHalt, PrecompileOutput};
use vera_identity::Did;
use vera_modules::acp::AcpModule;
use vera_modules::bulletin::BulletinModule;
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::vera::VeraModule;

/// ACP precompile address.
pub const ACP_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x10);

/// Bulletin precompile address.
pub const BULLETIN_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x11);

/// Vera precompile address.
pub const VERA_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x12);

/// Anchor precompile address.
pub const ANCHOR_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x14);

/// ValidatorRegistry precompile address.
pub const VALIDATOR_REGISTRY_ADDRESS: Address = vera_modules::validator_registry::layout::ADDRESS;

const fn address_from_last_two_bytes(hi: u8, lo: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = hi;
    bytes[19] = lo;
    Address::new(bytes)
}

pub(super) fn did_from_signer(signer: &str) -> Result<Did, PrecompileError> {
    // A view call has no signer, which is the caller's doing. A signer the
    // executor derived cannot be malformed.
    if signer.is_empty() {
        return Err(refusal::refused(
            RefusalKind::Unauthenticated,
            UNAUTHENTICATED_CALLER,
        ));
    }
    Did::new(signer).map_err(|e| internal_fault(format!("DID: {e}")))
}

const UNAUTHENTICATED_CALLER: &str = "module call requires an authenticated caller";

/// Sentinel prefix of an error that is the node's own: stored state that does
/// not read back as what was written, or a value the executor derived that is
/// not what it must be. revm's precompile error has no variant to tell such a
/// fault from a refusal of what the caller sent, so the fault is marked.
///
/// Only a marked error fails the block. Every other error of a module call
/// rejects the request that caused it: its sender gets a failed receipt and
/// the block goes on. The default is the refusal because calldata is the
/// caller's to choose, and a request that failed its block would fail every
/// block proposed while it waits in the pool.
const INTERNAL_FAULT: &str = "\u{0}internal-fault:";

/// A fault of the node, which fails the block.
pub(crate) fn internal_fault(reason: impl core::fmt::Display) -> PrecompileError {
    PrecompileError::Fatal(format!("{INTERNAL_FAULT}{reason}"))
}

/// The reason of an [`internal_fault`], or `None` for a refusal.
pub(crate) fn internal_fault_reason(error: &PrecompileError) -> Option<String> {
    match error {
        PrecompileError::Fatal(message) => message.strip_prefix(INTERNAL_FAULT).map(str::to_owned),
        // Not raised by the modules; whatever raises one is not a refusal.
        PrecompileError::FatalAny(error) => Some(error.to_string()),
    }
}

pub(super) fn decode_error(e: alloy_sol_types::Error) -> PrecompileError {
    refusal::refused(RefusalKind::UndecodableInput, format!("ABI decode: {e}"))
}

/// A call naming no method of its module.
pub(super) fn unknown_selector(module: &str, selector: [u8; 4]) -> PrecompileError {
    refusal::refused(
        RefusalKind::UnknownSelector,
        format!("unknown {module} selector: 0x{}", hex::encode(selector)),
    )
}

/// Calldata too short to hold a selector.
pub(super) fn short_input() -> DispatchResult {
    err_dispatch(Stated(
        RefusalKind::UnknownSelector,
        "input too short for selector",
    ))
}

pub(super) fn json_bytes(v: &impl serde::Serialize) -> Bytes {
    Bytes::from(serde_json::to_vec(v).unwrap_or_default())
}

pub(super) fn ok_output(gas: u64, ret: Vec<u8>) -> PrecompileOutput {
    PrecompileOutput::new(gas, ret.into(), 0)
}

pub(super) const fn oog_dispatch() -> DispatchResult {
    DispatchResult {
        precompile: PrecompileOutput::halt(PrecompileHalt::OutOfGas, 0),
        logs: vec![],
        refusal: None,
    }
}

/// Sentinels an out-of-gas halt while it propagates through dispatch helpers;
/// the dispatch boundary converts it back into an out-of-gas halt result.
pub(super) const OUT_OF_GAS_MESSAGE: &str = "\u{0}out-of-gas";

pub(super) fn out_of_gas_error() -> PrecompileError {
    PrecompileError::Fatal(OUT_OF_GAS_MESSAGE.to_string())
}

pub(crate) fn is_out_of_gas(error: &PrecompileError) -> bool {
    matches!(error, PrecompileError::Fatal(message) if message == OUT_OF_GAS_MESSAGE)
}

/// Message carried by a recoverable dispatch error, without the fatal-error
/// display prefix or refusal tag — module-style reverts report the bare cause.
pub(crate) fn recoverable_message(error: &PrecompileError) -> String {
    match error {
        PrecompileError::Fatal(message) => refusal::split(message).1.to_owned(),
        other => other.to_string(),
    }
}

/// A revert carrying a refusal raised as an error, with its kind.
pub(crate) fn refusal_dispatch(error: &PrecompileError) -> DispatchResult {
    err_dispatch(Stated(refusal::kind_of(error), recoverable_message(error)))
}

/// Result of dispatching to a vera module, including any emitted event logs.
#[derive(Debug)]
pub struct DispatchResult {
    /// The precompile output (gas, return data, revert status).
    pub precompile: PrecompileOutput,
    /// Event logs emitted during the dispatch.
    pub logs: Vec<Log>,
    /// What the module refused, for a revert.
    pub refusal: Option<RefusalKind>,
}

/// Return type for module dispatch functions.
pub type DispatchReturn = Result<DispatchResult, PrecompileError>;

pub(super) fn ok_dispatch(gas: u64, ret: Vec<u8>, logs: Vec<Log>) -> DispatchResult {
    DispatchResult {
        precompile: ok_output(gas, ret),
        logs,
        refusal: None,
    }
}

/// A revert carrying the refusal's message as its data, charging no gas.
pub(crate) fn err_dispatch(e: impl Refuse) -> DispatchResult {
    DispatchResult {
        precompile: PrecompileOutput::revert(0, Bytes::from(e.to_string().into_bytes()), 0),
        logs: vec![],
        refusal: Some(e.refusal_kind()),
    }
}

/// A revert for a successful call whose records exceed the native storage bounds.
pub(crate) fn storage_bounds_dispatch(gas_used: u64) -> DispatchResult {
    let mut rejected = err_dispatch(Stated(
        RefusalKind::StorageBounds,
        "module record exceeds native storage bounds",
    ));
    rejected.precompile.gas_used = gas_used;
    rejected
}

pub(super) fn event_log<E: alloy_sol_types::SolEvent>(address: Address, event: &E) -> Log {
    Log {
        address,
        data: event.encode_log_data(),
    }
}

/// Route calldata to the module at the target address.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_to_module(
    acp: &mut AcpModule,
    bulletin: &mut BulletinModule,
    vera: &mut VeraModule,
    target: Address,
    calldata: &[u8],
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    gas_limit: u64,
) -> Option<DispatchReturn> {
    if target == ACP_ADDRESS {
        Some(acp::dispatch(
            acp, vera, block_ctx, tx_ctx, calldata, gas_limit,
        ))
    } else if target == BULLETIN_ADDRESS {
        Some(bulletin::dispatch(
            bulletin, acp, block_ctx, tx_ctx, calldata, gas_limit,
        ))
    } else if target == VERA_ADDRESS {
        Some(vera::dispatch(
            vera, acp, block_ctx, tx_ctx, calldata, gas_limit,
        ))
    } else if target == ANCHOR_ADDRESS {
        Some(anchor::dispatch(vera, block_ctx, calldata, gas_limit))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_missing_signer_is_a_refusal_and_a_malformed_one_a_fault() {
        let missing = did_from_signer("").unwrap_err();
        assert_eq!(internal_fault_reason(&missing), None);
        assert_eq!(recoverable_message(&missing), UNAUTHENTICATED_CALLER);
        assert_eq!(refusal::kind_of(&missing), RefusalKind::Unauthenticated);

        let malformed = did_from_signer("not-a-did").unwrap_err();
        assert!(internal_fault_reason(&malformed).is_some());
    }

    #[test]
    fn precompile_addresses_are_nonzero() {
        assert_ne!(ACP_ADDRESS, Address::ZERO);
        assert_ne!(BULLETIN_ADDRESS, Address::ZERO);
        assert_ne!(VERA_ADDRESS, Address::ZERO);
        assert_ne!(VALIDATOR_REGISTRY_ADDRESS, Address::ZERO);
    }

    #[test]
    fn precompile_addresses_are_distinct() {
        let addrs = [
            ACP_ADDRESS,
            BULLETIN_ADDRESS,
            VERA_ADDRESS,
            VALIDATOR_REGISTRY_ADDRESS,
        ];
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j]);
            }
        }
    }

    #[test]
    fn precompile_addresses_are_l2_convention() {
        assert_eq!(
            ACP_ADDRESS,
            "0x0000000000000000000000000000000000000810"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            BULLETIN_ADDRESS,
            "0x0000000000000000000000000000000000000811"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            VERA_ADDRESS,
            "0x0000000000000000000000000000000000000812"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            VALIDATOR_REGISTRY_ADDRESS,
            "0x0000000000000000000000000000000000000813"
                .parse::<Address>()
                .unwrap()
        );
    }
}
