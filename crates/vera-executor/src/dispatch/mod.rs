//! Module call shims: ABI dispatch for the ACP, bulletin, vera, validator
//! registry and anchor modules.
//!
//! Module addresses:
//! - `0x0810` — ACP (access control policies)
//! - `0x0811` — Bulletin (coordination / DKG messages)
//! - `0x0812` — Vera (identity / JWS token lifecycle)
//! - `0x0813` — ValidatorRegistry (validator identity management)
//! - `0x0814` — Anchor (finalized revisions of other deployments)

mod acp;
mod anchor;
mod bulletin;
mod output;
pub(crate) mod refusal;
pub(crate) mod validator_registry;
mod vera;

pub use output::{ModuleError, ModuleOutput, ModuleStatus};
use refusal::{Refuse, Stated};
use vera_domain::RefusalKind;

use alloy_primitives::{Address, Bytes, Log};
use vera_identity::Did;
use vera_modules::acp::AcpModule;
use vera_modules::bulletin::BulletinModule;
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::validator_registry::MembershipLimits;
use vera_modules::vera::VeraModule;

/// ACP module address.
pub const ACP_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x10);

/// Bulletin module address.
pub const BULLETIN_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x11);

/// Vera module address.
pub const VERA_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x12);

/// Anchor module address.
pub const ANCHOR_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x14);

/// Validator registry module address.
pub const VALIDATOR_REGISTRY_ADDRESS: Address = vera_modules::validator_registry::ADDRESS;

const fn address_from_last_two_bytes(hi: u8, lo: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = hi;
    bytes[19] = lo;
    Address::new(bytes)
}

pub(super) fn did_from_signer(signer: &str) -> Result<Did, ModuleError> {
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

/// A fault of the node, which fails the block.
pub(crate) fn internal_fault(reason: impl core::fmt::Display) -> ModuleError {
    ModuleError::Fault(reason.to_string())
}

pub(super) fn decode_error(e: alloy_sol_types::Error) -> ModuleError {
    refusal::refused(RefusalKind::UndecodableInput, format!("ABI decode: {e}"))
}

/// A call naming no method of its module.
pub(super) fn unknown_selector(module: &str, selector: [u8; 4]) -> ModuleError {
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

pub(super) const fn oog_dispatch() -> DispatchResult {
    DispatchResult {
        output: ModuleOutput::out_of_gas(),
        logs: vec![],
        refusal: None,
    }
}

/// A revert carrying a refusal raised as an error, with its kind.
pub(crate) fn refusal_dispatch(error: &ModuleError) -> DispatchResult {
    err_dispatch(Stated(refusal::kind_of(error), error.to_string()))
}

/// Result of dispatching to a vera module, including any emitted event logs.
#[derive(Debug)]
pub struct DispatchResult {
    /// Status, gas and return data of the call.
    pub output: ModuleOutput,
    /// Event logs emitted during the dispatch.
    pub logs: Vec<Log>,
    /// What the module refused, for a revert.
    pub refusal: Option<RefusalKind>,
}

/// Return type for module dispatch functions.
pub type DispatchReturn = Result<DispatchResult, ModuleError>;

pub(super) fn ok_dispatch(gas: u64, ret: Vec<u8>, logs: Vec<Log>) -> DispatchResult {
    DispatchResult {
        output: ModuleOutput::success(gas, ret.into()),
        logs,
        refusal: None,
    }
}

/// A revert carrying the refusal's message as its data, charging no gas.
pub(crate) fn err_dispatch(e: impl Refuse) -> DispatchResult {
    DispatchResult {
        output: ModuleOutput::revert(0, Bytes::from(e.to_string().into_bytes())),
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
    rejected.output.gas_used = gas_used;
    rejected
}

pub(super) fn event_log<E: alloy_sol_types::SolEvent>(address: Address, event: &E) -> Log {
    Log {
        address,
        data: event.encode_log_data(),
    }
}

/// Route calldata to the module at the target address, or `None` when the
/// target is not a module.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_to_module(
    acp: &mut AcpModule,
    bulletin: &mut BulletinModule,
    vera: &mut VeraModule,
    target: Address,
    calldata: &[u8],
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    limits: MembershipLimits,
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
    } else if target == VALIDATOR_REGISTRY_ADDRESS {
        Some(validator_registry::dispatch(
            vera, acp, limits, block_ctx, tx_ctx, calldata, gas_limit,
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_missing_signer_is_a_refusal_and_a_malformed_one_a_fault() {
        assert_eq!(
            did_from_signer("").unwrap_err(),
            refusal::refused(RefusalKind::Unauthenticated, UNAUTHENTICATED_CALLER)
        );
        assert!(matches!(
            did_from_signer("not-a-did").unwrap_err(),
            ModuleError::Fault(_)
        ));
    }

    #[test]
    fn module_addresses_are_nonzero() {
        assert_ne!(ACP_ADDRESS, Address::ZERO);
        assert_ne!(BULLETIN_ADDRESS, Address::ZERO);
        assert_ne!(VERA_ADDRESS, Address::ZERO);
        assert_ne!(VALIDATOR_REGISTRY_ADDRESS, Address::ZERO);
    }

    #[test]
    fn module_addresses_are_distinct() {
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
    fn module_addresses_are_fixed() {
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
