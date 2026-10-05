//! Vera precompiles — ABI dispatch for ACP, Bulletin, Vera, and ValidatorRegistry modules.
//!
//! L2-convention addresses:
//! - `0x0810` — ACP (access control policies)
//! - `0x0811` — Bulletin (coordination / DKG messages)
//! - `0x0812` — Vera (identity / JWS token lifecycle)
//! - `0x0813` — ValidatorRegistry (validator identity management)

mod acp;
mod bulletin;
pub(crate) mod validator_registry;
mod vera;

use std::sync::{Arc, Mutex};

mod journal;
pub use journal::ModuleInspector;
use journal::ModuleJournal;

use alloy_primitives::{Address, B256, Bytes, Log};
use identity::Did;
use revm::{
    context::Cfg,
    context_interface::{Block, ContextTr, JournalTr, Transaction},
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{CallInputs, InterpreterResult},
    precompile::{
        Precompile, PrecompileError, PrecompileId, PrecompileOutput, PrecompileResult, Precompiles,
    },
    primitives::hardfork::SpecId,
};
use vera_modules::acp::AcpModule;
use vera_modules::bulletin::BulletinModule;
use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};
use vera_modules::vera::VeraModule;

/// ACP precompile address.
pub const ACP_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x10);

/// Bulletin precompile address.
pub const BULLETIN_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x11);

/// Vera precompile address.
pub const VERA_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x12);

/// ValidatorRegistry precompile address.
pub const VALIDATOR_REGISTRY_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x13);

const fn address_from_last_two_bytes(hi: u8, lo: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = hi;
    bytes[19] = lo;
    Address::new(bytes)
}

pub(super) fn did_from_signer(signer: &str) -> Result<Did, PrecompileError> {
    Did::new(signer).map_err(|e| PrecompileError::Other(format!("DID: {e}").into()))
}

pub(super) fn decode_error(e: alloy_sol_types::Error) -> PrecompileError {
    PrecompileError::Other(format!("ABI decode: {e}").into())
}

pub(super) fn module_error(e: impl core::fmt::Display) -> PrecompileOutput {
    PrecompileOutput {
        gas_used: 0,
        gas_refunded: 0,
        bytes: Bytes::from(e.to_string().into_bytes()),
        reverted: true,
    }
}

pub(super) fn json_bytes(v: &impl serde::Serialize) -> Bytes {
    Bytes::from(serde_json::to_vec(v).unwrap_or_default())
}

pub(super) fn ok_output(gas: u64, ret: Vec<u8>) -> PrecompileOutput {
    PrecompileOutput {
        gas_used: gas,
        gas_refunded: 0,
        bytes: ret.into(),
        reverted: false,
    }
}

/// Result of dispatching to a vera module, including any emitted event logs.
#[derive(Debug)]
pub struct DispatchResult {
    /// The precompile output (gas, return data, revert status).
    pub precompile: PrecompileOutput,
    /// EVM-compatible logs emitted during the dispatch.
    pub logs: Vec<Log>,
}

/// Return type for module dispatch functions.
pub type DispatchReturn = Result<DispatchResult, PrecompileError>;

pub(super) fn ok_dispatch(gas: u64, ret: Vec<u8>, logs: Vec<Log>) -> DispatchResult {
    DispatchResult {
        precompile: ok_output(gas, ret),
        logs,
    }
}

pub(super) fn err_dispatch(e: impl core::fmt::Display) -> DispatchResult {
    DispatchResult {
        precompile: module_error(e),
        logs: vec![],
    }
}

pub(super) fn event_log<E: alloy_sol_types::SolEvent>(address: Address, event: &E) -> Log {
    Log {
        address,
        data: event.encode_log_data(),
    }
}

const fn stub_precompile(_input: &[u8], _gas_limit: u64) -> PrecompileResult {
    Ok(PrecompileOutput {
        gas_used: 0,
        gas_refunded: 0,
        bytes: revm::primitives::Bytes::new(),
        reverted: true,
    })
}

/// Vera precompile provider that extends standard Ethereum precompiles
/// with ABI-dispatching precompiles for ACP, Bulletin, and Vera modules.
#[derive(Debug)]
pub struct VeraPrecompiles {
    eth: EthPrecompiles,
    custom: Precompiles,
    journal: Arc<Mutex<ModuleJournal>>,
    current_tx_hash: B256,
    current_signer_did: String,
    genesis_id: [u8; 32],
    max_active_members: u32,
}

/// Route calldata to the appropriate module based on the target precompile address.
///
/// Used by both the EVM precompile path and the native BLS tx path to ensure
/// both converge on the same module methods.
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
    } else {
        None
    }
}

fn new_custom_precompiles() -> Precompiles {
    let mut custom = Precompiles::default();
    custom.extend([
        Precompile::new(PrecompileId::custom("acp"), ACP_ADDRESS, stub_precompile),
        Precompile::new(
            PrecompileId::custom("bulletin"),
            BULLETIN_ADDRESS,
            stub_precompile,
        ),
        Precompile::new(PrecompileId::custom("vera"), VERA_ADDRESS, stub_precompile),
        Precompile::new(
            PrecompileId::custom("validator_registry"),
            VALIDATOR_REGISTRY_ADDRESS,
            stub_precompile,
        ),
    ]);
    custom
}

impl VeraPrecompiles {
    /// Create a new vera precompile provider for the given spec.
    pub fn new(spec: SpecId) -> Self {
        Self {
            eth: EthPrecompiles::new(spec),
            custom: new_custom_precompiles(),
            journal: Arc::default(),
            current_tx_hash: B256::ZERO,
            current_signer_did: String::new(),
            genesis_id: [0; 32],
            max_active_members: vera_domain::MAX_DKG_PARTICIPANTS.get(),
        }
    }

    /// Create a vera precompile provider with pre-built module instances.
    pub fn with_modules(
        spec: SpecId,
        acp_module: AcpModule,
        bulletin_module: BulletinModule,
        vera_module: VeraModule,
    ) -> Self {
        Self {
            eth: EthPrecompiles::new(spec),
            custom: new_custom_precompiles(),
            journal: Arc::new(Mutex::new(ModuleJournal::new((
                acp_module,
                bulletin_module,
                vera_module,
            )))),
            current_tx_hash: B256::ZERO,
            current_signer_did: String::new(),
            genesis_id: [0; 32],
            max_active_members: vera_domain::MAX_DKG_PARTICIPANTS.get(),
        }
    }

    /// Enforce the configured epoch capacity on membership commands.
    #[must_use]
    pub const fn with_membership_limit(mut self, limit: u32) -> Self {
        self.max_active_members = limit;
        self
    }

    /// Bind administrative approvals to the deployment genesis record.
    #[must_use]
    pub const fn with_genesis_id(mut self, genesis_id: [u8; 32]) -> Self {
        self.genesis_id = genesis_id;
        self
    }

    /// Set the tx hash for the current EVM transaction being executed.
    pub const fn set_tx_hash(&mut self, tx_hash: B256) {
        self.current_tx_hash = tx_hash;
    }

    /// Set the signer DID for the current EVM transaction being executed.
    pub fn set_signer_did(&mut self, did: String) {
        self.current_signer_did = did;
    }

    /// Inspector required to align module mutations with call-frame outcomes.
    pub fn inspector(&self) -> ModuleInspector {
        ModuleInspector(self.journal.clone())
    }

    /// Retain a transaction checkpoint through post-execution validation.
    pub fn begin_transaction(&self) {
        self.journal.lock().unwrap().begin();
    }

    /// Commit or restore module changes after the complete execution result.
    pub fn finish_transaction(&self, success: bool) {
        self.journal.lock().unwrap().finish(success);
    }

    /// Extract module state after block execution.
    pub fn take_modules(self) -> (AcpModule, BulletinModule, VeraModule) {
        let mut journal = self.journal.lock().unwrap();
        journal.finish(true);
        std::mem::take(&mut journal.modules)
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for VeraPrecompiles {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.eth, spec)
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        if self.custom.contains(&inputs.bytecode_address) {
            let block = context.block();
            let block_ctx = BlockExecCtx {
                genesis_id: self.genesis_id,
                deployment_id: context.cfg().chain_id(),
                timestamp: Timestamp {
                    seconds: block.timestamp().as_limbs()[0],
                    block_height: block.number().as_limbs()[0],
                },
            };
            let direct_caller = inputs.caller == context.tx().caller();
            let tx_ctx = TxExecCtx {
                sequence: context.tx().nonce(),
                tx_hash: self.current_tx_hash.to_vec(),
                // A contract cannot inherit the submitting key's module authority.
                signer: if direct_caller {
                    self.current_signer_did.clone()
                } else {
                    String::new()
                },
            };
            let calldata = inputs.input.bytes(context);

            if inputs.bytecode_address == VALIDATOR_REGISTRY_ADDRESS {
                if !direct_caller && !validator_registry::is_query(&calldata) {
                    return Self::dispatch_result_to_interpreter(
                        inputs,
                        Err(PrecompileError::Other(
                            "module write requires an authenticated caller".into(),
                        )),
                    )
                    .map(|(result, _)| result);
                }
                if inputs.is_static && !validator_registry::is_query(&calldata) {
                    return Ok(Some(Self::static_write_error(inputs)));
                }
                let journal = self.journal.lock().unwrap();
                let dispatch_result = validator_registry::dispatch_with_journal(
                    context,
                    &journal.modules.0,
                    &journal.modules.2,
                    self.max_active_members,
                    &tx_ctx,
                    &calldata,
                    inputs.gas_limit,
                );
                let (result, logs) = Self::dispatch_result_to_interpreter(inputs, dispatch_result)?;
                for log in logs {
                    context.journal_mut().log(log);
                }
                return Ok(result);
            }

            let (result, logs) = self.run_custom(inputs, &calldata, &block_ctx, &tx_ctx)?;
            for log in logs {
                context.journal_mut().log(log);
            }
            return Ok(result);
        }
        self.eth.run(context, inputs)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let eth_addrs: Vec<Address> = self.eth.warm_addresses().collect();
        let custom_addrs: Vec<Address> = self.custom.addresses().cloned().collect();
        Box::new(eth_addrs.into_iter().chain(custom_addrs))
    }

    fn contains(&self, address: &Address) -> bool {
        self.eth.contains(address) || self.custom.contains(address)
    }
}

impl VeraPrecompiles {
    fn dispatch_result_to_interpreter(
        inputs: &CallInputs,
        dispatch_result: DispatchReturn,
    ) -> Result<(Option<InterpreterResult>, Vec<Log>), String> {
        use revm::interpreter::{Gas, InstructionResult};

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(inputs.gas_limit),
            output: revm::primitives::Bytes::new(),
        };
        match dispatch_result {
            Ok(dr) => {
                result.gas.record_refund(dr.precompile.gas_refunded);
                if !result.gas.record_cost(dr.precompile.gas_used) {
                    result.result = InstructionResult::PrecompileOOG;
                    return Ok((Some(result), vec![]));
                }
                result.result = if dr.precompile.reverted {
                    InstructionResult::Revert
                } else {
                    InstructionResult::Return
                };
                result.output = dr.precompile.bytes;
                let logs = if dr.precompile.reverted {
                    vec![]
                } else {
                    dr.logs
                };
                Ok((Some(result), logs))
            }
            Err(revm::precompile::PrecompileError::Fatal(e)) => Err(e),
            Err(e) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
                Ok((Some(result), vec![]))
            }
        }
    }

    const fn static_write_error(inputs: &CallInputs) -> InterpreterResult {
        InterpreterResult {
            result: revm::interpreter::InstructionResult::StateChangeDuringStaticCall,
            gas: revm::interpreter::Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        }
    }

    fn run_custom(
        &mut self,
        inputs: &CallInputs,
        calldata: &[u8],
        block_ctx: &BlockExecCtx,
        tx_ctx: &TxExecCtx,
    ) -> Result<(Option<InterpreterResult>, Vec<Log>), String> {
        let mut journal = self.journal.lock().unwrap();
        journal.checkpoint()?;
        let (acp, bulletin, vera) = &mut journal.modules;
        let mut dispatch_result =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dispatch_to_module(
                    acp,
                    bulletin,
                    vera,
                    inputs.bytecode_address,
                    calldata,
                    block_ctx,
                    tx_ctx,
                    inputs.gas_limit,
                )
            })) {
                Ok(Some(result)) => result,
                Ok(None) => return Ok((None, vec![])),
                Err(_) => {
                    tracing::warn!("module call panicked");
                    Err(PrecompileError::Other("module execution failed".into()))
                }
            };

        if inputs.is_static && journal.changed() {
            return Ok((Some(Self::static_write_error(inputs)), vec![]));
        }
        if matches!(&dispatch_result, Ok(result) if !result.precompile.reverted)
            && !journal.writes_fit_native_bounds()
        {
            dispatch_result = Err(PrecompileError::Other(
                "module record exceeds native storage bounds".into(),
            ));
        }
        Self::dispatch_result_to_interpreter(inputs, dispatch_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{database::EmptyDB, handler::MainnetContext};

    type TestCtx = MainnetContext<EmptyDB>;

    fn test_precompiles() -> VeraPrecompiles {
        VeraPrecompiles::new(SpecId::CANCUN)
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

    #[test]
    fn vera_precompiles_contains_custom() {
        let precompiles = test_precompiles();
        assert!(<VeraPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &ACP_ADDRESS
        ));
        assert!(<VeraPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &BULLETIN_ADDRESS
        ));
        assert!(<VeraPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &VERA_ADDRESS
        ));
        assert!(<VeraPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &VALIDATOR_REGISTRY_ADDRESS
        ));
    }

    #[test]
    fn vera_precompiles_contains_standard() {
        let ecrecover = "0x0000000000000000000000000000000000000001"
            .parse::<Address>()
            .unwrap();
        let precompiles = test_precompiles();
        assert!(<VeraPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &ecrecover
        ));
    }

    #[test]
    fn vera_precompiles_warm_addresses_include_custom() {
        let precompiles = test_precompiles();
        let warm: Vec<Address> =
            <VeraPrecompiles as PrecompileProvider<TestCtx>>::warm_addresses(&precompiles)
                .collect();
        assert!(warm.contains(&ACP_ADDRESS));
        assert!(warm.contains(&BULLETIN_ADDRESS));
        assert!(warm.contains(&VERA_ADDRESS));
        assert!(warm.contains(&VALIDATOR_REGISTRY_ADDRESS));
    }
}
