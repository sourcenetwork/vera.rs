//! Validator registry dispatch — ABI decode/encode for all `IValidatorRegistry` selectors.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use commonware_codec::ReadExt as _;
use vera_modules::acp::AcpModule;
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::validator_registry::abi::IValidatorRegistry;
use vera_modules::validator_registry::error::ValidatorRegistryError;
use vera_modules::validator_registry::types::ValidatorInfo;
use vera_modules::validator_registry::{MemberRecord, MembershipLimits};
use vera_modules::vera::VeraModule;

use super::{
    DispatchResult, DispatchReturn, ModuleError, VALIDATOR_REGISTRY_ADDRESS, decode_error,
    did_from_signer, err_dispatch, event_log, internal_fault, json_bytes, ok_dispatch,
    oog_dispatch,
};

const ADD_VALIDATOR_GAS: u64 = 150_000;
const REMOVE_VALIDATOR_GAS: u64 = 150_000;
const SET_STATUS_GAS: u64 = 50_000;
const UPDATE_P2P_GAS: u64 = 60_000;
const GET_VALIDATOR_GAS: u64 = 15_000;
const GET_VALIDATORS_GAS: u64 = 20_000;
const GET_ACTIVE_COUNT_GAS: u64 = 10_000;
const INPUT_COST_PER_WORD: u64 = 6;

const fn input_cost(calldata_len: usize) -> u64 {
    calldata_len.div_ceil(32) as u64 * INPUT_COST_PER_WORD
}

fn valid_consensus_key(key: &[u8; 32]) -> bool {
    vera_domain::PublicKey::read(&mut commonware_codec::Copying(key.as_slice())).is_ok()
}

/// Unreadable registry state is the node's fault; anything else refuses the request.
fn settle(
    result: Result<(), ValidatorRegistryError>,
    done: impl FnOnce() -> DispatchResult,
) -> DispatchReturn {
    match result {
        Ok(()) => Ok(done()),
        Err(error) => refuse(error),
    }
}

fn refuse(error: ValidatorRegistryError) -> DispatchReturn {
    match error {
        ValidatorRegistryError::Corrupt(reason) => Err(internal_fault(reason)),
        error => Ok(err_dispatch(error)),
    }
}

fn read<T>(result: Result<T, ValidatorRegistryError>) -> Result<T, ModuleError> {
    result.map_err(|error| internal_fault(error.to_string()))
}

fn info(address: Address, member: MemberRecord) -> ValidatorInfo {
    ValidatorInfo {
        address: format!("{address:?}"),
        consensus_pubkey: hex::encode(member.consensus_key),
        p2p_address: member.p2p_address,
        active: member.active,
        address_sequence: member.address_sequence,
    }
}

/// Consensus keys of the active members, sorted, for the roster an epoch
/// boundary records.
pub(crate) fn active_consensus_keys(vera: &VeraModule) -> Result<Vec<[u8; 32]>, ModuleError> {
    let keys = read(vera.active_consensus_keys())?;
    if !keys.iter().all(valid_consensus_key) {
        return Err(internal_fault("invalid consensus key"));
    }
    Ok(keys)
}

/// Dispatch an ABI-encoded call to the validator registry by selector.
pub(super) fn dispatch(
    vera: &mut VeraModule,
    acp: &AcpModule,
    limits: MembershipLimits,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    if input.len() < 4 {
        return Ok(super::short_input());
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");
    let charged = |base: u64| base + input_cost(input.len());
    let event = |gas: u64, log| ok_dispatch(gas, Vec::new(), vec![log]);

    match selector {
        IValidatorRegistry::addValidatorCall::SELECTOR => {
            let gas = charged(ADD_VALIDATOR_GAS);
            if gas_limit < gas {
                return Ok(oog_dispatch());
            }
            let call =
                IValidatorRegistry::addValidatorCall::abi_decode(input).map_err(decode_error)?;
            let caller = did_from_signer(&tx_ctx.signer)?;
            if !valid_consensus_key(&call.consensusPubkey.0) {
                return Ok(err_dispatch(ValidatorRegistryError::InvalidPublicKey));
            }
            let added = vera.add_validator(
                acp,
                &caller,
                limits,
                call.validator,
                call.consensusPubkey.0,
                &call.p2pAddr,
            );
            settle(added, || {
                event(
                    gas,
                    event_log(
                        VALIDATOR_REGISTRY_ADDRESS,
                        &IValidatorRegistry::ValidatorAdded {
                            validator: call.validator,
                            consensusPubkey: call.consensusPubkey,
                        },
                    ),
                )
            })
        }

        IValidatorRegistry::removeValidatorCall::SELECTOR => {
            let gas = charged(REMOVE_VALIDATOR_GAS);
            if gas_limit < gas {
                return Ok(oog_dispatch());
            }
            let call =
                IValidatorRegistry::removeValidatorCall::abi_decode(input).map_err(decode_error)?;
            let caller = did_from_signer(&tx_ctx.signer)?;
            settle(vera.remove_validator(acp, &caller, call.validator), || {
                event(
                    gas,
                    event_log(
                        VALIDATOR_REGISTRY_ADDRESS,
                        &IValidatorRegistry::ValidatorRemoved {
                            validator: call.validator,
                        },
                    ),
                )
            })
        }

        IValidatorRegistry::setValidatorStatusCall::SELECTOR => {
            let gas = charged(SET_STATUS_GAS);
            if gas_limit < gas {
                return Ok(oog_dispatch());
            }
            let call = IValidatorRegistry::setValidatorStatusCall::abi_decode(input)
                .map_err(decode_error)?;
            let caller = did_from_signer(&tx_ctx.signer)?;
            let changed =
                vera.set_validator_status(acp, &caller, limits, call.validator, call.active);
            settle(changed, || {
                event(
                    gas,
                    event_log(
                        VALIDATOR_REGISTRY_ADDRESS,
                        &IValidatorRegistry::ValidatorStatusChanged {
                            validator: call.validator,
                            active: call.active,
                        },
                    ),
                )
            })
        }

        IValidatorRegistry::updateP2PAddressCall::SELECTOR => {
            let gas = charged(UPDATE_P2P_GAS);
            if gas_limit < gas {
                return Ok(oog_dispatch());
            }
            let call = IValidatorRegistry::updateP2PAddressCall::abi_decode(input)
                .map_err(decode_error)?;
            // The validator's consensus key authorizes the change; the
            // submitter only has to be an authenticated native signer.
            did_from_signer(&tx_ctx.signer)?;
            let updated = vera.update_p2p_address(
                &block_ctx.genesis_id,
                call.validator,
                &call.p2pAddr,
                call.sequence,
                &call.signature,
            );
            settle(updated, || {
                event(
                    gas,
                    event_log(
                        VALIDATOR_REGISTRY_ADDRESS,
                        &IValidatorRegistry::ValidatorUpdated {
                            validator: call.validator,
                        },
                    ),
                )
            })
        }

        IValidatorRegistry::getValidatorsCall::SELECTOR => {
            let gas = charged(GET_VALIDATORS_GAS);
            if gas_limit < gas {
                return Ok(oog_dispatch());
            }
            let validators: Vec<_> = read(vera.registry_members())?
                .into_iter()
                .map(|(address, member)| info(address, member))
                .collect();
            let ret =
                IValidatorRegistry::getValidatorsCall::abi_encode_returns(&json_bytes(&validators));
            Ok(ok_dispatch(gas, ret, vec![]))
        }

        IValidatorRegistry::getValidatorCall::SELECTOR => {
            let gas = charged(GET_VALIDATOR_GAS);
            if gas_limit < gas {
                return Ok(oog_dispatch());
            }
            let call =
                IValidatorRegistry::getValidatorCall::abi_decode(input).map_err(decode_error)?;
            let validator = read(vera.registry_member(call.validator))?
                .map(|member| info(call.validator, member));
            let ret =
                IValidatorRegistry::getValidatorCall::abi_encode_returns(&json_bytes(&validator));
            Ok(ok_dispatch(gas, ret, vec![]))
        }

        IValidatorRegistry::getActiveValidatorCountCall::SELECTOR => {
            let gas = charged(GET_ACTIVE_COUNT_GAS);
            if gas_limit < gas {
                return Ok(oog_dispatch());
            }
            let active = read(vera.registry_members())?
                .iter()
                .filter(|(_, member)| member.active)
                .count();
            let ret = IValidatorRegistry::getActiveValidatorCountCall::abi_encode_returns(
                &U256::from(active),
            );
            Ok(ok_dispatch(gas, ret, vec![]))
        }

        _ => Err(super::unknown_selector("ValidatorRegistry", selector)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_cost_rounds_up_words() {
        assert_eq!(input_cost(0), 0);
        assert_eq!(input_cost(1), INPUT_COST_PER_WORD);
        assert_eq!(input_cost(32), INPUT_COST_PER_WORD);
        assert_eq!(input_cost(33), INPUT_COST_PER_WORD * 2);
        assert_eq!(input_cost(64), INPUT_COST_PER_WORD * 2);
    }
}
