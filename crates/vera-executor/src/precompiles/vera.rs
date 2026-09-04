//! Vera precompile dispatch — ABI decode/encode for all IVera selectors.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use identity::Did;
use revm::precompile::PrecompileError;
use vera_modules::acp::AcpModule;
use vera_modules::types::{BlockExecCtx, TxExecCtx};
use vera_modules::vera::VeraModule;
use vera_modules::vera::abi::IVera;
use vera_modules::vera::administration::SignedAdministrativeRequest;

use super::{
    DispatchReturn, VERA_ADDRESS, decode_error, did_from_signer, err_dispatch, event_log,
    json_bytes, ok_dispatch, oog_dispatch,
};

/// Flat gas cost for read operations (real metering is Phase 10).
const READ_GAS: u64 = 1000;
/// Flat gas cost for write operations (real metering is Phase 10).
const WRITE_GAS: u64 = 5000;

/// Dispatch an ABI-encoded call to the Vera module by selector.
pub(super) fn dispatch(
    module: &mut VeraModule,
    acp: &mut AcpModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    if input.len() < 4 {
        return Ok(err_dispatch("input too short for selector"));
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");

    match selector {
        IVera::storeThresholdObjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Ok(oog_dispatch());
            }
            let call = IVera::storeThresholdObjectCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > vera_modules::vera::objects::MAX_OBJECT_REQUEST_BYTES {
                return Err(PrecompileError::Fatal(
                    "object request is too large".to_string(),
                ));
            }
            let object = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
            match module.store_threshold_object(acp, block_ctx, tx_ctx, &call.bearerToken, &object)
            {
                Ok(record) => Ok(ok_dispatch(
                    WRITE_GAS,
                    IVera::storeThresholdObjectCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IVera::applyRingCommandCall::SELECTOR => {
            if gas_limit < 500_000 {
                return Ok(oog_dispatch());
            }
            let call = IVera::applyRingCommandCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > vera_modules::vera::rings::MAX_RING_REQUEST_BYTES {
                return Err(PrecompileError::Fatal(
                    "ring command is too large".to_string(),
                ));
            }
            let command = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
            match module.apply_ring_command(acp, block_ctx, tx_ctx, &call.bearerToken, &command) {
                Ok(record) => Ok(ok_dispatch(
                    500_000,
                    IVera::applyRingCommandCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IVera::applyRingParticipantRequestCall::SELECTOR => {
            if gas_limit < 100_000 {
                return Ok(oog_dispatch());
            }
            let call =
                IVera::applyRingParticipantRequestCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > vera_modules::vera::rings::MAX_RING_REQUEST_BYTES {
                return Err(PrecompileError::Fatal(
                    "ring request is too large".to_string(),
                ));
            }
            let signed = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
            match module.apply_ring_participant_request(block_ctx, &signed) {
                Ok(record) => Ok(ok_dispatch(
                    100_000,
                    IVera::applyRingParticipantRequestCall::abi_encode_returns(&json_bytes(
                        &record,
                    )),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IVera::finalizeRingReshareCall::SELECTOR => {
            if gas_limit < 500_000 {
                return Ok(oog_dispatch());
            }
            let call = IVera::finalizeRingReshareCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > vera_modules::vera::rings::MAX_RING_REQUEST_BYTES {
                return Err(PrecompileError::Fatal(
                    "ring request is too large".to_string(),
                ));
            }
            let signed = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
            match module.finalize_ring_reshare(block_ctx, &signed) {
                Ok(record) => Ok(ok_dispatch(
                    500_000,
                    IVera::finalizeRingReshareCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IVera::submitRingReportCall::SELECTOR => {
            if gas_limit < 500_000 {
                return Ok(oog_dispatch());
            }
            let call = IVera::submitRingReportCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > vera_modules::vera::rings::reports::MAX_REPORT_REQUEST_BYTES {
                return Err(PrecompileError::Fatal(
                    "ring request is too large".to_string(),
                ));
            }
            let signed = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
            match module.submit_ring_report(block_ctx, &signed) {
                Ok(record) => Ok(ok_dispatch(
                    500_000,
                    IVera::submitRingReportCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IVera::applyNodeRequestCall::SELECTOR => {
            if gas_limit < 100_000 {
                return Ok(oog_dispatch());
            }
            let call = IVera::applyNodeRequestCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > vera_modules::vera::nodes::MAX_NODE_BYTES {
                return Err(PrecompileError::Fatal(
                    "node request is too large".to_string(),
                ));
            }
            let signed = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
            match module.apply_node_request(block_ctx, &signed) {
                Ok(record) => Ok(ok_dispatch(
                    100_000,
                    IVera::applyNodeRequestCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IVera::applyAdministrationCall::SELECTOR => {
            if gas_limit < 500_000 {
                return Ok(oog_dispatch());
            }
            let call = IVera::applyAdministrationCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > 32_768 {
                return Err(PrecompileError::Fatal(
                    "administrative request is too large".to_string(),
                ));
            }
            let signed: SignedAdministrativeRequest = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
            match module.apply_administrative_request(
                acp,
                block_ctx.genesis_id,
                block_ctx.timestamp.seconds,
                &signed,
            ) {
                Ok(()) => Ok(ok_dispatch(500_000, Vec::new(), vec![])),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IVera::getAdministrationCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
            }
            match module.administration() {
                Ok(state) => Ok(ok_dispatch(
                    READ_GAS,
                    IVera::getAdministrationCall::abi_encode_returns(&json_bytes(&state)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        // ── Write methods ────────────────────────────────────────────
        IVera::revokeDelegationCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Ok(oog_dispatch());
            }
            let call = IVera::revokeDelegationCall::abi_decode(input).map_err(decode_error)?;
            let caller = did_from_signer(&tx_ctx.signer)?;
            let record = match module.revoke_delegation(block_ctx, &caller, &call.token) {
                Ok(record) => record,
                Err(error) => return Ok(err_dispatch(error)),
            };
            let event = IVera::JWSTokenInvalidated {
                tokenHash: alloy_primitives::keccak256(record.token_hash.as_bytes()),
                issuerDid: record.issuer_did,
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(VERA_ADDRESS, &event)],
            ))
        }
        IVera::invalidateJWSCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Ok(oog_dispatch());
            }
            let call = IVera::invalidateJWSCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;

            let record = match module.invalidate_jws(block_ctx, tx_ctx, &creator, &call.tokenHash) {
                Ok(record) => record,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let event = IVera::JWSTokenInvalidated {
                tokenHash: alloy_primitives::keccak256(call.tokenHash.as_bytes()),
                issuerDid: record.issuer_did,
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(VERA_ADDRESS, &event)],
            ))
        }

        IVera::updateParamsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Ok(oog_dispatch());
            }
            let call = IVera::updateParamsCall::abi_decode(input).map_err(decode_error)?;
            let authority = did_from_signer(&tx_ctx.signer)?;
            let params: vera_modules::vera::types::VeraParams =
                serde_json::from_slice(&call.params)
                    .map_err(|e| PrecompileError::Fatal(format!("params JSON decode: {e}")))?;

            match module.update_params(&authority, params) {
                Ok(()) => {}
                Err(e) => return Ok(err_dispatch(e)),
            }

            Ok(ok_dispatch(WRITE_GAS, Vec::new(), vec![]))
        }

        // ── Read methods ─────────────────────────────────────────────
        IVera::getJWSTokenCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
            }
            let call = IVera::getJWSTokenCall::abi_decode(input).map_err(decode_error)?;

            let record = match module.get_jws_token(&call.tokenHash) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let (found, record_bytes) = record
                .as_ref()
                .map_or_else(|| (false, Bytes::new()), |r| (true, json_bytes(r)));

            let ret = IVera::getJWSTokenCall::abi_encode_returns(&IVera::getJWSTokenReturn {
                found,
                record: record_bytes,
            });
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IVera::getJWSTokensByDidCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
            }
            let call = IVera::getJWSTokensByDidCall::abi_decode(input).map_err(decode_error)?;
            let did = Did::new(&call.did)
                .map_err(|e| PrecompileError::Fatal(format!("DID parse: {e}")))?;

            let tokens = match module.get_jws_tokens_by_did(&did) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IVera::getJWSTokensByDidCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IVera::getJWSTokensByAccountCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
            }
            let call = IVera::getJWSTokensByAccountCall::abi_decode(input).map_err(decode_error)?;
            let account_str = format!("{}", call.account);

            let tokens = match module.get_jws_tokens_by_account(&account_str) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IVera::getJWSTokensByAccountCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IVera::getDelegationsBySubmitterCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
            }
            let call =
                IVera::getDelegationsBySubmitterCall::abi_decode(input).map_err(decode_error)?;
            let tokens = match module.get_jws_tokens_by_account(&call.submitter) {
                Ok(tokens) => tokens,
                Err(error) => return Ok(err_dispatch(error)),
            };
            let ret =
                IVera::getDelegationsBySubmitterCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IVera::getChainConfigCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
            }
            // Zero-parameter function — no ABI decoding needed.
            let config = match module.get_chain_config() {
                Ok(c) => c,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IVera::getChainConfigCall::abi_encode_returns(&json_bytes(&config));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IVera::getParamsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Ok(oog_dispatch());
            }
            // Zero-parameter function — no ABI decoding needed.
            let params = match module.query_params() {
                Ok(p) => p,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IVera::getParamsCall::abi_encode_returns(&json_bytes(&params));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        _ => Err(PrecompileError::Fatal(format!(
            "unknown Vera selector: 0x{}",
            hex::encode(selector)
        ))),
    }
}

#[test]
fn threshold_object_requires_gas_before_decoding_or_admission() {
    use revm::precompile::{PrecompileHalt, PrecompileStatus};
    let result = dispatch(
        &mut VeraModule::new(),
        &mut AcpModule::new(),
        &BlockExecCtx::default(),
        &TxExecCtx {
            sequence: 0,
            tx_hash: vec![],
            signer: String::new(),
        },
        &IVera::storeThresholdObjectCall::SELECTOR,
        WRITE_GAS - 1,
    );
    assert!(matches!(
        result,
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolEvent;
    use revm::precompile::{PrecompileHalt, PrecompileStatus};
    use vera_modules::{types::Timestamp, vera::types::JWSTokenStatus};

    #[test]
    fn invalidation_event_retains_issuer_when_authorized_account_revokes() {
        let issuer = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let account = "did:key:z6MkmjY8GnV5iJjM2BXSVn4MoDbZZbLffKHsygxC4BLd5v8P";
        let mut module = VeraModule::new();
        let mut acp = AcpModule::new();
        let block = BlockExecCtx::default();
        module
            .store_or_update_jws_token(
                &block,
                "token",
                &did_from_signer(issuer).unwrap(),
                account,
                Timestamp::default(),
                Timestamp::default(),
            )
            .unwrap();
        let hash = vera_modules::vera::keys::hash_jws_token("token");
        let tx = TxExecCtx {
            sequence: 0,
            tx_hash: vec![1; 32],
            signer: account.into(),
        };
        let call = IVera::invalidateJWSCall {
            tokenHash: hash.clone(),
        };
        let result = dispatch(
            &mut module,
            &mut acp,
            &block,
            &tx,
            &call.abi_encode(),
            WRITE_GAS,
        )
        .unwrap();
        assert!(!result.precompile.status.is_revert());
        let stored = module.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(stored.status, JWSTokenStatus::Invalid);
        assert_eq!(stored.invalidated_by, account);
        assert_eq!(result.logs.len(), 1);
        let event = IVera::JWSTokenInvalidated::decode_log(&result.logs[0]).unwrap();
        assert_eq!(event.data.issuerDid, issuer);
        assert_ne!(event.data.issuerDid, account);
    }
}
