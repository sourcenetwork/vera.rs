use super::*;
use revm::precompile::{PrecompileHalt, PrecompileStatus};

const YAML: &str = "name: validation\nresources:\n  - name: file\n";

fn call(policy: &[u8], marshal_type: u8) -> Vec<u8> {
    IAcp::validatePolicyCall {
        policy: policy.to_vec().into(),
        marshalType: marshal_type,
    }
    .abi_encode()
}

fn dispatch_call(module: &mut AcpModule, input: &[u8], gas: u64) -> DispatchReturn {
    dispatch(
        module,
        &mut VeraModule::new(),
        &BlockExecCtx::default(),
        &TxExecCtx {
            signer: "did:key:owner".into(),
            tx_hash: vec![1; 32],
            sequence: 0,
        },
        input,
        gas,
    )
}

fn expected_gas(input: &[u8], policy: &[u8]) -> u64 {
    READ_GAS + (input.len() as u64).div_ceil(16) * 8 + (policy.len() as u64).div_ceil(16) * 8
}

#[test]
fn policy_validation_charges_exact_input_work_and_preserves_results() {
    let mut module = AcpModule::new();
    let before = module.store().serialize();
    for (policy, format) in [
        (YAML, 1),
        (r#"{"name":"validation","resources":[{"name":"file"}]}"#, 2),
        ("name: [", 1),
        (YAML, 0),
    ] {
        let input = call(policy.as_bytes(), format);
        let gas = expected_gas(&input, policy.as_bytes());
        let result = dispatch_call(&mut module, &input, gas).unwrap();
        assert!(!result.precompile.status.is_revert());
        assert_eq!(result.precompile.gas_used, gas);
        assert!(result.logs.is_empty());
        let result =
            IAcp::validatePolicyCall::abi_decode_returns(&result.precompile.bytes).unwrap();
        let (valid, reason, _) = module
            .query_validate_policy(policy, marshal_type_from_u8(format))
            .unwrap();
        assert_eq!((result.valid, result.reason), (valid, reason));
        assert!(matches!(
            dispatch_call(&mut module, &input, gas - 1),
            Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
        ));
    }
    assert_eq!(module.store().serialize(), before);
}

#[test]
fn policy_validation_reserves_before_decode_and_bounds_oversized_definitions() {
    let mut module = AcpModule::new();
    let mut malformed = call(YAML.as_bytes(), 1);
    malformed[4..36].fill(0xff);
    let raw_cost = (malformed.len() as u64).div_ceil(16) * 8;
    assert!(matches!(
        dispatch_call(&mut module, &malformed, READ_GAS + raw_cost - 1),
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
    for input in [
        malformed,
        IAcp::validatePolicyCall::SELECTOR.to_vec(),
        call(&[0xff], 1),
    ] {
        assert!(matches!(
            dispatch_call(&mut module, &input, 1_000_000),
            Err(PrecompileError::Fatal(_))
        ));
    }

    let oversized = " ".repeat(vera_modules::acp::MAX_POLICY_DEFINITION_BYTES + 1);
    let input = call(oversized.as_bytes(), 1);
    let gas = expected_gas(&input, oversized.as_bytes());
    let result = dispatch_call(&mut module, &input, gas).unwrap();
    assert!(!result.precompile.status.is_revert());
    assert_eq!(result.precompile.gas_used, gas);
    let result = IAcp::validatePolicyCall::abi_decode_returns(&result.precompile.bytes).unwrap();
    let (valid, reason, _) = module
        .query_validate_policy(&oversized, PolicyMarshalingType::ShortYaml)
        .unwrap();
    assert_eq!((result.valid, result.reason), (valid, reason));
    assert!(matches!(
        dispatch_call(&mut module, &input, gas - 1),
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
    let mut oversized_utf8 = oversized.into_bytes();
    oversized_utf8[0] = 0xff;
    assert!(matches!(
        dispatch_call(&mut module, &call(&oversized_utf8, 1), 1_000_000),
        Err(PrecompileError::Fatal(_))
    ));
}

#[test]
fn policy_validation_borrowed_fields_preserve_alloy_decoding() {
    let mut module = AcpModule::new();
    let mut scalar = call(YAML.as_bytes(), 1);
    // The existing non-validating Alloy decoder accepts high uint8 padding bits.
    scalar[36..67].fill(0xff);
    let mut unaligned = call(YAML.as_bytes(), 1);
    unaligned.insert(68, 0);
    unaligned[35] = 65;
    let mut unpadded = call(YAML.as_bytes(), 1);
    unpadded.truncate(4 + 64 + 32 + YAML.len());
    for input in [scalar, unaligned, unpadded] {
        let decoded = IAcp::validatePolicyCall::abi_decode(&input).unwrap();
        assert_eq!(decoded.policy.as_ref(), YAML.as_bytes());
        assert_eq!(decoded.marshalType, 1);
        let gas = expected_gas(&input, &decoded.policy);
        let result = dispatch_call(&mut module, &input, gas).unwrap();
        assert!(!result.precompile.status.is_revert());
        assert_eq!(result.precompile.gas_used, gas);
        let result =
            IAcp::validatePolicyCall::abi_decode_returns(&result.precompile.bytes).unwrap();
        assert!(result.valid);
        assert!(result.reason.is_empty());
    }
}

#[test]
fn policy_validation_nested_batches_share_the_remaining_allowance() {
    let mut module = AcpModule::new();
    let validation = call(YAML.as_bytes(), 1);
    let nested = IAcp::batchCallsCall {
        calls: vec![validation.clone().into()],
    }
    .abi_encode();
    let input = IAcp::batchCallsCall {
        calls: vec![validation.clone().into(), nested.into()],
    }
    .abi_encode();
    let gas = READ_GAS * 2 + expected_gas(&validation, YAML.as_bytes()) * 2;
    let result = dispatch_call(&mut module, &input, gas).unwrap();
    assert!(!result.precompile.status.is_revert());
    assert_eq!(result.precompile.gas_used, gas);
    assert!(matches!(
        dispatch_call(&mut module, &input, gas - 1),
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
}
