use super::*;
use revm::precompile::{PrecompileHalt, PrecompileStatus};
use vera_modules::acp::{MAX_REGISTRATION_OBJECTS, decision::MAX_ACCESS_OPERATIONS};
use vera_modules::types::Timestamp;

const ACTOR: &[u8] = b"did:key:owner";

fn layouts() -> [([u8; 4], usize, usize); 3] {
    [
        (IAcp::checkAccessCall::SELECTOR, 3, MAX_ACCESS_OPERATIONS),
        (
            IAcp::verifyAccessRequestCall::SELECTOR,
            3,
            MAX_ACCESS_OPERATIONS,
        ),
        (
            IAcp::generateCommitmentCall::SELECTOR,
            2,
            MAX_REGISTRATION_OBJECTS,
        ),
    ]
}

fn put_word(input: &mut [u8], offset: usize, value: usize) {
    input[offset..offset + 32].fill(0);
    input[offset + 24..offset + 32].copy_from_slice(&(value as u64).to_be_bytes());
}

// All parallel arrays share one head, whose elements all share one string tail.
// Deliberately omit padding, matching the permissive owned decoder.
fn aliased(selector: [u8; 4], arrays: usize, count: usize, payload: &[u8]) -> Vec<u8> {
    let array = (arrays + 2) * 32;
    let tail = array + 32 + count * 32;
    let actor = tail + 32 + payload.len();
    let mut input = vec![0; 4 + actor + 32 + ACTOR.len()];
    input[..4].copy_from_slice(&selector);
    for index in 0..arrays {
        put_word(&mut input, 4 + (index + 1) * 32, array);
    }
    put_word(&mut input, 4 + (arrays + 1) * 32, actor);
    put_word(&mut input, 4 + array, count);
    for index in 0..count {
        put_word(&mut input, 4 + array + 32 + index * 32, count * 32);
    }
    put_word(&mut input, 4 + tail, payload.len());
    input[4 + tail + 32..4 + actor].copy_from_slice(payload);
    put_word(&mut input, 4 + actor, ACTOR.len());
    input[4 + actor + 32..].copy_from_slice(ACTOR);
    input
}

fn owned_strings(input: &[u8]) -> Vec<String> {
    if input.starts_with(&IAcp::checkAccessCall::SELECTOR) {
        let call = IAcp::checkAccessCall::abi_decode(input).unwrap();
        call.resources
            .into_iter()
            .chain(call.objectIds)
            .chain(call.permissions)
            .chain([call.actor])
            .collect()
    } else if input.starts_with(&IAcp::verifyAccessRequestCall::SELECTOR) {
        let call = IAcp::verifyAccessRequestCall::abi_decode(input).unwrap();
        call.resources
            .into_iter()
            .chain(call.objectIds)
            .chain(call.permissions)
            .chain([call.actor])
            .collect()
    } else {
        let call = IAcp::generateCommitmentCall::abi_decode(input).unwrap();
        call.resources
            .into_iter()
            .chain(call.objectIds)
            .chain([call.actor])
            .collect()
    }
}

fn error(input: &[u8], expected: &str) {
    let error = batch::validate(input).unwrap_err().to_string();
    assert!(error.contains(expected), "{error}");
}

fn batch(calls: Vec<Vec<u8>>) -> Vec<u8> {
    IAcp::batchCallsCall {
        calls: calls.into_iter().map(Into::into).collect(),
    }
    .abi_encode()
}

#[test]
fn leaf_array_counts_are_bounded_even_for_empty_aliased_strings() {
    for (selector, arrays, maximum) in layouts() {
        let input = aliased(selector, arrays, maximum, b"");
        batch::validate(&input).unwrap();
        assert_eq!(owned_strings(&input).len(), arrays * maximum + 1);
        error(
            &aliased(selector, arrays, maximum + 1, b""),
            "count limit exceeded",
        );
        let array = (arrays + 2) * 32;
        let mut huge = aliased(selector, arrays, 0, b"");
        huge.truncate(4 + array + 32);
        put_word(&mut huge, 4 + array, usize::MAX);
        error(&huge, "count limit exceeded");
    }
}

#[test]
fn leaf_preflight_counts_aliases_and_lossy_utf8_exactly_like_owned_decode() {
    for payload in [
        b"abc".as_slice(),
        "é🚀".as_bytes(),
        &[b'a', 0xf0, 0x90, 0x80, b'b', 0xff, 0xe2, 0x82],
    ] {
        for (selector, arrays, _) in layouts() {
            let input = aliased(selector, arrays, 3, payload);
            let bytes = owned_strings(&input).iter().map(String::len).sum::<usize>();
            let mut remaining = bytes;
            leaf::validate(&input, &mut remaining).unwrap();
            assert_eq!(remaining, 0);
            let error = leaf::validate(&input, &mut (bytes - 1)).unwrap_err();
            assert!(error.to_string().contains("decoded bytes limit exceeded"));
        }
    }
}

#[test]
fn leaf_preflight_charges_an_actor_aliased_to_an_array_string() {
    for (selector, arrays, _) in layouts() {
        let mut input = aliased(selector, arrays, 1, &[0xff]);
        let tail = (arrays + 2) * 32 + 64;
        put_word(&mut input, 4 + (arrays + 1) * 32, tail);
        let bytes = owned_strings(&input).iter().map(String::len).sum::<usize>();
        assert_eq!(bytes, 3 * (arrays + 1));
        let mut remaining = bytes;
        leaf::validate(&input, &mut remaining).unwrap();
        assert_eq!(remaining, 0);
        assert!(leaf::validate(&input, &mut (bytes - 1)).is_err());
    }
}

#[test]
fn leaf_preflight_preserves_unaligned_offsets_and_unpadded_strings() {
    for (selector, arrays, _) in layouts() {
        let mut input = aliased(selector, arrays, 2, b"x");
        let array = (arrays + 2) * 32;
        let actor = array + 32 + 64 + 32 + 1;
        input.insert(4 + array, 0);
        for index in 0..arrays {
            put_word(&mut input, 4 + (index + 1) * 32, array + 1);
        }
        put_word(&mut input, 4 + (arrays + 1) * 32, actor + 1);
        batch::validate(&input).unwrap();
        let strings = owned_strings(&input);
        assert_eq!(&strings[..arrays * 2], vec!["x"; arrays * 2]);
        assert_eq!(strings.last().unwrap(), "did:key:owner");
    }
}

#[test]
fn leaf_preflight_rejects_malformed_heads_tails_and_parallel_lengths() {
    for (selector, arrays, _) in layouts() {
        let valid = aliased(selector, arrays, 1, b"x");
        let array = (arrays + 2) * 32;
        let tail = array + 64;
        let mut cases = vec![selector.to_vec(), valid[..4 + array - 1].to_vec()];
        let mut truncated = valid.clone();
        truncated.pop();
        cases.push(truncated);
        for offset in [4 + 32, 4 + array, 4 + array + 32, 4 + tail] {
            let mut overflow = valid.clone();
            overflow[offset..offset + 32].fill(255);
            cases.push(overflow);
        }
        let mut missing_head = valid.clone();
        put_word(&mut missing_head, 4 + array, 2);
        missing_head.truncate(4 + array + 64);
        cases.push(missing_head);
        for malformed in cases {
            error(&malformed, "invalid ACP string-array ABI");
        }
        let mut mismatch = valid;
        let different_array = mismatch.len() - 4;
        mismatch.extend_from_slice(&[0; 32]);
        put_word(&mut mismatch, 4 + 64, different_array);
        error(&mismatch, "array length mismatch");
    }
}

#[test]
fn leaf_strings_share_the_batch_expansion_budget_across_nested_calls() {
    let input = aliased(
        IAcp::generateCommitmentCall::SELECTOR,
        2,
        128,
        &vec![b'x'; 32768],
    );
    batch::validate(&input).unwrap();
    let nested = batch(vec![input.clone(), batch(vec![input])]);
    assert!(nested.len() < vera_domain::MAX_TX_BYTES);
    error(&nested, "decoded bytes limit exceeded");
}

#[test]
fn oversized_leaf_arrays_fail_before_standalone_or_nested_mutations() {
    for (selector, arrays, maximum) in layouts() {
        let input = aliased(selector, arrays, maximum, &vec![b'x'; 1 << 20]);
        assert!(input.len() < vera_domain::MAX_TX_BYTES);
        error(&input, "decoded bytes limit exceeded");
        let create = IAcp::createPolicyCall {
            policy: Bytes::from_static(b"name: earlier\nresources:\n  - name: file\n"),
            marshalType: 1,
        }
        .abi_encode();
        for calldata in [
            input.clone(),
            batch(vec![create, batch(vec![input.clone()])]),
        ] {
            let mut module = AcpModule::new();
            let mut vera = VeraModule::new();
            let before = (module.store().serialize(), vera.store().serialize());
            let block = BlockExecCtx {
                timestamp: Timestamp {
                    seconds: 100,
                    block_height: 1,
                },
                ..Default::default()
            };
            let tx = TxExecCtx {
                signer: "did:key:owner".into(),
                tx_hash: vec![1; 32],
                sequence: 0,
            };
            let result =
                dispatch(&mut module, &mut vera, &block, &tx, &calldata, 1_000_000).unwrap_err();
            assert!(matches!(result, PrecompileError::Fatal(_)));
            assert!(result.to_string().contains("decoded bytes limit exceeded"));
            assert_eq!(
                (module.store().serialize(), vera.store().serialize()),
                before
            );
        }
        let mut module = AcpModule::new();
        let mut vera = VeraModule::new();
        assert!(matches!(
            dispatch(
                &mut module,
                &mut vera,
                &BlockExecCtx::default(),
                &TxExecCtx {
                    signer: "did:key:owner".into(),
                    tx_hash: vec![1; 32],
                    sequence: 0
                },
                &selector,
                leaf::required_gas(&input).unwrap() - 1
            ),
            Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
        ));
    }
}

fn edit_call(policy: Vec<u8>, token: Option<String>) -> Vec<u8> {
    match token {
        None => IAcp::editPolicyCall {
            policyId: B256::ZERO,
            policy: policy.into(),
            marshalType: 1,
        }
        .abi_encode(),
        Some(bearer_token) => IAcp::bearerEditPolicyCall {
            bearerToken: bearer_token,
            policyId: B256::ZERO,
            policy: policy.into(),
            marshalType: 1,
        }
        .abi_encode(),
    }
}

#[test]
fn edit_abi_preflight_enforces_existing_definition_and_token_byte_bounds() {
    for token in [None, Some("x".repeat(16 * 1024))] {
        let valid = edit_call(vec![b'x'; 64 * 1024], token.clone());
        batch::validate(&valid).unwrap();
        error(
            &edit_call(vec![b'x'; 64 * 1024 + 1], token.clone()),
            "policy definition exceeds 64 KiB",
        );
        error(
            &batch(vec![valid, edit_call(vec![b'x'; 64 * 1024 + 1], token)]),
            "policy definition exceeds 64 KiB",
        );
    }
    error(
        &edit_call(vec![], Some("x".repeat(16 * 1024 + 1))),
        "decoded bytes limit exceeded",
    );
}

#[test]
fn edit_abi_preflight_counts_aliased_token_lossy_utf8_before_owned_decode() {
    let mut input = edit_call(vec![255], Some(String::new()));
    let policy_offset = input[4 + 64..4 + 96].to_vec();
    input[4..4 + 32].copy_from_slice(&policy_offset);
    let owned = IAcp::bearerEditPolicyCall::abi_decode(&input).unwrap();
    assert_eq!(owned.bearerToken, "\u{fffd}");
    let decoded = owned.policy.len() + owned.bearerToken.len();
    let mut remaining = decoded;
    leaf::validate(&input, &mut remaining).unwrap();
    assert_eq!(remaining, 0);
    assert!(leaf::validate(&input, &mut (decoded - 1)).is_err());
    let mut expanded = edit_call(vec![255; 6000], Some(String::new()));
    let policy_offset = expanded[4 + 64..4 + 96].to_vec();
    expanded[4..4 + 32].copy_from_slice(&policy_offset);
    error(&expanded, "decoded bytes limit exceeded");
}

#[test]
fn edit_abi_preflight_rejects_bad_offsets_and_lengths_without_allocating() {
    for token in [None, Some(String::new())] {
        let policy_head = if token.is_some() { 64 } else { 32 };
        let valid = edit_call(vec![b'x'], token);
        for offset in [4 + policy_head, valid.len() - 64] {
            let mut malformed = valid.clone();
            malformed[offset..offset + 32].fill(255);
            assert!(batch::validate(&malformed).is_err());
        }
        assert!(batch::validate(&valid[..4 + policy_head + 31]).is_err());
    }
}

#[test]
fn permission_leaf_bytes_are_bounded_before_alias_or_utf8_expansion() {
    for selector in [
        IAcp::checkAccessCall::SELECTOR,
        IAcp::verifyAccessRequestCall::SELECTOR,
    ] {
        for (byte, width) in [(b'x', 1), (0xff, 3)] {
            let count = 64;
            let length = ((64 << 10) - ACTOR.len()) / (3 * count * width);
            let exact = aliased(selector, 3, count, &vec![byte; length]);
            batch::validate(&exact).unwrap();
            assert!(owned_strings(&exact).iter().map(String::len).sum::<usize>() <= 64 << 10);
            let oversized = aliased(selector, 3, count, &vec![byte; length + 1]);
            assert!(oversized.len() < 64 << 10);
            error(&oversized, "decoded bytes limit exceeded");
            error(&batch(vec![oversized]), "decoded bytes limit exceeded");
        }
    }
}
