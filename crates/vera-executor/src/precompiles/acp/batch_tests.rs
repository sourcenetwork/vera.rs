use super::*;
use vera_modules::acp::types::PolicyRecord;
use vera_modules::types::Timestamp;

fn batch(calls: Vec<Vec<u8>>) -> Vec<u8> {
    IAcp::batchCallsCall {
        calls: calls.into_iter().map(Into::into).collect(),
    }
    .abi_encode()
}

fn empty() -> Vec<u8> {
    batch(vec![])
}

fn nested(depth: usize) -> Vec<u8> {
    let mut input = empty();
    for _ in 1..depth {
        input = batch(vec![input]);
    }
    input
}

fn put_word(input: &mut [u8], offset: usize, value: usize) {
    input[offset..offset + 32].fill(0);
    input[offset + 24..offset + 32].copy_from_slice(&(value as u64).to_be_bytes());
}

fn aliased(payload: &[u8], count: usize) -> Vec<u8> {
    let tail = 68 + count * 32;
    let mut input = vec![0; tail + 32 + payload.len()];
    input[..4].copy_from_slice(&IAcp::batchCallsCall::SELECTOR);
    put_word(&mut input, 4, 32);
    put_word(&mut input, 36, count);
    for index in 0..count {
        put_word(&mut input, 68 + index * 32, count * 32);
    }
    put_word(&mut input, tail, payload.len());
    input[tail + 32..].copy_from_slice(payload);
    input
}

fn error(input: &[u8], expected: &str) {
    let result = batch::validate(input).unwrap_err().to_string();
    assert!(result.contains(expected), "{result}");
}

struct Fixture {
    acp: AcpModule,
    vera: VeraModule,
    block: BlockExecCtx,
    tx: TxExecCtx,
}

impl Fixture {
    fn new() -> Self {
        Self {
            acp: AcpModule::new(),
            vera: VeraModule::new(),
            block: BlockExecCtx {
                timestamp: Timestamp {
                    seconds: 100,
                    block_height: 1,
                },
                ..Default::default()
            },
            tx: TxExecCtx {
                signer: "did:key:owner".into(),
                tx_hash: vec![1; 32],
                sequence: 0,
            },
        }
    }

    fn dispatch(&mut self, input: &[u8], gas: u64) -> DispatchReturn {
        dispatch(
            &mut self.acp,
            &mut self.vera,
            &self.block,
            &self.tx,
            input,
            gas,
        )
    }

    fn state(&self) -> (Vec<u8>, Vec<u8>) {
        (self.acp.store().serialize(), self.vera.store().serialize())
    }
}

fn create(name: &str) -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: format!("name: {name}\nresources:\n  - name: file\n")
            .into_bytes()
            .into(),
        marshalType: 1,
    }
    .abi_encode()
}

fn created(output: &[u8]) -> PolicyRecord {
    let bytes = IAcp::createPolicyCall::abi_decode_returns(output).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn batch_depth_accepts_sixteen_wrappers_and_rejects_the_next() {
    let mut fixture = Fixture::new();
    let input = nested(batch::MAX_DEPTH);
    let result = fixture
        .dispatch(&input, READ_GAS * batch::MAX_DEPTH as u64)
        .unwrap();
    assert!(!result.precompile.reverted);
    assert_eq!(
        result.precompile.gas_used,
        READ_GAS * batch::MAX_DEPTH as u64
    );
    let before = fixture.state();
    let error = fixture
        .dispatch(&nested(batch::MAX_DEPTH + 1), 1_000_000)
        .unwrap_err();
    assert!(error.to_string().contains("depth limit exceeded"));
    assert_eq!(fixture.state(), before);
}

#[test]
fn batch_call_limit_counts_the_root_nested_wrappers_and_all_siblings() {
    let leaf = IAcp::getPoliciesCall {}.abi_encode();
    let first = batch(vec![leaf.clone(); 126]);
    let second = batch(vec![leaf.clone(); 127]);
    let input = batch(vec![first.clone(), second]);
    batch::validate(&input).unwrap();
    let mut fixture = Fixture::new();
    let result = fixture
        .dispatch(&input, READ_GAS * batch::MAX_CALLS as u64)
        .unwrap();
    assert!(!result.precompile.reverted);
    assert_eq!(
        result.precompile.gas_used,
        READ_GAS * batch::MAX_CALLS as u64
    );
    error(
        &batch(vec![first, batch(vec![leaf; 128])]),
        "call count limit exceeded",
    );
}

#[test]
fn batch_preflight_counts_each_aliased_payload_before_owned_decoding() {
    let payload = vec![0; vera_domain::MAX_TX_BYTES / 16];
    let exact = aliased(&payload, 16);
    assert!(exact.len() < vera_domain::MAX_TX_BYTES);
    batch::validate(&exact).unwrap();
    error(&aliased(&payload, 17), "decoded bytes limit exceeded");

    let mut over = payload;
    over.push(0);
    let input = aliased(&over, 16);
    let mut fixture = Fixture::new();
    let before = fixture.state();
    let result = fixture.dispatch(&input, 1_000_000).unwrap_err();
    assert!(result.to_string().contains("decoded bytes limit exceeded"));
    assert_eq!(fixture.state(), before);
}

#[test]
fn batch_calldata_has_an_independent_root_byte_limit() {
    let mut input = empty();
    input.resize(vera_domain::MAX_TX_BYTES, 0);
    batch::validate(&input).unwrap();
    input.push(0);
    error(&input, "calldata bytes limit exceeded");
}

#[test]
fn batch_preflight_rejects_malformed_headers_offsets_and_lengths() {
    let mut cases = vec![IAcp::batchCallsCall::SELECTOR.to_vec()];
    let mut missing_head = empty();
    put_word(&mut missing_head, 36, 1);
    cases.push(missing_head);
    let mut truncated_tail = aliased(&[0; 4], 1);
    truncated_tail.pop();
    cases.push(truncated_tail);
    for offset in [4, 36, 68, 100] {
        let mut overflow = aliased(&[0; 4], 1);
        overflow[offset..offset + 32].fill(255);
        cases.push(overflow);
    }
    let mut out_of_bounds = aliased(&[0; 4], 1);
    put_word(&mut out_of_bounds, 68, usize::MAX);
    cases.push(out_of_bounds);
    for input in cases {
        error(&input, "invalid ACP batch ABI");
    }
    let mut huge_count = empty();
    put_word(&mut huge_count, 36, batch::MAX_CALLS);
    error(&huge_count, "call count limit exceeded");
    let mut huge_length = aliased(&[0; 4], 1);
    put_word(&mut huge_length, 100, vera_domain::MAX_TX_BYTES + 1);
    error(&huge_length, "decoded bytes limit exceeded");
}

#[test]
fn batch_preflight_preserves_bounded_aliases_unaligned_offsets_and_unpadded_bytes() {
    let leaf = IAcp::getPoliciesCall {}.abi_encode();
    let input = aliased(&leaf, 2);
    let decoded = IAcp::batchCallsCall::abi_decode(&input).unwrap();
    assert_eq!(decoded.calls, vec![Bytes::from(leaf.clone()); 2]);
    let mut fixture = Fixture::new();
    let result = fixture.dispatch(&input, READ_GAS * 3).unwrap();
    assert!(!result.precompile.reverted);
    assert_eq!(result.precompile.gas_used, READ_GAS * 3);

    let mut unaligned = aliased(&leaf, 1);
    unaligned.insert(100, 0);
    put_word(&mut unaligned, 68, 33);
    batch::validate(&unaligned).unwrap();
    assert_eq!(
        IAcp::batchCallsCall::abi_decode(&unaligned).unwrap().calls,
        vec![Bytes::from(leaf)]
    );
}

#[test]
fn empty_batch_charges_before_preflight_and_rolls_back_when_nested_gas_runs_out() {
    let mut fixture = Fixture::new();
    let before = fixture.state();
    assert!(matches!(
        fixture.dispatch(&IAcp::batchCallsCall::SELECTOR, READ_GAS - 1),
        Err(PrecompileError::OutOfGas)
    ));
    let result = fixture.dispatch(&empty(), READ_GAS).unwrap();
    assert_eq!(result.precompile.gas_used, READ_GAS);
    assert!(
        IAcp::batchCallsCall::abi_decode_returns(&result.precompile.bytes)
            .unwrap()
            .is_empty()
    );
    let input = batch(vec![create("earlier"), empty()]);
    assert!(matches!(
        fixture.dispatch(&input, WRITE_GAS + READ_GAS * 2 - 1),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
}

#[test]
fn nested_batch_preserves_result_order_and_charges_every_wrapper() {
    let mut fixture = Fixture::new();
    let input = batch(vec![
        create("first"),
        batch(vec![create("second"), empty()]),
        create("third"),
    ]);
    let gas = WRITE_GAS * 3 + READ_GAS * 3;
    let result = fixture.dispatch(&input, gas).unwrap();
    assert!(!result.precompile.reverted);
    assert_eq!(result.precompile.gas_used, gas);
    assert_eq!(result.logs.len(), 3);
    let outputs = IAcp::batchCallsCall::abi_decode_returns(&result.precompile.bytes).unwrap();
    let inner = IAcp::batchCallsCall::abi_decode_returns(&outputs[1]).unwrap();
    for (name, output) in [
        ("first", &outputs[0]),
        ("second", &inner[0]),
        ("third", &outputs[2]),
    ] {
        let record = created(output);
        assert_eq!(record.policy.name, name);
        assert_eq!(
            fixture
                .acp
                .query_policy(&record.policy.id)
                .unwrap()
                .policy
                .name,
            name
        );
    }
    assert!(
        IAcp::batchCallsCall::abi_decode_returns(&inner[1])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn nested_batch_late_revert_restores_state_logs_and_error_indices() {
    let mut fixture = Fixture::new();
    let before = fixture.state();
    let input = batch(vec![
        create("first"),
        batch(vec![
            create("second"),
            IAcp::getPolicyCall {
                policyId: B256::ZERO,
            }
            .abi_encode(),
        ]),
    ]);
    let result = fixture.dispatch(&input, 1_000_000).unwrap();
    assert!(result.precompile.reverted);
    assert!(result.logs.is_empty());
    assert_eq!(result.precompile.gas_used, WRITE_GAS * 2 + READ_GAS * 2);
    assert!(
        String::from_utf8_lossy(&result.precompile.bytes)
            .starts_with("batch call 2 reverted: batch call 2 reverted:")
    );
    assert_eq!(fixture.state(), before);
}
