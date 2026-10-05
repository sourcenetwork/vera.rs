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
    let leaf_gas = fixture
        .dispatch(&leaf, 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    let expected_gas = 3 * READ_GAS + 253 * leaf_gas;
    let result = fixture.dispatch(&input, expected_gas).unwrap();
    assert!(!result.precompile.reverted);
    assert_eq!(result.precompile.gas_used, expected_gas);
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
    let leaf_gas = fixture
        .dispatch(&leaf, 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    let expected_gas = READ_GAS + 2 * leaf_gas;
    let result = fixture.dispatch(&input, expected_gas).unwrap();
    assert!(!result.precompile.reverted);
    assert_eq!(result.precompile.gas_used, expected_gas);

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
    let missing = IAcp::getPolicyCall {
        policyId: B256::ZERO,
    }
    .abi_encode();
    let read_gas = fixture
        .dispatch(&missing, 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    assert_eq!(
        result.precompile.gas_used,
        WRITE_GAS * 2 + READ_GAS * 2 + read_gas
    );
    assert!(
        String::from_utf8_lossy(&result.precompile.bytes)
            .starts_with("batch call 2 reverted: batch call 2 reverted:")
    );
    assert_eq!(fixture.state(), before);
}

fn large_policy_read(fixture: &mut Fixture) -> (Vec<u8>, usize, u64) {
    // A large YAML comment leaves a small compiled policy and a legitimately retained raw policy.
    let policy = format!(
        "name: large\nresources:\n  - name: file\n# {}\n",
        "x".repeat(60 << 10),
    );
    let call = IAcp::createPolicyCall {
        policy: policy.into_bytes().into(),
        marshalType: 1,
    }
    .abi_encode();
    let result = fixture.dispatch(&call, WRITE_GAS).unwrap();
    assert!(!result.precompile.reverted);
    let record = created(&result.precompile.bytes);
    let read = IAcp::getPolicyCall {
        policyId: record.policy.id.parse().unwrap(),
    }
    .abi_encode();
    let result = fixture.dispatch(&read, 1_000_000).unwrap();
    assert!(!result.precompile.reverted);
    let per_result = 64 + result.precompile.bytes.len().div_ceil(32) * 32;
    let max_results = (batch_results::MAX_RESULT_BYTES - 64) / per_result;
    assert!((4..batch::MAX_CALLS - 2).contains(&max_results));
    // Leave enough execution allowance to exercise the independent result-byte limit.
    let gas = 3 * READ_GAS + WRITE_GAS + (max_results as u64 + 1) * result.precompile.gas_used;
    (read, max_results, gas)
}

#[test]
fn repeated_policy_reads_stop_before_retaining_an_oversized_batch_result() {
    let mut fixture = Fixture::new();
    let (read, count, gas) = large_policy_read(&mut fixture);
    let input = batch(vec![read.clone(); count]);
    let result = fixture.dispatch(&input, gas).unwrap();
    assert!(!result.precompile.reverted);
    assert!(result.precompile.bytes.len() <= batch_results::MAX_RESULT_BYTES);
    assert_eq!(
        IAcp::batchCallsCall::abi_decode_returns(&result.precompile.bytes)
            .unwrap()
            .len(),
        count
    );
    let before = fixture.state();
    let error = fixture
        .dispatch(&batch(vec![read; count + 1]), gas)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("batch result byte limit exceeded")
    );
    assert_eq!(fixture.state(), before);
}

#[test]
fn nested_wrappers_share_the_result_budget_even_when_outer_encoding_would_fit() {
    let mut fixture = Fixture::new();
    let (read, max_results, gas) = large_policy_read(&mut fixture);
    let count = max_results / 3 + 1;
    let flat = fixture
        .dispatch(&batch(vec![read.clone(); count * 2]), gas)
        .unwrap();
    assert!(!flat.precompile.reverted);
    assert!(flat.precompile.bytes.len() < batch_results::MAX_RESULT_BYTES);
    let inner = batch(vec![read; count]);
    let before = fixture.state();
    let error = fixture
        .dispatch(&batch(vec![inner.clone(), inner]), gas)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("batch result byte limit exceeded")
    );
    assert_eq!(fixture.state(), before);
}

#[test]
fn late_result_exhaustion_restores_prior_writes_and_returns_no_logs() {
    let mut fixture = Fixture::new();
    let (read, count, gas) = large_policy_read(&mut fixture);
    let before = fixture.state();
    let mut calls = vec![create("must-rollback")];
    calls.extend(std::iter::repeat_n(read, count + 1));
    // No successful/reverted DispatchResult (and therefore no logs) escapes this error.
    let error = fixture.dispatch(&batch(calls), gas).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("batch result byte limit exceeded")
    );
    assert_eq!(fixture.state(), before);
}

fn large_policy_listing(fixture: &mut Fixture, count: usize) -> Vec<u8> {
    let actor = Did::new(&fixture.tx.signer).unwrap();
    let policy = format!(
        "name: listing\nresources:\n  - name: file\n# {}\n",
        "x".repeat(60 << 10),
    );
    for _ in 0..count {
        fixture
            .acp
            .create_policy(&actor, &policy, PolicyMarshalingType::ShortYaml)
            .unwrap();
    }
    IAcp::getPolicyIdsCall {}.abi_encode()
}

#[test]
fn policy_id_listing_charges_exact_work_and_repeated_batches_exhaust_remaining_gas() {
    let mut fixture = Fixture::new();
    let read = large_policy_listing(&mut fixture, 16);
    let before = fixture.state();
    let measured = fixture.dispatch(&read, 1_000_000).unwrap();
    assert!(!measured.precompile.reverted);
    let required = measured.precompile.gas_used;
    assert!(required > 60_000);
    assert_eq!(
        IAcp::getPolicyIdsCall::abi_decode_returns(&measured.precompile.bytes)
            .unwrap()
            .len(),
        16
    );
    assert_eq!(
        fixture
            .dispatch(&read, required)
            .unwrap()
            .precompile
            .gas_used,
        required
    );
    assert!(matches!(
        fixture.dispatch(&read, required - 1),
        Err(PrecompileError::OutOfGas)
    ));
    let nested = batch(vec![read.clone(), batch(vec![read.clone()])]);
    let exact = READ_GAS * 2 + required * 2;
    assert_eq!(
        fixture
            .dispatch(&nested, exact)
            .unwrap()
            .precompile
            .gas_used,
        exact
    );
    assert!(matches!(
        fixture.dispatch(&nested, exact - 1),
        Err(PrecompileError::OutOfGas)
    ));
    let input = batch(vec![read.clone(); batch::MAX_CALLS - 1]);
    batch::validate(&input).unwrap();
    assert!(matches!(
        fixture.dispatch(&input, 1_000_000),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
    let mut calls = vec![create("prior-write")];
    calls.extend(std::iter::repeat_n(read, batch::MAX_CALLS - 2));
    assert!(matches!(
        fixture.dispatch(&batch(calls), 1_000_000),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
}

#[test]
fn oversized_policy_id_listing_keeps_read_charges_and_rolls_back_earlier_batch_writes() {
    let mut fixture = Fixture::new();
    let read = large_policy_listing(&mut fixture, 18);
    let before = fixture.state();
    let result = fixture.dispatch(&read, 1_000_000).unwrap();
    assert!(result.precompile.reverted);
    assert!(result.precompile.gas_used > READ_GAS);
    assert!(
        String::from_utf8_lossy(&result.precompile.bytes).contains("use certified prefix pages")
    );
    let input = batch(vec![read.clone(); batch::MAX_CALLS - 1]);
    batch::validate(&input).unwrap();
    let repeated = fixture.dispatch(&input, 1_000_000).unwrap();
    assert!(repeated.precompile.reverted);
    assert_eq!(
        repeated.precompile.gas_used,
        READ_GAS + result.precompile.gas_used
    );
    assert!(
        String::from_utf8_lossy(&repeated.precompile.bytes).starts_with("batch call 1 reverted:")
    );
    assert!(repeated.logs.is_empty());
    assert_eq!(fixture.state(), before);
    let result = fixture
        .dispatch(&batch(vec![create("prior-write"), read]), 1_000_000)
        .unwrap();
    assert!(result.precompile.reverted);
    assert!(result.precompile.gas_used > READ_GAS + WRITE_GAS);
    assert!(result.logs.is_empty());
    assert_eq!(fixture.state(), before);
}
