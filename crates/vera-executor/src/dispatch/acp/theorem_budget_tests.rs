use super::*;
use crate::dispatch::ModuleStatus;
use vera_modules::acp::theorem::TheoremReport;

const POLICY: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader\n";

fn fixture() -> (AcpModule, B256) {
    let owner = Did::new("did:key:owner").unwrap();
    let mut acp = AcpModule::new();
    let policy = acp
        .create_policy(
            &owner,
            POLICY,
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap()
        .policy
        .id;
    acp.direct_policy_cmd(
        &owner,
        &policy,
        PolicyCmd::RegisterObject(Object {
            resource: "file".into(),
            id: "report".into(),
        }),
    )
    .unwrap();
    (acp, policy.parse().unwrap())
}

fn evaluate(acp: &AcpModule, policy: B256, assertions: usize, gas: u64) -> DispatchResult {
    let source = format!(
        "Authorizations {{ {} }} Delegations {{ did:key:owner > file:report#reader }}",
        "file:report#read@did:key:owner ".repeat(assertions)
    );
    dispatch(
        &mut acp.clone(),
        &mut VeraModule::new(),
        &BlockExecCtx::default(),
        &TxExecCtx {
            signer: "did:key:owner".into(),
            tx_hash: vec![1; 32],
            sequence: 0,
        },
        &IAcp::evaluateTheoremCall {
            policyId: policy,
            source,
        }
        .abi_encode(),
        gas,
    )
    .unwrap()
}

#[test]
fn theorem_evaluation_charges_every_assertion_and_halts_when_the_allowance_ends() {
    let (acp, policy) = fixture();
    let one = evaluate(&acp, policy, 1, 1_000_000).output;
    let many = evaluate(&acp, policy, 32, 1_000_000).output;
    assert!(one.gas_used > READ_GAS);
    assert!(many.gas_used > one.gas_used + 31 * 32);
    let report: TheoremReport = serde_json::from_slice(
        &IAcp::evaluateTheoremCall::abi_decode_returns(&many.bytes).unwrap(),
    )
    .unwrap();
    assert!(report.ok);
    assert_eq!(report.theorem_count, 33);

    let exact = evaluate(&acp, policy, 32, many.gas_used).output;
    assert_eq!(exact.bytes, many.bytes);
    assert_eq!(exact.gas_used, many.gas_used);
    for gas in [many.gas_used - 1, one.gas_used, READ_GAS, READ_GAS - 1] {
        assert!(matches!(
            evaluate(&acp, policy, 32, gas).output.status,
            ModuleStatus::OutOfGas
        ));
    }
}

#[test]
fn rejected_theorem_sources_pay_for_their_bytes() {
    let (acp, policy) = fixture();
    let dispatch = |source: String| {
        dispatch(
            &mut acp.clone(),
            &mut VeraModule::new(),
            &BlockExecCtx::default(),
            &TxExecCtx {
                signer: "did:key:owner".into(),
                tx_hash: vec![1; 32],
                sequence: 0,
            },
            &IAcp::evaluateTheoremCall {
                policyId: policy,
                source,
            }
            .abi_encode(),
            1_000_000,
        )
        .unwrap()
        .output
    };
    let short = dispatch("?".into());
    let long = dispatch("?".repeat(16 << 10));
    assert!(short.status.is_revert() && long.status.is_revert());
    assert!(long.gas_used > short.gas_used);
    assert!(short.gas_used > READ_GAS);
}
