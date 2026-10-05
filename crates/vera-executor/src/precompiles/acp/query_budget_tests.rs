use super::*;
use vera_modules::acp::{
    pages::RelationshipPageRequest,
    types::{PolicyCommandRequest, SuppliedMetadata},
};
use vera_modules::types::Timestamp;

#[derive(Clone)]
struct Fixture {
    module: AcpModule,
    vera: VeraModule,
    block: BlockExecCtx,
    tx: TxExecCtx,
    policy: B256,
}

impl Fixture {
    fn new() -> Self {
        let actor = Did::new("did:key:owner").unwrap();
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(
                &actor,
                "name: files\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        let block = BlockExecCtx {
            timestamp: Timestamp {
                seconds: 10,
                block_height: 1,
            },
            ..Default::default()
        };
        let tx = TxExecCtx {
            signer: actor.to_string(),
            tx_hash: vec![1; 32],
            sequence: 0,
        };
        for index in 0..16 {
            module
                .execute_policy_cmd_with_metadata(
                    &actor,
                    &policy,
                    PolicyCommandRequest {
                        command: PolicyCmd::RegisterObject(Object {
                            resource: "file".into(),
                            id: format!("report-{index}"),
                        }),
                        metadata: SuppliedMetadata {
                            attributes: [("note".into(), "x".repeat(60 << 10))].into(),
                            ..Default::default()
                        },
                    },
                    &block,
                    &tx,
                )
                .unwrap();
        }
        Self {
            module,
            vera: VeraModule::new(),
            block,
            tx,
            policy: policy.parse().unwrap(),
        }
    }

    fn dispatch(&mut self, input: &[u8], gas: u64) -> DispatchReturn {
        dispatch(
            &mut self.module,
            &mut self.vera,
            &self.block,
            &self.tx,
            input,
            gas,
        )
    }

    fn filtered(&self) -> Vec<u8> {
        IAcp::filterRelationshipsCall {
            policyId: self.policy,
            resource: "file".into(),
            objectId: String::new(),
            relation: "owner".into(),
            actor: "did:key:absent".into(),
        }
        .abi_encode()
    }
}

fn batch(calls: Vec<Vec<u8>>) -> Vec<u8> {
    IAcp::batchCallsCall {
        calls: calls.into_iter().map(Into::into).collect(),
    }
    .abi_encode()
}

fn create() -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: b"name: transient\nresources:\n  - name: file\n"
            .to_vec()
            .into(),
        marshalType: 1,
    }
    .abi_encode()
}

#[test]
fn query_budget_all_collection_routes_enforce_exact_allowance() {
    let mut fixture = Fixture::new();
    let selector = build_relationship_selector("file", "", "owner", "did:key:absent").unwrap();
    let calls = [
        IAcp::getPolicyIdsCall {}.abi_encode(),
        IAcp::getPolicyCall {
            policyId: fixture.policy,
        }
        .abi_encode(),
        IAcp::getPoliciesCall {}.abi_encode(),
        IAcp::getPoliciesPageCall {
            cursor: Bytes::new(),
        }
        .abi_encode(),
        IAcp::getRelationshipsPageCall {
            policyId: fixture.policy,
            request: serde_json::to_vec(&RelationshipPageRequest {
                selector,
                after: None,
            })
            .unwrap()
            .into(),
        }
        .abi_encode(),
        IAcp::getPolicyCatalogueCall {
            policyId: fixture.policy,
        }
        .abi_encode(),
        fixture.filtered(),
        IAcp::hasRelationshipCall {
            policyId: fixture.policy,
            resource: "file".into(),
            objectId: "report-0".into(),
            relation: "owner".into(),
            actor: "did:key:owner".into(),
        }
        .abi_encode(),
    ];
    let before = fixture.module.store().serialize();
    for call in calls {
        let measured = fixture.dispatch(&call, 1_000_000).unwrap();
        assert!(
            !measured.precompile.reverted,
            "{:?}",
            measured.precompile.bytes
        );
        let required = measured.precompile.gas_used;
        assert!(required > READ_GAS);
        let exact = fixture.dispatch(&call, required).unwrap();
        assert!(!exact.precompile.reverted);
        assert_eq!(exact.precompile.gas_used, required);
        assert_eq!(exact.precompile.bytes, measured.precompile.bytes);
        assert!(matches!(
            fixture.dispatch(&call, required - 1),
            Err(PrecompileError::OutOfGas)
        ));
    }
    assert_eq!(fixture.module.store().serialize(), before);
}

#[test]
fn query_budget_empty_filtered_results_charge_scans_and_nested_batches_roll_back() {
    let mut fixture = Fixture::new();
    let read = fixture.filtered();
    let result = fixture.dispatch(&read, 1_000_000).unwrap();
    assert!(!result.precompile.reverted);
    let bytes =
        IAcp::filterRelationshipsCall::abi_decode_returns(&result.precompile.bytes).unwrap();
    assert_eq!(bytes.as_ref(), b"[]");
    let required = result.precompile.gas_used;
    assert!(required > 60_000);
    let before = fixture.module.store().serialize();
    let input = batch(vec![read.clone(), batch(vec![read.clone()])]);
    let exact = READ_GAS * 2 + required * 2;
    let output = fixture.dispatch(&input, exact).unwrap();
    assert!(!output.precompile.reverted);
    assert_eq!(output.precompile.gas_used, exact);
    assert!(matches!(
        fixture.dispatch(&input, exact - 1),
        Err(PrecompileError::OutOfGas)
    ));
    let creation_gas = fixture
        .clone()
        .dispatch(&create(), 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    let input = batch(vec![create(), batch(vec![read.clone(), read.clone()])]);
    assert!(matches!(
        fixture.dispatch(&input, exact + creation_gas - 1),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(fixture.module.store().serialize(), before);
    let repeated = batch(vec![read; batch::MAX_CALLS - 1]);
    batch::validate(&repeated).unwrap();
    assert!(matches!(
        fixture.dispatch(&repeated, 1_000_000),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(fixture.module.store().serialize(), before);
}

#[test]
fn query_budget_ordinary_read_failure_keeps_charges_and_rolls_back_prior_writes() {
    let mut fixture = Fixture::new();
    let missing = IAcp::getPolicyCall {
        policyId: B256::ZERO,
    }
    .abi_encode();
    let failure = fixture.dispatch(&missing, 1_000_000).unwrap();
    assert!(failure.precompile.reverted);
    assert!(failure.precompile.gas_used > READ_GAS);
    let before = fixture.module.store().serialize();
    let creation_gas = fixture
        .clone()
        .dispatch(&create(), 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    let input = batch(vec![create(), batch(vec![missing])]);
    let result = fixture.dispatch(&input, 1_000_000).unwrap();
    assert!(result.precompile.reverted);
    assert_eq!(
        result.precompile.gas_used,
        2 * READ_GAS + creation_gas + failure.precompile.gas_used
    );
    assert!(result.logs.is_empty());
    assert_eq!(fixture.module.store().serialize(), before);
}

#[test]
fn query_budget_has_relationship_preserves_exact_matching_and_actor_validation() {
    let mut fixture = Fixture::new();
    for (object, relation, actor, expected) in [
        ("report-0", "owner", "did:key:owner", true),
        ("report-0", "owner", "did:key:absent", false),
        ("", "owner", "did:key:owner", false),
        ("report-0", "", "did:key:owner", false),
    ] {
        let call = IAcp::hasRelationshipCall {
            policyId: fixture.policy,
            resource: "file".into(),
            objectId: object.into(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode();
        let result = fixture.dispatch(&call, 1_000_000).unwrap();
        assert!(!result.precompile.reverted);
        assert_eq!(
            IAcp::hasRelationshipCall::abi_decode_returns(&result.precompile.bytes).unwrap(),
            expected
        );
    }
    let call = IAcp::hasRelationshipCall {
        policyId: fixture.policy,
        resource: "file".into(),
        objectId: "report-0".into(),
        relation: "owner".into(),
        actor: String::new(),
    }
    .abi_encode();
    assert!(fixture.dispatch(&call, 1_000_000).is_err());
}
