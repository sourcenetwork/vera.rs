use super::*;
use vera_modules::acp::{
    pages::{RecordPage, RelationshipPageRequest},
    theorem::TheoremReport,
    types::{
        PolicyCmdResult, PolicyCommandRequest, PolicyCreation, PolicyRecord, RelationshipRecord,
        SuppliedMetadata,
    },
};
use vera_modules::types::Timestamp;

const POLICY: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader\n";

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
                    seconds: 10,
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
    fn call(&mut self, call: impl SolCall) -> alloy_primitives::Bytes {
        let output = dispatch(
            &mut self.acp,
            &mut self.vera,
            &self.block,
            &self.tx,
            &call.abi_encode(),
            1_000_000,
        )
        .unwrap();
        assert!(!output.precompile.reverted, "{:?}", output.precompile.bytes);
        output.precompile.bytes
    }
    fn command(&mut self, policy: B256, command: PolicyCmd) -> PolicyCmdResult {
        let output = self.call(IAcp::executePolicyCommandCall {
            policyId: policy,
            request: serde_json::to_vec(&PolicyCommandRequest {
                command,
                metadata: Default::default(),
            })
            .unwrap()
            .into(),
        });
        let bytes = IAcp::executePolicyCommandCall::abi_decode_returns(&output).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    fn create(&mut self) -> alloy_primitives::B256 {
        let output = self.call(IAcp::createPolicyWithOptionsCall {
            request: serde_json::to_vec(&PolicyCreation {
                policy: POLICY.into(),
                marshal_type: PolicyMarshalingType::ShortYaml,
                required_specification: None,
                metadata: SuppliedMetadata {
                    blob: b"policy".to_vec(),
                    ..Default::default()
                },
            })
            .unwrap()
            .into(),
        });
        let bytes = IAcp::createPolicyWithOptionsCall::abi_decode_returns(&output).unwrap();
        let record: PolicyRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record.metadata.creation_ts, self.block.timestamp);
        assert_eq!(record.metadata.tx_signer, self.tx.signer);
        assert_eq!(record.supplied_metadata.blob, b"policy");
        record.policy.id.parse().unwrap()
    }
}

#[test]
fn native_lifecycle_dispatch_preserves_metadata_and_enforces_ownership() {
    let mut f = Fixture::new();
    let policy = f.create();
    f.call(IAcp::executePolicyCommandCall {
        policyId: policy,
        request: serde_json::to_vec(&PolicyCommandRequest {
            command: PolicyCmd::RegisterObject(Object {
                resource: "file".into(),
                id: "report".into(),
            }),
            metadata: SuppliedMetadata {
                blob: b"object".to_vec(),
                ..Default::default()
            },
        })
        .unwrap()
        .into(),
    });
    f.call(IAcp::transferObjectCall {
        policyId: policy,
        resource: "file".into(),
        objectId: "report".into(),
        newOwner: "did:key:next".into(),
    });
    let output = f.call(IAcp::getObjectRegistrationCall {
        policyId: policy,
        resource: "file".into(),
        objectId: "report".into(),
    });
    let bytes = IAcp::getObjectRegistrationCall::abi_decode_returns(&output).unwrap();
    let record: Option<RelationshipRecord> = serde_json::from_slice(&bytes).unwrap();
    let record = record.unwrap();
    assert_eq!(record.metadata.owner_did, "did:key:next");
    assert_eq!(record.supplied_metadata.blob, b"object");
    let output = f.call(IAcp::checkManagementAuthorityCall {
        policyId: policy,
        resource: "file".into(),
        objectId: "report".into(),
        relation: "reader".into(),
        actor: "did:key:owner".into(),
    });
    assert!(!IAcp::checkManagementAuthorityCall::abi_decode_returns(&output).unwrap());
    let output = f.call(IAcp::evaluateTheoremCall { policyId: policy, source: "Authorizations { file:report#read@did:key:next } Delegations { !did:key:owner > file:report#reader }".into() });
    let bytes = IAcp::evaluateTheoremCall::abi_decode_returns(&output).unwrap();
    let report: TheoremReport = serde_json::from_slice(&bytes).unwrap();
    assert!(report.ok);
    assert_eq!(report.theorem_count, 2);
    let output = f.call(IAcp::getRelationshipsPageCall {
        policyId: policy,
        request: serde_json::to_vec(&RelationshipPageRequest {
            selector: RelationshipSelector {
                object_selector: None,
                relation_selector: None,
                subject_selector: None,
            },
            after: None,
        })
        .unwrap()
        .into(),
    });
    let bytes = IAcp::getRelationshipsPageCall::abi_decode_returns(&output).unwrap();
    let page: RecordPage<RelationshipRecord> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(page.records.len(), 1);
    assert!(page.next.is_none());
    f.block.timestamp = Timestamp {
        seconds: 20,
        block_height: 2,
    };
    f.call(IAcp::editPolicyMetadataCall {
        policyId: policy,
        metadata: serde_json::to_vec(&SuppliedMetadata::default())
            .unwrap()
            .into(),
    });
    f.call(IAcp::editPolicyCall {
        policyId: policy,
        policy: POLICY.as_bytes().to_vec().into(),
        marshalType: 1,
    });
    assert_eq!(
        f.acp
            .query_policy(&hex::encode(policy))
            .unwrap()
            .last_modified,
        Some(f.block.timestamp.clone())
    );
    f.tx.signer = "did:key:next".into();
    let before = f.acp.store().serialize();
    let call = IAcp::deletePolicyCall { policyId: policy }.abi_encode();
    let rejected = dispatch(&mut f.acp, &mut f.vera, &f.block, &f.tx, &call, 1_000_000).unwrap();
    assert!(rejected.precompile.reverted);
    assert_eq!(f.acp.store().serialize(), before);
    f.tx.signer = "did:key:owner".into();
    let output = f.call(IAcp::deletePolicyCall { policyId: policy });
    assert!(IAcp::deletePolicyCall::abi_decode_returns(&output).unwrap());
    f.acp.validate_restored_state().unwrap();
    let output = f.call(IAcp::getPoliciesCall {});
    let bytes = IAcp::getPoliciesCall::abi_decode_returns(&output).unwrap();
    assert!(
        serde_json::from_slice::<Vec<PolicyRecord>>(&bytes)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn failed_batch_restores_deleted_policy_and_low_gas_cannot_mutate() {
    let mut f = Fixture::new();
    let policy = f.create();
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let generated = f
        .acp
        .query_generate_commitment(
            &hex::encode(policy),
            std::slice::from_ref(&object),
            &Actor(Did::new(&f.tx.signer).unwrap()),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = f.command(
        policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
    )
    else {
        panic!("expected commitment")
    };
    f.tx.signer = "did:key:later-owner".into();
    f.block.timestamp = Timestamp {
        seconds: 20,
        block_height: 2,
    };
    f.command(policy, PolicyCmd::RegisterObject(object));
    f.tx.signer = "did:key:owner".into();
    f.block.timestamp = Timestamp {
        seconds: 30,
        block_height: 3,
    };
    assert!(matches!(
        f.command(
            policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: generated.proofs[0].clone(),
            }
        ),
        PolicyCmdResult::RevealRegistration { event: Some(_), .. }
    ));
    f.acp.validate_restored_state().unwrap();
    let before = f.acp.store().serialize();
    let deletion = IAcp::deletePolicyCall { policyId: policy }.abi_encode();
    assert!(matches!(
        dispatch(
            &mut f.acp,
            &mut f.vera,
            &f.block,
            &f.tx,
            &deletion,
            WRITE_GAS - 1
        ),
        Err(PrecompileError::OutOfGas)
    ));
    let batch = IAcp::batchCallsCall {
        calls: vec![
            deletion.into(),
            IAcp::getPolicyCall { policyId: policy }.abi_encode().into(),
        ],
    }
    .abi_encode();
    let result = dispatch(&mut f.acp, &mut f.vera, &f.block, &f.tx, &batch, 1_000_000).unwrap();
    assert!(result.precompile.reverted);
    assert!(result.logs.is_empty());
    assert_eq!(f.acp.store().serialize(), before);
    f.acp.validate_restored_state().unwrap();
}

#[test]
fn relationship_selector_supports_resource_only_and_rejects_missing_resource() {
    use vera_modules::acp::types::ObjectSelector;
    let selector = build_relationship_selector("file", "", "", "").unwrap();
    assert!(
        matches!(selector.object_selector, Some(ObjectSelector::ResourcePredicate(name)) if name == "file")
    );
    assert!(build_relationship_selector("", "report", "", "").is_err());
}
