//! Component timings; excludes signing, persistence, consensus, and transport.

use std::hint::black_box;
use std::time::Instant;

use vera_acp::Relationship;
use vera_identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
    },
    bulletin::BulletinModule,
    types::{BlockExecCtx, Timestamp, TxExecCtx},
};

const POLICY: &str = "\
name: baseline
resources:
  - name: file
    relations:
      - name: reader
        types: [actor]
    permissions:
      - name: read
        expr: reader
";

fn measure(
    name: &str,
    objects: usize,
    samples: usize,
    operations_per_sample: usize,
    mut operation: impl FnMut(usize),
) {
    let mut timings = Vec::with_capacity(samples);
    let started = Instant::now();
    for index in 0..samples {
        let sample_start = Instant::now();
        operation(index);
        timings.push(sample_start.elapsed());
    }
    let elapsed = started.elapsed();
    timings.sort_unstable();
    let percentile =
        |percent: usize| -> u128 { timings[(samples * percent).div_ceil(100) - 1].as_nanos() };
    println!(
        "{}",
        serde_json::json!({
            "scenario": name,
            "objects": objects,
            "samples": samples,
            "operations_per_sample": operations_per_sample,
            "elapsed_seconds": elapsed.as_secs_f64(),
            "operations_per_second": (samples * operations_per_sample) as f64
                / elapsed.as_secs_f64(),
            "sample_ns": {
                "p50": percentile(50), "p95": percentile(95), "p99": percentile(99),
            },
        })
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(
        args.len() <= 2,
        "usage: module_baseline [objects] [samples]"
    );
    let parse = |index: usize, default: usize| {
        args.get(index).map_or(default, |value| {
            value.parse::<usize>().expect("expected a positive integer")
        })
    };
    let objects = parse(0, 1_000);
    let samples = parse(1, 1_000);
    assert!(objects > 0 && samples > 0, "counts must be positive");
    let owner = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    let reader = Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
    let mut module = AcpModule::new();
    let policy_id = module
        .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    for index in 0..objects {
        module
            .direct_policy_cmd(
                &owner,
                &policy_id,
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: index.to_string(),
                }),
            )
            .unwrap();
    }
    let relationship = Relationship::with_entity("file", "0", "reader", reader.clone());
    module
        .direct_policy_cmd(
            &owner,
            &policy_id,
            PolicyCmd::SetRelationship(relationship.clone()),
        )
        .unwrap();
    let request = AccessRequest {
        actor: Actor(reader),
        operations: vec![Operation {
            object: Object {
                resource: "file".into(),
                id: "0".into(),
            },
            permission: "read".into(),
        }],
    };
    // Warm the code and fixture without inserting cache hits into the measured store.
    for _ in 0..10 {
        assert!(
            module
                .query_verify_access_request(&policy_id, &request)
                .unwrap()
        );
    }
    measure("access_allowed", objects, samples, 1, |_| {
        assert!(black_box(
            module
                .query_verify_access_request(&policy_id, &request)
                .unwrap()
        ));
    });
    module
        .direct_policy_cmd(
            &owner,
            &policy_id,
            PolicyCmd::DeleteRelationship(relationship.clone()),
        )
        .unwrap();
    measure("access_denied", objects, samples, 1, |_| {
        assert!(!black_box(
            module
                .query_verify_access_request(&policy_id, &request)
                .unwrap()
        ));
    });
    module
        .direct_policy_cmd(
            &owner,
            &policy_id,
            PolicyCmd::SetRelationship(relationship.clone()),
        )
        .unwrap();
    measure("relationship_delete_set", objects, samples, 2, |_| {
        module
            .direct_policy_cmd(
                &owner,
                &policy_id,
                PolicyCmd::DeleteRelationship(relationship.clone()),
            )
            .unwrap();
        module
            .direct_policy_cmd(
                &owner,
                &policy_id,
                PolicyCmd::SetRelationship(relationship.clone()),
            )
            .unwrap();
    });
    measure("clone_register_diff", objects, samples, 1, |_| {
        let mut fork = module.clone();
        fork.direct_policy_cmd(
            &owner,
            &policy_id,
            PolicyCmd::RegisterObject(Object {
                resource: "file".into(),
                id: "new".into(),
            }),
        )
        .unwrap();
        let changes = black_box(fork.store().diff_from(module.store()));
        assert_eq!(changes.len(), 1);
    });

    let mut bulletin = BulletinModule::new();
    let context = BlockExecCtx {
        genesis_id: [0; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 1_000,
            block_height: 1,
        },
    };
    let caller = TxExecCtx {
        sequence: 0,
        tx_hash: vec![1; 32],
        signer: owner.to_string(),
    };
    bulletin
        .register_namespace(&mut module, &context, &caller, &owner, "baseline")
        .unwrap();
    let mut payload = [0u8; 256];
    measure("bulletin_post_256_bytes", objects, samples, 1, |index| {
        payload[..8].copy_from_slice(&(index as u64).to_le_bytes());
        bulletin
            .create_post(&module, &caller, &owner, "baseline", &payload, &[1], "")
            .unwrap();
    });
    assert_eq!(
        bulletin.query_namespace_posts("baseline").unwrap().len(),
        samples
    );
}
