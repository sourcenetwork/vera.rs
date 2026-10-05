//! Fixed-fixture component timings; these do not measure distributed consensus latency.

#[path = "component_baseline/certificate.rs"]
mod certificate;
#[path = "component_baseline/lifecycle.rs"]
mod lifecycle;

use serde_json::json;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::NativeTx;
use vera_modules::acp::{AcpModule, types::PolicyMarshalingType};
use vera_permission::{AccessRequest, Actor, Object, Operation, PERMISSION_LIMITS, capture_reads};

fn measure(name: &str, mut operation: impl FnMut()) {
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_millis(200) {
        operation();
    }
    let mut samples = Vec::new();
    let mut iterations = Vec::new();
    for _ in 0..9 {
        let start = Instant::now();
        let mut count = 0_u64;
        while start.elapsed() < Duration::from_millis(100) {
            operation();
            count += 1;
        }
        samples.push(start.elapsed().as_secs_f64() * 1e9 / count as f64);
        iterations.push(count);
    }
    println!(
        "{}",
        json!({"name": name, "unit": "ns/op", "samples": samples, "iterations": iterations})
    );
}

fn measure_prepared<S, T>(
    name: &str,
    mut prepare: impl FnMut() -> S,
    mut operation: impl FnMut(&mut S) -> T,
) {
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_millis(200) {
        let mut state = prepare();
        black_box(operation(black_box(&mut state)));
        black_box(&state);
    }
    let mut samples = Vec::new();
    let mut iterations = Vec::new();
    for _ in 0..9 {
        let window = Instant::now();
        let mut elapsed = Duration::ZERO;
        let mut count = 0_u64;
        while count == 0 || window.elapsed() < Duration::from_millis(100) {
            let mut state = prepare();
            let start = Instant::now();
            let result = operation(black_box(&mut state));
            black_box(&state);
            elapsed += start.elapsed();
            black_box(result);
            count += 1;
        }
        samples.push(elapsed.as_secs_f64() * 1e9 / count as f64);
        iterations.push(count);
    }
    println!(
        "{}",
        json!({"name": name, "unit": "ns/op", "samples": samples, "iterations": iterations})
    );
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("build with --release");
        std::process::exit(2);
    }
    println!(
        "{}",
        json!({"format_version": 1, "fixture_version": 2,
        "kind": "configuration", "samples": 9, "sample_ms": 100, "warmup_ms": 200})
    );
    let signer = BlsSigner::new(42_u64.into(), 9001).unwrap();
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, vec![7; 256].into())
        .unwrap();
    let tx = NativeTx::decode_wire(&wire).unwrap();
    let message = tx.signing_data();
    measure("native_bls_verify", || {
        let did = vera_crypto::bls::verify_and_identify(
            black_box(tx.bls_pubkey.as_slice()),
            black_box(&message),
            black_box(tx.signature.as_slice()),
        )
        .unwrap();
        assert_eq!(did, signer.did());
    });
    let owner = signer.did().parse().unwrap();
    let mut module = AcpModule::new();
    let policy = module.create_policy(&owner,
        "name: benchmark\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n",
        PolicyMarshalingType::ShortYaml).unwrap();
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    module
        .direct_policy_cmd(
            &owner,
            &policy.policy.id,
            vera_modules::acp::types::PolicyCmd::RegisterObject(object.clone()),
        )
        .unwrap();
    let request = AccessRequest {
        actor: Actor(owner),
        operations: vec![Operation {
            object,
            permission: "read".into(),
        }],
    };
    measure("acp_owner_read_capture", || {
        let reads = capture_reads(
            black_box(module.store().clone()),
            black_box(&policy.policy.id),
            black_box(&request),
            PERMISSION_LIMITS,
        )
        .unwrap();
        assert!(!reads.is_empty());
        black_box(reads);
    });
    let (light, trusted) = certificate::fixture();
    measure("consensus_certificate_verify", || {
        black_box(vera_domain::verify_light_block(black_box(&light), black_box(&trusted)).unwrap());
    });
    lifecycle::run();
}
