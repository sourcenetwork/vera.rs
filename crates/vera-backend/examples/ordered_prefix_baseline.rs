//! Ordered Commonware proof, sync and recovery qualification with local component timings.
//! Timings exclude consensus and transport.
//! The native layout uses canonical ACP key builders and a generated policy ID;
//! object IDs are eight-digit counters and record values are synthetic 256-byte payloads.

mod index {
    pub(super) use vera_backend::native::KeyPrefix;
}
#[cfg(test)]
#[path = "ordered_prefix/index_tests.rs"]
mod index_tests;
#[cfg(test)]
#[path = "ordered_prefix/lifecycle.rs"]
mod lifecycle;
#[cfg(test)]
#[path = "ordered_prefix/permission.rs"]
mod permission;
#[path = "ordered_prefix/proof.rs"]
mod proof;
#[cfg(test)]
#[path = "ordered_prefix/sync.rs"]
mod sync;
#[cfg(test)]
#[path = "ordered_prefix/tests.rs"]
mod tests;

use bytes::Bytes;
use commonware_codec::RangeCfg;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    journal::contiguous::variable, merkle::full, qmdb::current::VariableConfig,
    translator::Translator,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use proof::Store;
use std::{collections::BTreeMap, hint::black_box, time::Instant};
use vera_modules::acp::{
    AcpModule, keys,
    types::{PolicyMarshalingType, PolicyRecord},
};
use zanzibar::{Relationship, Subject};

type LogCodec = ((RangeCfg<usize>, ()), RangeCfg<usize>);

fn config<T: Translator + Default>(
    context: &tokio::Context,
) -> VariableConfig<T, LogCodec, Sequential> {
    let cache = CacheRef::from_pooler(context, NZU16!(4096), NZUsize!(1024));
    VariableConfig {
        merkle_config: full::Config {
            journal_partition: "prefix-mmr".into(),
            metadata_partition: "prefix-mmr-meta".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: variable::Config {
            partition: "prefix-log".into(),
            items_per_section: NZU64!(1024),
            compression: None,
            codec_config: ((RangeCfg::new(0..=1024), ()), RangeCfg::new(0..=65536)),
            page_cache: cache,
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
        },
        grafted_metadata_partition: "prefix-graft".into(),
        translator: T::default(),
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn run<F, Fut>(f: F) -> Fut::Output
where
    F: FnOnce(tokio::Context) -> Fut,
    Fut: std::future::Future,
{
    let dir = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(dir.path())).start(f)
}

fn prefix(object: usize, layout: &str, policy: &PolicyRecord) -> Vec<u8> {
    let text = format!("relationship/policy/rel/document/{object:08}/blocked/");
    match layout {
        "grouped" => Sha256::hash(&[text.as_bytes()]).to_vec(),
        "native" => keys::relationship_generation_prefix(
            &policy.policy.id,
            policy
                .relations
                .pair(&Relationship::new(
                    "document",
                    "",
                    "blocked",
                    Subject::entity_set("group", "", "member"),
                ))
                .unwrap(),
            &keys::relation_prefix("document", &format!("{object:08}"), "blocked"),
        ),
        _ => text.into_bytes(),
    }
}

fn key(object: usize, subject: usize, layout: &str, policy: &PolicyRecord) -> Vec<u8> {
    if layout == "native" {
        let relation = Relationship::new(
            "document",
            format!("{object:08}"),
            "blocked",
            Subject::entity_set("group", format!("{subject:08}"), "member"),
        );
        return keys::relationship_generation_key(
            &policy.policy.id,
            policy.relations.pair(&relation).unwrap(),
            &keys::relationship_storage_key(&relation),
        );
    }
    let mut key = prefix(object, layout, policy);
    key.extend_from_slice(format!("{subject:08}").as_bytes());
    key
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() <= 3,
        "usage: ordered_prefix_baseline [other_objects] [samples] [text|grouped|native]"
    );
    let parse = |i: usize, default| args.get(i).map_or(default, |v| v.parse::<usize>().unwrap());
    let objects = parse(0, 1000);
    let samples = parse(1, 100);
    let layout = args.get(2).map_or("grouped", String::as_str);
    assert!(matches!(layout, "text" | "grouped" | "native"));
    let owner = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        .parse()
        .unwrap();
    let policy = AcpModule::new().create_policy(&owner, "name: documents\nresources:\n  - name: document\n    relations:\n      - name: blocked\n  - name: group\n    relations:\n      - name: member\n", PolicyMarshalingType::ShortYaml).unwrap();
    assert!((1..=100_000).contains(&objects) && (1..=10_000).contains(&samples));
    run(|context| async move {
        let cfg = config(&context);
        let mut db = Store::init(context, cfg, None).await.unwrap();
        let value = Bytes::from(vec![7; 256]);
        let translator = index::KeyPrefix::default();
        let mut buckets = BTreeMap::<_, usize>::new();
        for start in (1..=objects).step_by(128) {
            let mut batch = db.new_batch();
            for object in start..=(start + 127).min(objects) {
                let key = key(object, 0, layout, &policy);
                *buckets.entry(translator.transform(&key)).or_default() += 1;
                batch = batch.write(key, Some(value.clone()));
            }
            let batch = batch.merkleize(&db, None).await.unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.commit().await.unwrap();
        }
        let prefix = prefix(0, layout, &policy);
        println!(
            "layout,other_objects,samples,subjects,proof_component_bytes,generate_p50_ns,generate_p95_ns,verify_p50_ns,verify_p95_ns,index_buckets,max_bucket_records"
        );
        let mut previous = 0;
        for subjects in [0, 1, 8, 64, 256] {
            if subjects > previous {
                let mut batch = db.new_batch();
                for subject in previous..subjects {
                    let key = key(0, subject, layout, &policy);
                    *buckets.entry(translator.transform(&key)).or_default() += 1;
                    batch = batch.write(key, Some(value.clone()));
                }
                let batch = batch.merkleize(&db, None).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.commit().await.unwrap();
            }
            previous = subjects;
            let mut generate = Vec::with_capacity(samples);
            let mut verify = Vec::with_capacity(samples);
            let mut proof_bytes = 0;
            for _ in 0..samples {
                let start = Instant::now();
                let witness = proof::prove(&db, &prefix).await.unwrap();
                generate.push(start.elapsed().as_nanos());
                assert_eq!(witness.entries.len(), subjects);
                proof_bytes = witness.component_bytes();
                let start = Instant::now();
                assert!(black_box(&witness).verify(black_box(&prefix), black_box(&db.root())));
                verify.push(start.elapsed().as_nanos());
            }
            generate.sort_unstable();
            verify.sort_unstable();
            let p50 = (samples * 50).div_ceil(100) - 1;
            let p95 = (samples * 95).div_ceil(100) - 1;
            println!(
                "{layout},{objects},{samples},{subjects},{proof_bytes},{},{},{},{},{},{}",
                generate[p50],
                generate[p95],
                verify[p50],
                verify[p95],
                buckets.len(),
                buckets.values().max().unwrap()
            );
        }
    });
}
