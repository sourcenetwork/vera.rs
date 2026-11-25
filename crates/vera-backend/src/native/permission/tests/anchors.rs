//! Term and fork records of one deployment past the complete-prefix budget.

use super::*;
use vera_modules::vera::anchors::{
    ForkRecord, TermRecord, fork_block_of_key, fork_key, fork_prefix, term_key, term_of_key,
    term_prefix,
};
use vera_permission::{MAX_PAGE_RECORDS, ModuleId, PAGE_PROOF_BYTES, PrefixPageRequest};

const TERMS: u64 = 3_000;
const FORKS: u64 = 2_000;

fn term(deployment: B256, term: u64) -> (Vec<u8>, Option<Vec<u8>>) {
    let record = TermRecord {
        deployment,
        term,
        holder: B256::repeat_byte(0xd1),
        cut_height: 100_000 + term,
        cut_block: B256::left_padding_from(&term.to_be_bytes()),
        sequence: 100_000 + term,
        recorded_at: 100_000 + term,
    };
    (term_key(&deployment, term), Some(record.encode()))
}

fn fork(deployment: B256, index: u64) -> (Vec<u8>, Option<Vec<u8>>) {
    let block_hash = B256::left_padding_from(&(index + 1).to_be_bytes());
    let record = ForkRecord {
        deployment,
        sequence: 100_000,
        anchored_height: 100_000,
        anchored_block: B256::repeat_byte(0xaa),
        height: 100_000,
        block_hash,
        term: 0,
        ancestor: block_hash,
        reported_at: 100_000 + index,
    };
    (fork_key(&deployment, &block_hash), Some(record.encode()))
}

/// Read every page of `prefix` and decode each entry with `decode`; `cursor`
/// turns a continuation key into the next page's start.
async fn pages<T>(
    databases: [&NativeDb; 4],
    root: B256,
    prefix: Vec<u8>,
    decode: impl Fn(&vera_permission::current::Entry) -> T,
    cursor: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Vec<T> {
    let mut request = PrefixPageRequest {
        module: ModuleId::Vera,
        prefix: prefix.clone().into(),
        start: prefix.into(),
        limit: MAX_PAGE_RECORDS,
    };
    let mut records = Vec::new();
    loop {
        let page = crate::native::prefix_page_at(databases, root, &request)
            .await
            .unwrap()
            .verify(root, &request, PAGE_PROOF_BYTES)
            .unwrap();
        records.extend(page.entries.iter().map(&decode));
        match page.continuation {
            Some(next) => request.start = cursor(&next).expect("a record key").into(),
            None => return records,
        }
    }
}

#[test]
fn term_and_fork_history_is_read_in_pages_past_the_complete_prefix_budget() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let deployment = B256::repeat_byte(0x42);
            let set = init(&context).await;
            let mut changes: ModuleChanges = Default::default();
            let mut records: Vec<_> = (1..=TERMS)
                .map(|number| term(deployment, number))
                .chain((0..FORKS).map(|index| fork(deployment, index)))
                .collect();
            records.sort();
            changes[ModuleId::Vera.index()] = records;
            let root = apply(&set, changes).await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            let databases = [&*a, &*b, &*h, &*n];

            // One complete-prefix proof cannot hold either history.
            for prefix in [term_prefix(&deployment), fork_prefix(&deployment)] {
                assert!(matches!(
                    crate::native::prefix_proof_at(databases, root, ModuleId::Vera, &prefix).await,
                    Err(crate::BackendError::Permission(
                        vera_permission::PermissionError::Limit
                    ))
                ));
            }

            let terms = pages(
                databases,
                root,
                term_prefix(&deployment),
                |entry| TermRecord::decode(&deployment, &entry.key, &entry.value).unwrap(),
                |key| term_of_key(&deployment, key).map(|next| term_key(&deployment, next)),
            )
            .await;
            assert_eq!(
                terms.iter().map(|record| record.term).collect::<Vec<_>>(),
                (1..=TERMS).collect::<Vec<_>>()
            );

            let forks = pages(
                databases,
                root,
                fork_prefix(&deployment),
                |entry| ForkRecord::decode(&deployment, &entry.value).unwrap(),
                |key| fork_block_of_key(&deployment, key).map(|next| fork_key(&deployment, &next)),
            )
            .await;
            assert_eq!(forks.len() as u64, FORKS);
            assert!(
                forks
                    .windows(2)
                    .all(|pair| pair[0].block_hash < pair[1].block_hash)
            );
        },
    );
}
