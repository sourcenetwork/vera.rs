# vera.rs

Native Rust implementation of Vera's access control, bulletin, identity and transparency services, using Commonware consensus and storage. Native requests use BLS12-381 signing; optional EVM execution reaches the same module logic.

See [architecture and request flows](docs/architecture.md) for service boundaries,
operator-managed membership, ACP, storage, threshold services, and recovery limits.

## Related Repos

All repos follow gopath convention at `/Users/johnzampolin/go/src/github.com/{org}/{repo}`:

| Repo | Org | Purpose |
|------|-----|---------|
| **vera.rs** | sourcenetwork | This repo — SourceHub rewrite on Commonware |
| **sourcehub** | sourcenetwork | Go implementation (Cosmos SDK) — the upstream being replaced |
| **orbis-rs** | sourcenetwork | Threshold key management — primary consumer of vera.rs (BLS native txs) |
| **defradb.rs** | sourcenetwork | CRDT storage — queries ACP via vera.rs (EVM precompile calls) |
| **bankd-commonware** | mizufinance | Reference: Commonware + REVM chain (infrastructure source for Phase 1) |
| **monorepo** | commonwarexyz | Commonware primitives (consensus, crypto, p2p, storage) |

### Code reuse across repos

| Component | Source repo | Used in vera.rs for |
|-----------|-----------|-------------------|
| Zanzibar engine (relation-tuple graph) | vendored `crates/zanzibar/` (from defradb.rs 8d34d9c) | ACP policy evaluation |
| DID types, identity crate | vendored `crates/identity/` (from defradb.rs 8d34d9c) | DID resolution |
| YAML policy parser, DocumentACP types | vendored `crates/acp/` (from defradb.rs 8d34d9c) | ACP policy creation |
| Simplex consensus, REVM executor, e2e harness | bankd-commonware | Consensus, EVM execution, testing |
| BLS12-381 threshold crypto | commonware monorepo | Block signing, native tx verification |

The development toolchain is pinned to Rust 1.98.0 in `rust-toolchain.toml`.
Linux native-service CI covers module/storage checks, native lifecycle and
recovery, crash injection, and a normal release build.

## Architecture

### Node assembly (`vera-node`)

`verad` parses its CLI into `NodeSettings` and calls `vera_node::run_node`, which
assembles the Commonware actor graph on a tokio runtime and runs until one actor
stops:

- **P2P:** `commonware_p2p::authenticated::discovery` network bootstrapped from
  `peers.json`, with registered channels for votes, certificates, the marshal
  resolver, backfill, block broadcast, DKG, DKG probe, mempool, history, and
  authenticated state transfer. Each channel permits 1,000 messages/second per
  peer with a burst of 64. Commonware sizes queues from retained-peer count
  times burst size, so the burst also controls startup queue allocation.
- **Consensus:** the Commonware `marshal` actor (block archive + finalization
  storage) driven by the glue `orchestrator` running Simplex with a
  `FixedEpocher` over genesis `blocks_per_epoch` and a VRF elector that feeds
  each round's threshold seed to the application.
- **Execution:** the glue `Stateful` actor wrapping `vera-app`'s
  `StatefulVeraApp` (below).
- **DKG/resharing:** the glue `probe` actor discovers the latest epoch when a
  node needs state sync, while the `reshare` actor deals BLS shares for the next
  epoch to the active set returned by `RegistryParticipants` from finalized
  state. Shares persist in `FileSecretStore`. Production validators create
  epoch-0 material together with `verad genesis`, which runs Commonware's
  distributed bootstrap DKG; `trusted_setup` is limited to local dev/test
  networks and is reused by `vera-harness`.
- **Transaction gossip:** `TxGossip` admits RPC-submitted transactions via a
  `MempoolValidator` checked against committed state and forwards them to all
  validators. There is no leader prediction.
- **RPC:** the `vera-jsonrpc` server over the live committed state (below).

The finalization callback persists execution and certificate history together
in one durable batch before returning to Commonware's acknowledgement path. Disk writes run
on the blocking pool; a failed write stops the actor before acknowledgement.
Marshal serves the certificate lookup independently of the stateful callback.
History defaults to RocksDB; the opt-in `regolith-history` build selects Regolith
with explicit synchronous writes and rejects the other backend's directory layout.
See [history storage](docs/history-storage.md) for the format and qualification limits.
Proposal transaction exclusion stops at the published finalized revision, including
the recovered index head, so it does not fetch pruned finalized ancestors.

The application retires cached proposal randomness for rounds behind finalized
execution. The finalized round and newer rounds remain available, and late
elector callbacks cannot reinsert retired seeds. This follows finality progress;
it does not impose a cap on rounds accumulated while finality is stalled.

### Execution (`vera-app` + `vera-executor`)

`StatefulVeraApp` implements `commonware_glue::stateful::Application`: it builds
blocks from the mempool, executes them against forked QMDB batch state, verifies
proposals by re-execution, and hands finalized receipts to a `FinalizedSink`
(`NodeSink`), which indexes blocks, logs, and light blocks and feeds the RPC
subscription channels. Block execution goes through `VeraExecutor`:

```
                     VeraExecutor
                          |
          +---------------+---------------+
          |                               |
     Native BLS txs                  EVM txs
     (processed first)               (processed second)
          |                               |
     BLS verify → did:key             REVM execution
     Deserialize NativeTx                 |
          |                          Precompile calls
     Dispatch to module              hit same modules
          |                               |
          v                               v
    module.method(args)  ←— same Rust code —→  module.method(args)
```

### Precompile addresses

| Address | Module | Purpose |
|---------|--------|---------|
| `0x0810` | ACP | Access control policies (Zanzibar relation tuples) |
| `0x0811` | Bulletin | Coordination / DKG messages / posts |
| `0x0812` | Vera | Identity / JWT token lifecycle |
| `0x0813` | ValidatorRegistry | Validator identity management (feeds resharing) |

### Shared module pattern

Each module is a plain Rust struct. Two thin shims sit on top:
- **Precompile shim:** ABI decode calldata → `module.method(args)`
- **Native tx shim:** BLS verify + deserialize → `module.method(args)`

Business logic lives once.

Provider relay grants use the same operator quorum as administrative changes.
Relay assertions bind a stable `did:opk` actor, native worker, genesis, scope,
grant generation and exact operation. ACP stores the actor as owner; token
records retain the signing relay as issuer. See docs/delegated-policies.md.

Delegated policy creation and editing preserve the actor as owner while a
separate worker signs the submission. Creation and editing require distinct
scopes; existing object-command tokens do not authorize either operation.
Created records bind the owner, worker, signed submission ID and creation
revision. See `docs/delegated-policies.md` for result verification.
Signed caller operation identities deduplicate successful effects across workers.
Outcomes are bounded, expire without allowing ID reuse, and share the execution
rollback boundary. Operator approvals configure the retained outcome budget.
See `docs/operation-identities.md`.

### State and recovery

Finalized execution appends run on the blocking pool and are awaited before
index/status publication. Writer failure stops finalization; the persistence
ordering and atomic history batch are unchanged.

Finalized history writes derived revision-hash and submission-hash mappings in
the same atomic batch as execution records. Historical lookups require the query
index head to match the durable history head and validate the selected record
against the requested hash. Recovery rebuilds missing or rewound mappings in
batches, publishing their head only after completion; normal recovery reuses
a matching index. These reads return execution data, with finality verified
separately by proof consumers.

The node uses `vera-app::OrderedState`: three execution partitions (accounts,
storage, code) and four ordered Commonware current-QMDB partitions (ACP, bulletin,
vera, native sequences). `StatefulVeraApp` seals all seven targets into each proposal
and verifies them by re-execution. An in-memory commitment participates in the same
Commonware coordinator generation, binding the native current-state root to the
selected operation-log targets. It is reconstructed from the durable recovery
anchor, not persisted as an independent journal.

ACP and token lifecycle errors reject proposal execution and re-verification.
Malformed token records encountered during reads or expiry are errors, including a mismatch between the storage key
and the record's token hash. Failed lifecycle work cannot publish its module view. Token expiry uses an ordered
deadline index, leaving invalidated and non-expiring tokens out of each revision's
sweep. See `docs/token-lifecycle.md`.

Pending alternatives retain isolated module snapshots. Database transitions finish
before query maps are published. Startup aligns all journals to marshal's durable
anchor, checks the combined native root, and then enables admission and RPC.
Finalized receipts and certificates are recovered through `FinalizedHistory`.
Native proposals also bind ordered receipt fields and the execution gas limit
through `Block::receipt_commitment`. Re-execution verifies this commitment;
history checks it before persistence and before indexing a recovered record.
See `docs/receipt-commitments.md` for the canonical encoding.

First boot records a durable initialization intent before changing journals, then
publishes `native-genesis.bin` after all seven partitions are durable. Interrupted
initialization can rewind and retry only with the same genesis configuration.
Existing JMT directories or a legacy genesis record require an explicit migration;
this node does not convert them. Missing genesis records alongside finalized
history are rejected instead of resetting state.
Native genesis predating receipt commitments also requires an explicit migration.

Seven authenticated peer resolvers serve bounded operation-log ranges. Fetches
allow up to 64 operations, with eight-operation inspection batches and responses
below the 4 MiB transport limit. Native keys are limited to 64 KiB; values and
commit metadata to 1 MiB. Code-partition peer messages cap values at 1 MiB even
though the older local journal codec permits larger records.

A `[snapshot]` configuration section requests initial authenticated snapshot
catch-up for an admitted member. Startup resumes interrupted synchronization from
durable metadata and uses retained-history replay after snapshot completion.
History and receipts are imported at the actual synchronized revision before
query-state publication and normal execution. See `docs/snapshot-recovery.md`. `OrderedCheckpoint` separately verifies direct
or descendant finality against caller-provisioned trust and authenticates native
log targets through `SyncProof`. Synchronization and recovery check reconstructed
current-state roots before publishing query maps. Operation-log proofs do not
provide historical activity or absence proofs.

`FinalizedHistory` provides 64 KiB record chunks and a bounded reverse-ancestry
import API. The import selection and cursor are durable, and imported history
remains unavailable until recovery at the matching state anchor completes.
Starting an import selects metadata format 3 to prevent older binaries from
discarding its unfinished records. The node serves chunks through Commonware's
resolver on authenticated channel 16. `HistoryPeer::import_next_from` bounds
record and finality-proof assembly, verifies both before persistence and cancels
pending fetches when dropped. Imported certificates retain their verifier material
and any descendants beyond the recovery anchor without advancing execution.
The storage handoff waits for history recovery at the final selected revision.
See `docs/receipt-commitments.md` for protocol and upgrade details.

`vera-backend::native` rebuilds query maps from the retained operation log and
activity bitmap, reading at most 32 operations at a time under partition read
locks. This bounds temporary hydration buffers; all live query maps remain in
memory. Keys sharing their first 256 bytes scan one index bucket.

Current proof requests subscribe before checking for progress and wake when the
node publishes an execution index or finality evidence. A 50 ms fallback handles
custom publishers without notifications. Readers release storage guards before
waiting; existing proof admission and two-second request deadlines still apply.

`vera_getCurrentPermissionProof` returns a selected finalized revision with its
Commonware membership, absence and complete-prefix witnesses. Generation holds
all four native partition read locks and applies aggregate record and byte
limits, then releases the locks before waiting for the revision's certificate.
`VeraClient::verify_current_access` verifies the certificate, caller's minimum
height and evidence before running the shared ACP evaluator. Callers supply any
additional freshness policy. The separate `vera_getPermissionProof` endpoint
requires the requested root to remain available.
`vera_getCurrentRecordProof` captures a native record and its certified revision;
`VeraClient::read_current_record` verifies membership or absence against the requested
module, key and minimum revision. `vera_getCurrentPrefixProof` and
`VeraClient::read_current_prefix` provide complete native prefixes with the same
captured-revision guarantees. `PolicyPrefixResponse::verify_object_owner` derives live
ownership from policy and complete owner evidence at the same certified root.
Deleted policies and archived records are unregistered; retained cleanup records
cannot establish ownership. See `docs/native-relationship-keys.md` for the fresh-state cutover. Standalone `vera_getStateProof` and
`vera_getRelationProof` remain JMT-only and are unavailable on the native node.
Historical native activity proofs are not retained.
Proof RPCs share eight in-flight slots per node; blocking historical certificate
lookups have a separate eight-slot limit. Excess work returns JSON-RPC -32002
with `retryable: true` before starting, and so does exceeding the two-second
current-evidence deadline: the certificate is delayed, not absent. The Rust client exposes these responses
as `ResourceBusy`; `is_throttled()` also recognizes HTTP 429. Other -32002
errors remain ordinary RPC errors, and submissions are not automatically retried.
Receipt polls return no evidence yet when the finalization certificate is absent,
without holding a proof slot while waiting or assembling receipt payloads.
All Rust client RPC calls share bounded response decoding, request-ID/protocol
validation and a ten-second transport deadline; specialized proof methods retain
their narrower byte limits. Cancelling a lookup does not release its
slot until its blocking task finishes.
See `docs/permission-proofs.md` for formats and limits.

Legacy `VeraStateSet` and JMT proof support remain available to explicit library
callers. Native blocks select a tagged commitment encoding and carry four
additional module log targets and a receipt commitment; blocks omitting both
retain their original encoding. Native and legacy application layouts cannot
share one consensus group.

### RPC surfaces

The execution index keeps at most 1,024 recent revisions under a 64 MiB payload
accounting budget. It always retains the newest revision, even if that revision
alone exceeds the budget. Accounting includes vector capacity, strings and byte
payload lengths; it is not a total RSS bound. Readers hold immutable revision
snapshots across proof assembly, so eviction cannot remove their receipts.
Index publication and removal update all lookup maps under one lock.

Revision number/hash, transaction and receipt point queries use bounded archive
reads when absent from memory. The native receipt endpoint uses the same
conversion for recent and historical data, including signer identity and nonce.
Archive reconstruction uses one retained revision and the existing index builder;
it does not populate the global memory index. Archive errors propagate, and
occupied history-read slots return a retryable -32002 response.

Log queries inspect at most 10,000 revisions and 10,000 log entries, accept at
most 64 alternatives per address/topic selector, and return at most 1,000 logs.
The result budget charges 1 MiB for record structures, topics and payload bytes.
Ranges combine resident revisions with archive fallback under shared budgets.
Each range holds one history-read slot and decodes at most 64 MiB of encoded
archive records, charging each record before decoding. The backend must fetch the
record to determine its encoded length.
Queries exceeding a budget fail with RPC code -32005; clients must narrow their
range or filter. Reversed ranges fail with -32602. Results are never silently
truncated. These limits also apply when compatibility methods are enabled on a
native service.

`vera-jsonrpc` limits each batch to 64 calls and each connection to eight
subscriptions, eight queued output messages and eight WebSocket request tasks.
The receive loop stops accepting messages at the task limit; each task retains
its slot until its response enters the output queue. Response and ping writes
time out after ten seconds, and socket closure after one second.

`vera-jsonrpc` serves HTTP + WebSocket JSON-RPC:

| Surface | Methods | Consumer |
|----------|---------|----------|
| `eth_*` | `eth_sendRawTransaction`, `eth_call`, `eth_getStorageAt`, `eth_getTransactionReceipt`, … | defradb.rs, MetaMask, wallets |
| `eth_subscribe` | `newHeads`, `logs` | Indexers, light clients |
| `vera_subscribeHeaders` | `vera_header` notifications; `vera_unsubscribeHeaders` cancellation | Native verified consumers |
| `hub_*` | `vera_nodeStatus`, `vera_sendNativeTx`, `vera_getTransactionReceipt`, `vera_getNativeNonce`, `vera_getStateProof`, `vera_getLightBlock` | orbis-rs, BLS identities, light clients |

### Light-client material

Native receipt-proof requests consult durable execution history when a
submission is absent from the memory index. Archive reads and response-size
checks share the bounded blocking-history slots; cancellation retains the slot
until the blocking work finishes. The response keeps the same receipt
commitment and finality verification contract as the memory-index path.

The direct-finalization cache retains at most 1,024 entries and 64 MiB of
encoded payload buffer capacity. FIFO eviction removes only cached artifacts;
RPC reads fall back to durable history; clients verify the resulting proof.
Oversized artifacts bypass the cache. The epoch-key cache retains genesis and
recent material within 128 entries and 8 MiB of payload buffer capacity. Older
keys are recovered from validated epoch-boundary records using the deployment's
fixed epoch length. These cache limits do not bound total node history.

A `LightBlock` carries the canonical block, the BLS threshold finalization
certificate, and the epoch's group public key; `vera_domain::verify_light_block`
verifies it with one aggregate signature. `ModuleStateProof`s verify module
state against the header's `module_state_root`. Both are served over the `hub_*`
RPC methods above, and signed `GossipHeader`s stream through `vera_subscribeHeaders` as blocks finalize.
The native stream is available with only the header broadcaster configured.
Consumers authenticate headers against their configured finality trust; receiving a
notification alone does not establish its authority.

## Crate Structure

Workspace membership comes from the root `Cargo.toml` (`bin/verad` + `crates/*`).

```
vera.rs/
    bin/verad/                  # CLI binary: validator, devnet, testnet, genesis DKG, client
    crates/
        vera-app/               # Glue stateful Application around the block executor
        vera-backend/           # Concrete QMDB backend: VeraStateSet, BatchState, DbTargets
        vera-cli/               # CLI utilities (backtrace + SIGSEGV handlers)
        vera-client/            # Rust client library (EVM + BLS tx paths, typed queries)
        vera-config/            # Node configuration types (node, network, rpc, execution)
        vera-consensus/         # Consensus application layer: mempool, proposal, traits
        vera-crypto/            # BLS12-381, secp256k1, and JWT utilities
        vera-domain/            # Block, tx, light block, proof, and DKG payload types
        vera-e2e/               # End-to-end test harness (see crates/vera-e2e/README.md)
        vera-executor/          # Block execution: REVM, precompiles, VeraExecutor
        vera-genesis/           # Extended genesis configuration (validators, native mint)
        vera-harness/           # Node manager, cluster builder, observability (test-only)
        vera-indexer/           # Block/tx/light-block indexes backing RPC queries
        vera-jsonrpc/           # eth_* + hub_* JSON-RPC server and subscriptions
        vera-modules/           # ACP, Bulletin, Vera, ValidatorRegistry module logic
        vera-node/              # Validator assembly: p2p, marshal, DKG, stateful glue, RPC
        vera-overlay/           # Overlay state for unpersisted QMDB changes
        vera-permission/        # Permission/record/prefix evidence types and verification
        vera-qmdb/              # Core QMDB abstractions and traits
        vera-state/             # JMT-backed module state trees (RocksDB persistence)
        vera-traits/            # StateDb trait abstractions for storage/consensus
        test-infra/            # Shared test primitives: process, ports, logs, binary resolver
        vera-verifier/          # C shared-library verifier for receipts, records, prefixes and policies
```

## Building

```bash
cargo check                        # type-check workspace
cargo build -p verad                # build binary
cargo test --workspace --exclude vera-e2e  # run non-e2e tests
cargo clippy --all -- -D warnings  # lint
cargo fmt                    # format
```

## Development Principles

Borrowed from [defradb.rs](https://github.com/sourcenetwork/defradb.rs):

**No commented-out code. No TODO comments (create issues instead). No speculative docs.**

| Zone | Contains | Lives in |
|------|----------|----------|
| Past | How we got here | Git history, closed issues/PRs |
| Present | What the code does now | Working tree |
| Future | What we might do next | GitHub issues |

**One concept per file. Small files over large files.** Under 200 lines is fine, 200-400 check if doing one thing, over 400 consider splitting.

**Minimal comments.** Code should be self-documenting. Comment non-obvious WHY, safety invariants, public API docs (`///`). Don't comment what the code does, no TODO/FIXME, no commented-out code.

## Before Committing

1. `cargo check` passes
2. `cargo test --workspace --exclude vera-e2e` passes
3. `cargo clippy --all -- -D warnings` clean
4. `cargo fmt` applied
5. `cargo test -p vera-e2e --test vera_e2e_canonical` passes (requires `cargo build -p verad` first)

The e2e test (`vera_e2e_canonical`) is the baseline gate. It exercises both EVM and BLS transaction paths through a 4-node cluster: create policies, verify receipts, query state back, check cross-node consistency, and assert cluster health. Any change that breaks this test has broken the core pipeline.

## Git Conventions

- Present tense commit messages
- Worktree workflow: `git worktree add ../vera.rs-foo -b feat/foo`

Bulletin posts require a nonempty payload and ACP create-post permission. Proof
bytes are optional application data and are retained unchanged when supplied.
Successful post creation returns and emits the stored content-derived post ID.
The creation event also retains the submitted artifact label.

Token invalidation events identify the token issuer even when an authorized
account performs the revocation; the record retains that account in invalidated_by.

Resource diagnostics are opt-in with `RUST_LOG=warn,vera_diagnostics=debug`.
Every 30 seconds the node logs existing Commonware metrics, resident execution
index counts and accounted revision bytes, finalization/epoch cache entries and
buffer capacity, and history backend memtable/table-reader/block-cache byte counters.
Collection runs off the async executor; disabled diagnostics start no sampler.
Counters are non-atomic and exclude other allocations. Unsupported properties
remain absent, and collection failures are logged rather than reported as zero.

Both `vera_diagnostics=debug` and `vera_publication_diagnostics=debug` log marshal
tip/block delivery to the stateful mailbox, per-revision database apply and query
publication, sink lookup/history/index stages, and sink entry/completion. Delivery
records include mailbox feedback; a tip is not a durable block delivery or an
application acknowledgement. Missing delivery does not establish a network cause.

Synchronization startup ends when Commonware returns its durability handle.
A separate completion event records the original barrier's result, observed wait
from first polling, and total time since synchronization began. These intervals
include scheduling and may exceed storage I/O time. The height is absent until
this state instance has observed a database apply with diagnostics enabled.
Disabled diagnostics retain the original barrier without wrapping it.

Snapshot diagnostics on the same target report database transfer, history handoff,
and query-state hydration, with the selected revision at each stage. Transfer may
advance its selected revision before the history handoff begins.
