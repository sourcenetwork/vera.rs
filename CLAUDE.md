# vera.rs

Native Rust implementation of Vera's access control, bulletin, identity and transparency services, using Commonware consensus and storage. Native requests use BLS12-381 signing. Pipelined deployments disable legacy EVM transactions; rotating deployments retain optional compatibility execution.

See [architecture and request flows](docs/architecture.md) for service boundaries,
operator-managed membership, ACP, storage, threshold services, and recovery limits.

## First-release scope

Follow the [first-release checklist](docs/release-qualification.md#first-release-crates-and-daemon-artifacts)
for crate publication and daemon release automation. Qualify the selected Orbis
service version; four-host WAN qualification is a follow-up. Retain DKG
bootstrap/resharing and existing verification checks.
Do not reopen completed ACP v1, storage or measurement milestones to complete
publishing. Record candidate-specific validation when changing dependencies.

## Related Repos

Related repositories are independent checkouts; discover their paths rather than assuming a developer-specific directory layout:

| Repo | Org | Purpose |
|------|-----|---------|
| **vera.rs** | sourcenetwork | This repo — SourceHub rewrite on Commonware |
| **vera** | sourcenetwork | Existing Go service implementation used for behavior comparisons |
| **orbis-rs** | sourcenetwork | Application threshold signing and encryption, using native authorization, bulletin and ring records |
| **defradb.rs** | sourcenetwork | Document storage with native signed submissions and verified ACP evidence |
| **trust-api** | sourcenetwork | Separate Go gateway for authentication, relay workers and native APIs |
| **backbone** | sourcenetwork | Shared Rust clients and verification used by native consumers |
| **regolith** | sourcenetwork | Defra document storage and Vera finalized-history backend |
| **bankd-commonware** | mizufinance | Reference: Commonware + REVM chain (infrastructure source for Phase 1) |
| **monorepo** | commonwarexyz | Commonware primitives (consensus, crypto, p2p, storage) |

### Code reuse across repos

| Component | Source repo | Used in vera.rs for |
|-----------|-----------|-------------------|
| Zanzibar engine (relation-tuple graph) | vendored `crates/vera-zanzibar/` (from defradb.rs 8d34d9c) | ACP policy evaluation |
| DID types, identity crate | vendored `crates/vera-identity/` (from defradb.rs 8d34d9c) | DID resolution |
| YAML policy parser, DocumentACP types | vendored `crates/vera-acp/` (from defradb.rs 8d34d9c) | ACP policy creation |
| Simplex consensus, REVM executor, e2e harness | bankd-commonware | Consensus, EVM execution, testing |
| BLS12-381 threshold crypto | commonware monorepo | Block signing, native tx verification |

The development toolchain is pinned to Rust 1.99.1 in `rust-toolchain.toml`.
Linux native-service CI covers module/storage checks, native lifecycle and
recovery, crash injection, and a normal release build.
A hosted macOS arm64 job runs the embedded node's test targets.

## Architecture

### Node assembly (`vera-node`)

`verad` parses its CLI into `NodeSettings` and calls `vera_node::run_node`, which
assembles the Commonware actor graph on a tokio runtime and runs until one actor
stops:

- **P2P:** `commonware_p2p::authenticated::discovery` network bootstrapped from
  `peers.json`, with registered channels for votes, certificates, the marshal
  resolver, backfill, block broadcast, DKG, DKG probe, mempool, history,
  authenticated state transfer, and the devices' term exchange. Each channel permits 1,000 messages/second per
  peer with a burst of 64. Commonware sizes queues from retained-peer count
  times burst size, so the burst also controls startup queue allocation.
  The listener and the genesis DKG run Commonware's recommended discovery
  profile; `[network.discovery]` states individual settings instead, and an
  absent one keeps Commonware's value. `testnet`, `devnet`, the e2e harness and
  the embedded node state `DiscoveryConfig::local()`, the values of Commonware's
  local profile. The recommended profile has not been exercised between
  separate hosts. See docs/operating.md#configuration-knobs-operators-own.
- **Consensus:** the Commonware `marshal` actor (block archive + finalization
  storage) driven by the glue `orchestrator` running Simplex with a
  `FixedEpocher` over genesis `blocks_per_epoch`. The elector uses bounded leader
  terms when genesis selects pipelining; rotating deployments alone populate
  per-view VRF seeds for compatibility execution.
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
- **Watchdog:** a finality stall stops the node only while it is connected to
  enough peers for a voting quorum, or is the only validator. The peer count
  in `vera_nodeStatus` is sampled from the network's connection metric.
- **Backups:** `NodeOptions::backup` runs the same actors under a network key
  that is in no committee: a verify-only scheme, an observing reshare actor,
  no share, and submissions refused with a retryable error. A validator's
  network key stays its validator key, because Commonware accepts votes and
  epoch-probe replies by that key. `NodeOptions::devices` adds backups to
  every tracked peer set as secondary peers, so a validator accepts them and
  never dials them. A backup's watchdog counts a stall only while a peer is
  connected, and its restart re-arms state sync once the deployment may have
  moved past the retained consensus revisions. A backup keeps certificates of
  an epoch it has not entered (Commonware's orchestrator drops them), at most
  256 within 1 MiB, and
  replays them once marshal has processed the epoch's last block. Nodes with
  a peer keep the daemon's burst on the block-fetch channel and a burst of at
  least eight on the state and history transfer channels. A start returns
  once the node has applied the finalized blocks its archive holds or after
  30 seconds, whichever comes first, and the
  snapshot floor refresh waits while the synchronization handoff runs.

The finalization callback persists execution and certificate history together
in one durable batch before returning to Commonware's acknowledgement path. Disk writes run
on the blocking pool; a failed write stops the actor before acknowledgement.
Marshal serves the certificate lookup independently of the stateful callback.
History uses Regolith with explicit synchronous writes and rejects foreign
directory layouts before opening the database.
See [history storage](docs/history-storage.md) for the format and qualification limits.
`history_retention` (daemon default none) removes records below an epoch-aligned
floor, keeping only the floor's parent below it; reads below it fail with
`HistoryPruned`, and an importer from a pruned peer adopts a floor. See
[retention and the floor](docs/history-storage.md#retention-and-the-floor).
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

Operator policies list secp256k1 keys in hexadecimal and Ed25519 or P-256 keys
as `did:key`; every operator signs the same administrative digest. See
docs/consensus-membership.md#operator-keys.
Provider relay grants use the same operator quorum as administrative changes.
Relay assertions bind a stable `did:opk` actor, native worker, genesis, scope,
grant generation and exact operation. ACP stores the actor as owner; token
records retain the signing relay as issuer. See docs/delegated-policies.md.

Delegated policy creation and editing preserve the actor as owner while a
separate worker signs the submission. Creation and editing require distinct
scopes; existing object-command tokens do not authorize either operation.
Created records bind the owner, worker, signed submission ID and creation
revision. See `docs/delegated-policies.md` for result verification.
Delegation issuers are secp256k1 (ES256K), Ed25519 (EdDSA) or P-256 (ES256)
`did:key` actors; the key type fixes the token algorithm. Ed25519 and P-256
actors have one DID spelling and one signature encoding. Relay issuers remain
secp256k1.
A secp256k1 key is accepted in four spellings (compressed or uncompressed,
Base58BTC or Base64URL) and is one actor: state, results, events and proof
evaluation name its canonical compressed Base58BTC DID, in token issuers and
subjects, relationship subjects, `actor`-resource objects, checks, decisions
and collaborators. `vera_crypto::actor::canonical_did` defines that spelling
and `vera_modules::actor` applies it; other identifiers are compared as
written. Operation commitments and digests still cover the request as its
caller wrote it. See docs/delegated-policies.md#one-actor-per-key.
Signed caller operation identities deduplicate successful effects across workers
and across spellings of the actor's key.
Outcomes are bounded, expire without allowing ID reuse, and share the execution
rollback boundary. Operator approvals configure the policy-command lead:
identities on graph commands may lie up to that lead ahead of execution (600
seconds by default, at most 30 days); other operations keep 600 seconds, and
relay assertions still last at most 600 seconds. Outcomes claimed with more than
600 seconds left count against a separate long-lived budget, so each class's
operator-set budget refuses only its own new outcomes. `bearerPolicyCmds` applies an ordered list of up to 64 graph
commands in order, all or none, under one signed operation digest and one outcome.
See `docs/operation-identities.md`.

### State and recovery

Finalized execution appends run on the blocking pool and are awaited before
index/status publication. Writer failure stops finalization; the persistence
ordering and atomic history batch are unchanged.

Finalized history writes derived revision-hash and submission-hash mappings in
the same atomic batch as execution records. Historical lookups require the query
index head to match the durable history head and validate the selected record
against the requested hash. Recovery rebuilds missing or mismatched mappings in
batches, publishing their head only after completion; normal recovery reuses
a matching index, and a rewind of at most 1,024 revisions removes only the
discarded revisions' mappings together with the head rewind. These reads return execution data, with finality verified
separately by proof consumers.

The node uses `vera-app::OrderedState`: three execution partitions (accounts,
storage, code) and four ordered Commonware current-QMDB partitions (ACP, bulletin,
vera, native sequences). `StatefulVeraApp` seals all seven targets into each proposal
and verifies them by re-execution. An in-memory commitment participates in the same
Commonware coordinator generation, binding the native current-state root to the
selected operation-log targets. It is reconstructed from the durable recovery
anchor, not persisted as an independent journal.

A module call that fails on what its caller sent (an unknown selector, calldata
that does not decode, an argument out of bounds) rejects that request with a
failed receipt, and the block goes on. Only an error marked as the node's own
(`precompiles::internal_fault`: stored membership or policy state that does not
read back) fails the block, including inside an ACP batch. A call that exhausts
its gas allowance is a failure too: nothing it wrote is kept, a native request
is charged its full limit, and a contract's call returns no gas.
A refused native request's receipt names why: `vera_domain::Refusal` carries the
module, a `RefusalKind` that the receipt commitment binds, and the module's
message, bounded to 1,024 bytes and not committed because it embeds parser and
library text. A module error's variant decides its kind
(`vera_executor::precompiles::refusal`). A refusal is charged what the call
reported, at least 5,000; `out_of_gas` and a module panic keep the full limit.
`vera-client` returns `ClientError::Refused` for a refused native request and
`TxReverted` for an EVM revert; a contract caller still gets the message as
revert data. See `docs/receipt-commitments.md#refusals`.
Only a transaction's own call to a module carries its signer's authority. A call
made by contract code, DELEGATECALL and CALLCODE included, has no signer, and a
method that needs one refuses it.
EVM transactions execute only in their canonical EIP-2718 encoding, and a legacy
transaction must carry a chain ID. Blob (type 3) transactions are refused at
admission and execution. ACP and token lifecycle errors reject proposal execution and re-verification.
Malformed token records encountered during reads or expiry are errors, including a mismatch between the storage key
and the record's token hash. Failed lifecycle work cannot publish its module view. Token expiry uses an ordered
deadline index, leaving invalidated tokens out of each revision's sweep. Every
token record names an authorized account and an expiry time. See `docs/token-lifecycle.md`.

Pending alternatives retain isolated module snapshots. Database transitions finish
before query maps are published. Startup aligns all journals to marshal's durable
anchor, checks the combined native root, and then enables admission and RPC.
Finalized receipts and certificates are recovered through `FinalizedHistory`.
Native proposals also bind ordered receipt fields, including each refusal's
module and kind, and the execution gas limit through `Block::receipt_commitment`. Re-execution verifies this commitment;
history checks it before persistence and before indexing a recovered record.
See `docs/receipt-commitments.md` for the canonical encoding.

First boot records a durable initialization intent before changing journals, then
publishes `native-genesis.bin` after all seven partitions are durable. Interrupted
initialization can rewind and retry only with the same genesis configuration.
Foreign state layouts and incompatible genesis records are rejected.
Missing genesis records alongside finalized history are rejected instead of
resetting state. A persisted native genesis must contain the expected receipt
commitment.

`genesis.json` and `config.toml` reject keys they do not define. Genesis
validators need distinct addresses and consensus keys, and a node does not start
without at least one. The ValidatorRegistry slot layout is defined once, in
`vera_modules::validator_registry::layout`, for execution and genesis.

Seven authenticated peer resolvers serve bounded operation-log ranges. Fetches
allow up to 64 operations, with eight-operation inspection batches and responses
below the 4 MiB transport limit. Native keys are limited to 64 KiB; values and
commit metadata to 1 MiB. Code-partition peer messages cap values at 1 MiB even
though the older local journal codec permits larger records. A request for a
size the server has not reached yet waits for it, without the database lock,
for up to one second (at most 64 waiting per database) before it is refused.

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
resolver on authenticated channel 16, producing each chunk on the blocking pool,
two at a time; further requests are dropped and retried by the importer.
`HistoryPeer::import_next_from` bounds
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
cannot establish ownership. See `docs/native-relationship-keys.md` for the fresh-state cutover. `vera_getStateProof` and `vera_getRelationProof` are not registered. Record and
complete-prefix reads use the authenticated native endpoints.
Historical native activity proofs are not retained.
Proof RPCs share eight in-flight slots per node, including `vera_getLightBlock`
while it assembles a cached revision; blocking historical certificate
lookups have a separate eight-slot limit. A current-evidence request whose
minimum height is more than 256 revisions above the published head is refused
with the retryable -32002 at once; the lead is a policy, since no minimum
interval separates revisions. Excess work returns JSON-RPC -32002
with `retryable: true` before starting, and so does exceeding the two-second
current-evidence deadline: the certificate is delayed, not absent. The Rust client exposes these responses
as `ResourceBusy`; `is_throttled()` also recognizes HTTP 429. Other -32002
errors remain ordinary RPC errors, and submissions are not automatically retried.
The client's sign-and-submit helpers advance a signer's sequence only after the
node admits the request; receipt polling rides out connection failures within
its time budget, and its errors name the accepted submission.
Receipt polls return no evidence yet when the finalization certificate is absent,
without holding a proof slot while waiting or assembling receipt payloads.
All Rust client RPC calls share bounded response decoding, request-ID/protocol
validation and a ten-second transport deadline; specialized proof methods retain
their narrower byte limits. Cancelling a lookup does not release its
slot until its blocking task finishes.
See `docs/permission-proofs.md` for formats and limits.

The application uses ordered QMDB partitions for execution and native modules.
Native blocks select a tagged commitment encoding and carry four additional
module log targets and a receipt commitment. Blocks lacking these commitments,
or carrying a target with an empty range, are rejected by the application
without executing them. Legacy block decoding remains separate from the native application. Proofs
use Commonware QMDB only; retired JMT proof formats are not supported.

### RPC surfaces

The execution index keeps at most 1,024 recent revisions under a 64 MiB payload
accounting budget. It always retains the newest revision, even if that revision
alone exceeds the budget. Accounting includes vector capacity, strings and byte
payload lengths; it is not a total RSS bound. Readers hold immutable revision
snapshots across proof assembly, so eviction cannot remove their receipts.
Index publication and removal update all lookup maps under one lock.

Revision number/hash, transaction and receipt point queries use bounded archive
reads when absent from memory. The native receipt endpoint uses the same
conversion for recent and historical data, including signer identity, nonce and refusal.
Archive reconstruction uses one retained revision and the existing index builder;
it does not populate the global memory index. Archive errors propagate, and
occupied history-read slots return a retryable -32002 response.

Log queries inspect at most 10,000 revisions and 10,000 log entries, accept at
most 64 alternatives per address/topic selector over at most four topic
positions, and return at most 1,000 logs. `eth_subscribe("logs")` applies the
same selector limits and rejects a larger filter with -32602. A `blockHash`
filter selects that one revision; it cannot be combined with a range, and an
unknown hash fails with -32602.
The result budget charges 1 MiB for record structures, topics and payload bytes.
Ranges combine resident revisions with archive fallback under shared budgets.
Each range holds one history-read slot and decodes at most 64 MiB of encoded
archive records, charging each record before decoding. The backend must fetch the
record to determine its encoded length.
Queries exceeding a budget fail with RPC code -32005; clients must narrow their
range or filter. Reversed ranges fail with -32602. Results are never silently
truncated. These limits also apply when compatibility methods are enabled on a
native service.

`eth_call`, `eth_estimateGas` and `vera_simulateNativeCall` execute on the
blocking pool against a snapshot of module state, so they hold neither an
async worker nor the lock finalization publishes under. They share four slots
per node, and up to 64 more callers wait at most two seconds for one; a caller
beyond the 64, or one whose wait expires, gets the retryable -32002. A slot
stays taken until its execution ends. Each observes the head revision's height
and time, the deployment's genesis record and its membership limit, and writes
nothing. `eth_call` carries no signer, so module writes revert there.
`vera_simulateNativeCall` dry-runs a module call as a named DID without a
signature or sequence and returns success or the refusal its receipt would
name, gas and logs.
It is unauthenticated: it answers what a DID could do and authorizes nothing.
Its input is bounded like a native submission. See `docs/simulation.md`.
An estimate is a limit the call succeeded with. The search stops within 1/64 of
its upper bound and starts from the gas used at the cap, so a call that uses
less gas under a lower limit can be estimated well above its smallest
sufficient limit. `eth_getCode` returns empty bytes for an account without
code. Account state
reads answer for current state only: an explicit block number or `earliest`
fails with -32004, as it does for `eth_call`.

`vera-jsonrpc` limits each batch to 64 calls and each connection to eight
subscriptions, eight queued output messages and eight WebSocket request tasks.
The receive loop stops accepting messages at the task limit; each task retains
its slot until its response enters the output queue. Response and ping writes
time out after ten seconds, and socket closure after one second.

`vera-jsonrpc` serves HTTP + WebSocket JSON-RPC:

| Surface | Methods | Consumer |
|----------|---------|----------|
| `eth_*` | `eth_sendRawTransaction`, `eth_call`, `eth_getStorageAt`, `eth_getTransactionReceipt`, … | Optional compatibility clients; legacy submissions are disabled in pipelined mode |
| `eth_subscribe` | `newHeads`, `logs` | Indexers, light clients |
| `vera_subscribeHeaders` | `vera_header` notifications; `vera_unsubscribeHeaders` cancellation | Native verified consumers |
| `vera_*` | `vera_nodeStatus`, `vera_sendNativeTx`, `vera_simulateNativeCall` (unauthenticated dry run), `vera_getTransactionReceipt`, `vera_getNativeNonce`, current permission/record proofs and light blocks | Native Defra, Orbis, Trust and verification clients |

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
verifies it with one aggregate signature, weighting the vote and seed signatures
with operating-system randomness. Native record, prefix and permission
evidence authenticates module state against that finalized revision.
`GossipHeader`s carrying the finalization certificate stream through
`vera_subscribeHeaders` as revisions finalize.
The native stream is available with only the header broadcaster configured.
A subscriber more than 64 headers behind resumes at the oldest retained header;
the skipped heights are not replayed.
Consumers authenticate headers against their configured finality trust; receiving a
notification alone does not establish its authority.

### Embedded node

`vera_node::EmbeddedNode` hosts a single-validator deployment inside another
program on a dedicated thread and Commonware runtime. Hosts call the node's
method table in-process through `vera_jsonrpc::LocalRpc`; an RPC listener is
optional. The deployment's authority is the account's operator policy, its
consensus share comes from operating-system randomness, and a tripped watchdog
stops the node without exiting the host. `stop` holds back new proposals and
waits up to two seconds for proposed blocks to finalize, so the next start
does not wait out a view. A lone validator waits for a first
request before proposing, with a ten-second heartbeat. The wait runs before the
proposal request reaches the stateful actor, so a block's finality evidence is
published as it finalizes. The first proposal after a start does not wait, and
a solo genesis lifts the five-second limit on timestamp steps so an idle or
paused deployment stays on the clock. `EmbeddedConfig::thread_setup` runs on the node
thread before its runtime is built, so every node thread is created afterwards
and, on Linux, inherits the CPU affinity it sets. `SoloGenesis::policies` seeds ACP policies at
genesis under counters and owners the host chooses, so a host keeps the policy
identifiers it already uses. `thread_budget()` reports the
node, worker, blocking, verification and history-store thread counts.
`EmbeddedConfig::history_memory` sets the history store's block-cache and
write-buffer budgets, 8 MiB and 4 MiB by default; the daemon keeps Regolith's
512 MiB and 64 MiB. `EmbeddedConfig::sizing` sets the peer-channel burst and
QMDB page cache allocated at start, 1 and 256 pages by default against the
daemon's 64 and 4,096. A stopped node's directory is free even while clones of
its `LocalRpc` survive, and starting on a directory in use fails with
`EmbedError::DirectoryInUse`; the node locks `.node-hold` in its data
directory from before it changes its term record or consensus storage until
its runtime stops. An RPC address that cannot be bound fails the
start with `EmbedError::RpcBind`. `EmbeddedNode::rpc_addr` reports the bound
RPC address, including a port the system chose for port 0, and stays the same
across `take_over` and `follow`. The consensus listener always binds; `127.0.0.1:0` keeps
it on loopback with a system-chosen port. An embedded node prunes consensus
archives and state journals by default (`EmbeddedConfig::RETENTION`); finalized
history keeps `EmbeddedConfig::HISTORY_RETENTION` (16,384 revisions); receipts
and light blocks below its floor are unavailable on every device. A host may hold the key material itself:
`SoloDeployment` pairs the genesis record with the validator key and share,
`EmbeddedConfig::adopt` opens it in an empty directory or the one that already
holds it without writing either secret, and `EmbeddedNode::export` returns it
for another device. The export carries no state. Two devices started as
validator fork the deployment while they cannot reach each other; without
`switching` nothing detects it.
`EmbeddedConfig::backup` instead starts a backup from the genesis record alone:
it follows the active device at a given address under its own `DeviceKey`,
catches up by snapshot from an empty directory, re-executes blocks, serves
reads and proofs, and holds no validator key or share. The active device lists
its backups' keys in `EmbeddedConfig::backups`, which is configuration, not
state. See `docs/embedded-node.md`. Fault-injection builds abort an embedded
node at a point named in its directory's `crash-at` (`crate::crash`), and
`embedded_crash.rs` and `embedded_crash_term.rs` kill a child process at each
persisted first-boot, adoption, proposal, history, catch-up, handover,
takeover and rewind step and check the restart keeps every finalized request
once.

### Terms and the active device

A block carries a `term` that never decreases along a chain, and `GossipHeader`
repeats it. A `TermCertificate` (deployment, term, holder device, cut) moves
the active role between an account's devices; the operator policy approves it
and it changes no key. The node signs none: the host collects approvals.
`vera-domain` holds the type and digest,
`vera_permission::verify_term_certificate` checks it against an
`OperatorPolicy`, and `VeraClient` and the C verifier check it against
certified state.

`EmbeddedConfig::switching` names the account's devices. `hand_over` holds
proposals, including blocks built ahead of their turn, so nothing finalizes
above the cut, confirms the successor holds the final block and returns the
change to certify; `take_over` and `follow` restart the node in place in its new
role. `term.json` keeps the newest certificate, an announced handover and a
staged takeover; a device does not start as validator against them.
`EmbeddedNode::resume_stopped` undoes an announced handover on a stopped
directory. An embedded node
settles Commonware's consensus storage at every start, before marshal and
Simplex open it: a backup journals in Simplex partitions of its own and keeps
the validator's vote journal, a start as a backup after one as the validator
removes the backup's journals, and a start under a certificate removes both
roles' journals and marshal's cache and rebuilds its archive of finalization
certificates without those above the cut. A takeover away from its cut is
refused before anything is removed. A backup clears certificates above a cut
only under a certificate naming another device, and a rewind never applies
to the holder of the stored term (`TermRefusal::HolderResync`). A device that
followed validates again only under a certificate accepted since or after
`resume_stopped`. The validator's journal is otherwise removed only by such a
clearing or by a rewind. The
decision is stored in `term.json` first and an interrupted clearing is
finished by the next start. Every start that does not synchronize by snapshot
hands Simplex the finalization of the node's newest block as its floor, so a
voter with an empty journal starts on that block. See
docs/active-term.md#consensus-storage-across-a-switch. A lone
validator signs an epoch whose ceremony it only observed with the share its
host holds, once the epoch's sharing confirms it. Devices ask each other where
they stand on channel 17. An active device whose newest block is older than
`Switching::freshness` asks the others under its transport key before it
builds and again before a built block reaches consensus, and an active device
asks again every `Switching::freshness` in the background. A question carries
the asker's standing and is answered while the asked device asks itself.
An answer stops the proposal: a verified later certificate demotes the device
(`EmbeddedNode::demoted`), anything else is a `Contest`
(`EmbeddedNode::contested`) asked again at the next turn. An answer in a lower
term than the certificate the device holds does not, nor one holding that
certificate, nor one from a device
that holds back itself and has the higher transport key, so of two devices
in one term exactly one goes on. A device that reaches nobody proposes on,
and both sides of a partition finalize blocks until they reconnect.
`hand_over` naming the device itself renews its term to settle a contest, and
`take_over` on the active device accepts that certificate. A demoted device
keeps its own in-flight blocks; `follow` asks the holder for the newest block
the two share when its history left the holder's below the cut
(`TermRecord::common`), and the rewind reports and drops everything above it. A directory that last ran as a backup starts as
validator only under a certificate naming it (`TermRefusal::NotCertified`).
A backup holding the certificate of the next block without the block waits
`Switching::answer_timeout` for the block and then takes over below it: the
term voids it. A backup holding a certificate stops with
`TermRefusal::LowerTerm` on a finalized block of a lower term above the cut.
A device that follows a term whose cut is below blocks it finalized in a
lower term reports their submissions (`EmbeddedNode::discarded`,
`discarded-submissions.json`), drops those records from history and removes
`commonware/`, then takes state from the holder and imports history from the
cut. A device whose history left the holder's below the cut stops with
`TermRefusal::Diverged`. Blocks carry no certificate, so re-execution alone accepts any term at or
above the parent's. See `docs/active-term.md`.

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
        vera-crypto/            # BLS12-381, actor keys (secp256k1, Ed25519, P-256), JWT
        vera-domain/            # Block, tx, light block, proof, and DKG payload types
        vera-e2e/               # End-to-end test harness (see crates/vera-e2e/README.md)
        vera-executor/          # Block execution: REVM, precompiles, VeraExecutor
        vera-genesis/           # Extended genesis configuration (validators, native mint)
        vera-harness/           # Node manager, cluster builder, observability (test-only)
        vera-indexer/           # Block/tx/light-block indexes backing RPC queries
        vera-jsonrpc/           # Native vera_* RPC, subscriptions and compatibility methods
        vera-modules/           # ACP, Bulletin, Vera, ValidatorRegistry module logic
        vera-node/              # Validator assembly: p2p, marshal, DKG, stateful glue, RPC
        vera-permission/        # Permission/record/prefix evidence types and verification
        vera-qmdb/              # EVM change sets, record encodings, combined state root
        vera-traits/            # StateDbRead trait for EVM state reads
        vera-test-infra/            # Shared test primitives: process, ports, logs, binary resolver
        vera-verifier/          # C shared-library verifier for receipts, records, prefixes and policies
```

Native threshold rings retain a main/PET key pair when `requires_pet` is enabled.
Every participant signs the same pair; documents retain bounded PET tag/proof
attachments. See [native PET state](docs/native-pet.md) for signing domains,
fresh-state deployment requirements, report trust and qualification limits.

## Building

```bash
cargo check                        # type-check workspace
cargo build -p verad                # build binary
cargo test --workspace --exclude vera-e2e  # run non-e2e tests
cargo clippy --all -- -D warnings  # lint
cargo fmt                    # format
```

## Development Principles

Vera has not been deployed live. Releases start with fresh state; do not retain
obsolete APIs, build markers or migration scaffolding for development formats.
Current backup/recovery support and malformed-state validation remain required.

Use Regolith for finalized history and Commonware QMDB for authenticated state.
Do not add RocksDB profiling, optimization or backend-selection work. Qualify the
native core and one compatible Defra, Backbone, Orbis and separate Go Trust set.
The separate RocksDB/JMT module store and its proof path are removed. Preserve
native commitments and recovery behavior. Historical measurements retain their
original backend labels.

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
Payloads and proofs are limited to 64 KiB each, artifact labels to 1,024 bytes
and stored namespace IDs to 256 bytes. Bulletin event topics hash the stored
namespace ID. See `docs/bulletin-queries.md`.
Successful post creation returns and emits the stored content-derived post ID.
The creation event also retains the submitted artifact label.

Token invalidation events identify the token issuer even when an authorized
account performs the revocation; the record retains that account in invalidated_by.

Resource snapshots are opt-in with `RUST_LOG=warn,vera_resource_diagnostics=debug`.
This target leaves per-revision tracing disabled. `vera_diagnostics=debug` selects
resource snapshots together with per-revision diagnostics.
Every 30 seconds the node logs existing Commonware metrics, resident execution
index counts and accounted revision bytes, finalization/epoch cache entries and
buffer capacity, and Regolith memtable used/reserved, arena-pool, pinned-metadata
and block-cache byte counters.
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
