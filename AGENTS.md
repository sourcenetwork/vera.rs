# vera.rs

Native Rust implementation of Vera's access control, bulletin, identity and transparency services, using Commonware consensus and storage. Native requests use BLS12-381 signing. Every deployment runs pipelined Simplex consensus with bounded leader terms, and blocks carry native requests only.

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
| **vera.rs** | sourcenetwork | This repo — native Vera on Commonware |
| **vera** | sourcenetwork | Earlier Go service; its `acp_core` engine is the reference behind `tools/acp-oracle` |
| **orbis-rs** | sourcenetwork | Application threshold signing and encryption, using native authorization, bulletin and ring records |
| **defradb.rs** | sourcenetwork | Document storage with native signed submissions and verified ACP evidence |
| **trust-api** | sourcenetwork | Separate Go gateway; this repository ships no Go client, C verifier or tests for it |
| **backbone** | sourcenetwork | Shared Rust clients and verification used by native consumers |
| **regolith** | sourcenetwork | Defra document storage and Vera finalized-history backend |
| **bankd-commonware** | mizufinance | Reference Commonware chain (source of the consensus assembly and e2e harness) |
| **monorepo** | commonwarexyz | Commonware primitives (consensus, crypto, p2p, storage) |

### Code reuse across repos

| Component | Source repo | Used in vera.rs for |
|-----------|-----------|-------------------|
| Zanzibar engine (relation-tuple graph) | vendored `crates/vera-zanzibar/` (from defradb.rs 8d34d9c) | ACP policy evaluation |
| DID types, identity crate | vendored `crates/vera-identity/` (from defradb.rs 8d34d9c) | DID resolution |
| YAML policy parser, DocumentACP types | vendored `crates/vera-acp/` (from defradb.rs 8d34d9c) | ACP policy creation |
| Simplex consensus, e2e harness | bankd-commonware | Consensus, testing |
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
  `FixedEpocher` over genesis `blocks_per_epoch`. The round-robin elector
  assigns bounded leader terms from the genesis `simplex` parameters
  (defaults apply when the section is omitted).
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

### Execution (`vera-app` + `vera-executor`)

`StatefulVeraApp` implements `commonware_glue::stateful::Application`: it builds
blocks from the mempool, executes them against forked QMDB batch state, verifies
proposals by re-execution, and hands finalized receipts to a `FinalizedSink`
(`NodeSink`), which indexes blocks, logs, and light blocks and feeds the RPC
subscription channels. Block execution goes through `VeraExecutor`:

```
        VeraExecutor
             |
      Native BLS request
             |
      BLS verify → did:key
      Deserialize NativeTx
             |
      Dispatch to module
             |
             v
      module.method(args)
```

A block carries native requests only. Building skips and drops bytes that are
not a native request; verification rejects a block that carries any.

### Module addresses

| Address | Module | Purpose |
|---------|--------|---------|
| `0x0810` | ACP | Access control policies (Zanzibar relation tuples) |
| `0x0811` | Bulletin | Coordination / DKG messages / posts |
| `0x0812` | Vera | Identity / JWT token lifecycle |
| `0x0813` | ValidatorRegistry | Validator identity management (feeds resharing) |
| `0x0814` | Anchor | Finalized revisions of registered deployments as one chain each, their terms and forks (identity partition) |

### Shared module pattern

Each module is a plain Rust struct. A native request names a module address
and carries an ABI-encoded call; the executor verifies the BLS signature and
the dispatch shim decodes the call into `module.method(args)`.

Business logic lives once.

`vera-modules` has no Commonware or `vera-domain` dependency, so clients that
encode module calls (DefraDB's delegation crate) do not build the consensus
stack. Verification that needs consensus types, such as an anchor's finality
certificate, runs in the executor's shim before the module call.
`.github/scripts/check-light-crate-graph.py` fails CI if `vera-modules`,
`vera-crypto`, `vera-acp`, `vera-identity` or `vera-zanzibar` resolves
Commonware's runtime, glue, consensus, p2p or storage crates, or `vera-domain`.

Operator policies list secp256k1 keys in hexadecimal and Ed25519 or P-256 keys
as `did:key`; every operator signs the same administrative digest. See
docs/consensus-membership.md#operator-keys.
Any P-256 key may approve an administrative request or a term change, or
issue a delegation, with a passkey (WebAuthn) assertion whose challenge is the
digest: `vera_crypto::webauthn` checks 37-byte authenticator data with user
presence and verification, parses client data strictly (no duplicate member,
no trailing data, scalar extras, challenge compared as a string) and verifies
the raw low-S signature over the WebAuthn message. Approvals carry it in a
`webauthn` member; delegations use the `vera-delegation-webauthn-v1+jwt` type.
It proves only that the key's holder signed; the credential must be dedicated.
See docs/passkeys.md.
Provider relay grants use the same operator quorum as administrative changes.
Relay assertions bind a stable `did:opk` actor, native worker, genesis, scope,
grant generation and exact operation. ACP stores the actor as owner; token
records retain the signing relay as issuer. See docs/delegated-policies.md.

Delegated policy creation and editing preserve the actor as owner while a
separate worker signs the submission. Creation and editing require distinct
scopes; existing object-command tokens do not authorize either operation.
Created records bind the owner, worker, signed submission ID and creation
revision. See `docs/delegated-policies.md` for result verification.
A policy id is SHA-256 over acp's policy hash, the creator's 32-byte nonce
and the owner's canonical DID, derived as acp does and checked against acp's
vectors; creating the same triple twice is refused, and the record keeps the
nonce and creation hash. See `docs/policy-ids.md`.
Delegation issuers are secp256k1 (ES256K), Ed25519 (EdDSA) or P-256 (ES256)
`did:key` actors; the key type fixes the token algorithm. Ed25519 and P-256
actors have one DID spelling and one signature encoding per token type; a
P-256 actor's passkey tokens are a type of their own. Relay issuers remain
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

The node uses `vera-app::OrderedState`: four ordered Commonware current-QMDB
partitions (ACP, bulletin, vera, native sequences). `StatefulVeraApp` seals all
four targets into each proposal and verifies them by re-execution. An in-memory commitment participates in the same
Commonware coordinator generation, binding the native current-state root to the
selected operation-log targets. It is reconstructed from the durable recovery
anchor, not persisted as an independent journal.

A module call that fails on what its caller sent (an unknown selector, calldata
that does not decode, an argument out of bounds) rejects that request with a
failed receipt, and the block goes on. Only an error marked as the node's own
(`ModuleError::Fault`: stored membership or policy state that does not
read back) fails the block, including inside an ACP batch. A call that exhausts
its gas allowance is a failure too: nothing it wrote is kept, a native request
is charged its full limit.
A refused native request's receipt names why: `vera_domain::Refusal` carries the
module, a `RefusalKind` that the receipt commitment binds, and the module's
message, bounded to 1,024 bytes and not committed because it embeds parser and
library text. A module error's variant decides its kind
(`vera_executor::dispatch::refusal`). A refusal is charged what the call
reported, at least 5,000; `out_of_gas` and a module panic keep the full limit.
`vera-client` returns `ClientError::Refused` for a refused native request, with
its receipt. See `docs/receipt-commitments.md#refusals`.
A module method that needs a signer refuses a call without one
(`RefusalKind::Unauthenticated`), which is how the signerless `vera_call` is kept
to queries. ACP and token lifecycle errors reject proposal execution and re-verification.
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
publishes `native-genesis.bin` after all four partitions are durable. Interrupted
initialization can rewind and retry only with the same genesis configuration.
Foreign state layouts and incompatible genesis records are rejected.
Formats are versioned: a block leads with `BLOCK_FORMAT_VERSION`, the genesis
record and intent with `STATE_LAYOUT_VERSION` (also hashed into the genesis
fingerprint), a native request with its type byte, and each is refused with a
typed error (`vera_domain::UnsupportedVersion`, `NativeTxDecodeError`,
`UnsupportedHistoryFormat`) under any other value. A release that adds a
component raises the versions it changes; modules keep their addresses and call
encodings. See `docs/receipt-commitments.md#format-versions`.
Missing genesis records alongside finalized history are rejected instead of
resetting state. A persisted native genesis must contain the expected receipt
commitment.

`genesis.json` and `config.toml` reject keys they do not define. Genesis
validators need distinct addresses and consensus keys, and a node does not start
without at least one. The validator registry keeps one record per member in
the vera module's store (`registry/member/<address>`: consensus key, network
address, active flag, admission, address sequence), seeded at genesis and read
in address order; a record that does not read back fails the block. Every
admission takes the next number of a count that removal never lowers.
Membership commands need the membership policy's `manage` permission. A
validator changes its network address itself: `updateP2PAddress` carries its
Ed25519 consensus key's signature over the genesis record, its address, the
record's admission and sequence and the new address, any native signer submits
it, and it applies once; a member removed and admitted again signs under a new
admission
(`vera_client::ValidatorAddressUpdate`). See docs/consensus-membership.md#validator-records.

Four authenticated peer resolvers (channels 9 to 12) serve bounded operation-log ranges. Fetches
allow up to 64 operations, with eight-operation inspection batches and responses
below the 4 MiB transport limit. Native keys are limited to 64 KiB; values and
commit metadata to 1 MiB. A request for a
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
Starting an import marks the store as imported, so recovery keeps the blocks
its certificates need above the anchor. The node serves chunks through Commonware's
resolver on authenticated channel 13, producing each chunk on the blocking pool,
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
The Rust client verifies a revision's certificate once: it remembers up to 256
verified revisions by height, block hash and evidence digest under one
consensus key and term, so a remembered block with another certificate is
verified in full, and a later term, another block at a remembered height or another key empties
the record. Evidence is verified against the module root on every read. See
docs/permission-proofs.md#verified-revisions-in-the-rust-client.
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

A block has one encoding per format version: the version byte, consensus
context, parent, height, timestamp, term, module state root, requests, optional
DKG payload, the four module log targets and the receipt commitment. Every
field is required. A block carrying a target
with an empty range is rejected by the application without executing it. Proofs
use Commonware QMDB only.

### RPC surfaces

The execution index keeps at most 1,024 recent revisions under a 64 MiB payload
accounting budget. It always retains the newest revision, even if that revision
alone exceeds the budget. Accounting includes vector capacity, strings and byte
payload lengths; it is not a total RSS bound. Readers hold immutable revision
snapshots across proof assembly, so eviction cannot remove their receipts.
Index publication and removal update all lookup maps under one lock.

Receipt point queries use bounded archive reads when absent from memory. The
receipt endpoint uses the same conversion for recent and historical data,
including signer identity, nonce and refusal. Archive reconstruction uses one
retained revision and the existing index builder; it does not populate the
global memory index. Archive errors propagate, and occupied history-read slots
return a retryable -32002 response.

`vera_call` and `vera_simulateNativeCall` execute on the blocking pool against
a snapshot of module state, so they hold neither an async worker nor the lock
finalization publishes under. They share four slots per node, and up to 64 more
callers wait at most two seconds for one; a caller beyond the 64, or one whose
wait expires, gets the retryable -32002. A slot stays taken until its execution
ends. Each observes the head revision's height and time, the deployment's
genesis record and its membership limit, and writes nothing.
`vera_call(target, calldata)` evaluates a module call without a signer and
returns its output or the refusal: queries answer, and every method that needs
a signer is refused. `vera_simulateNativeCall` dry-runs a module call as a named
DID without a signature or sequence and returns success or the refusal its
receipt would name, gas and logs. Both bound their input like a native
submission.
Both are unauthenticated: the answer is the serving node's word about its head
revision, with no finality certificate and no state proof. Nothing that grants
access, records a decision or acts for another party may rely on either; the
certified record, prefix and permission reads are the authenticated path. The
Rust client's typed queries (`get_policy`, `has_relationship`, `get_post`, …)
go through `vera_call` and name their verified equivalents. See
`docs/simulation.md#when-an-unauthenticated-read-is-acceptable`.

`vera-jsonrpc` limits each batch to 64 calls and each connection to eight
subscriptions, eight queued output messages and eight WebSocket request tasks.
The receive loop stops accepting messages at the task limit; each task retains
its slot until its response enters the output queue. Response and ping writes
time out after ten seconds, and socket closure after one second.

`vera-jsonrpc` serves HTTP + WebSocket JSON-RPC:

| Surface | Methods | Consumer |
|----------|---------|----------|
| `vera_subscribeHeaders` | `vera_header` notifications; `vera_unsubscribeHeaders` cancellation | Native verified consumers |
| `vera_*` | `vera_nodeStatus`, `vera_sendNativeTx`, `vera_call` (unauthenticated module query), `vera_simulateNativeCall` (unauthenticated dry run), `vera_getTransactionReceipt`, `vera_getNativeNonce`, current permission/record proofs and light blocks | Native Defra, Orbis and verification clients |

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
genesis under owners and nonces the host chooses, so a host computes their ids
beforehand. `thread_budget()` reports the
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

### Anchored deployments

The anchor module keeps an ordered record of other deployments in the identity
partition. The anchoring deployment's operators register a deployment
(consensus key, genesis block, operator policy; identifier: SHA-256 of the
key) and grant native signers a daily quota of submissions for it, with the
administrative commands `RegisterDeployment`, `SetAnchorSubmitter` and
`RevokeAnchorSubmitter`; a request from a signer without a grant is refused at
admission and at execution. `anchorRevision` records a finalized revision
when its certificate verifies against the registered key (verified in
`vera-executor`, recorded by `VeraModule::record_anchor`), it is above the tip
of the deployment's anchors, it carries the term certified last, and it
proves, against the ancestry its block carries, that it descends from the
tip. `changeTerm` records a `TermCertificate` verified against the registered
operator policy: the tip moves to its cut and anchors above the cut are
superseded (`TermRecord::supersedes`). A certified block of another history is
refused and recordable as a fork (`reportFork`). Every anchor stays in an
append-only history (`anchor/v1/<deployment>/<sequence>`), read in bounded
pages. A refused submission is charged the full 250,000 gas and counted
against its signer's quota. `vera_getCurrentPolicySnapshot` captures a
policy record and its relationship, index and object prefixes at one revision.
`vera_client::anchoring` publishes a snapshot (capture, anchor that revision,
read the anchor back), verifies a relayed `AnchoredSnapshot` with the
anchoring deployment's key alone, evaluates access with the shared evaluator,
and reports a snapshot as stale once a newer anchor is known and as superseded
once a term voided its anchor. No partition changed. See `docs/anchoring.md`.

A block carries the peaks of a Commonware Merkle mountain range over its
ancestors' identifiers (`vera_domain::Ancestry`, block format 2). Voters check
that a candidate's ancestry extends its parent's, `Block::has_ancestor`
verifies an `AncestryProof`, and `vera_getAncestryProof` rebuilds one from
the block identifiers finalized history keeps by height, reading two records
whatever the span, without storing the range. See
`docs/receipt-commitments.md#ancestry`.

### Terms and the active device

A block carries a `term` that never decreases along a chain, and `GossipHeader`
repeats it. A `TermCertificate` (deployment, term, holder device, cut) moves
the active role between an account's devices; the operator policy approves it,
raw or by passkey, and it changes no key. The node signs none: the host
collects approvals. A certificate verifies only when its JSON encoding is at
most `MAX_TERM_CERTIFICATE_BYTES` (32 KiB): 128 raw approvals, or at least 13
passkey approvals. Messages between devices are limited to that plus 256
bytes. `vera-domain` holds the type and digest,
`vera_permission::verify_term_certificate` checks it against an
`OperatorPolicy` for the node, the executor and the client, and `VeraClient`
checks it against certified state.

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
they stand on channel 14. An active device whose newest block is older than
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
        vera-backend/           # QMDB storage of the native partitions, peer transfer, proofs
        vera-cli/               # CLI utilities (backtrace + SIGSEGV handlers)
        vera-client/            # Rust client library (native requests, verified reads, typed queries)
        vera-config/            # Node configuration types (node, network, rpc, execution)
        vera-consensus/         # Consensus application layer: mempool, proposal, traits
        vera-crypto/            # BLS12-381, actor keys (secp256k1, Ed25519, P-256), JWT, passkeys
        vera-domain/            # Block, tx, light block, proof, and DKG payload types
        vera-e2e/               # End-to-end test harness (see crates/vera-e2e/README.md)
        vera-executor/          # Block execution: native requests, module call shims, VeraExecutor
        vera-genesis/           # Genesis configuration (operators, policies, validators, consensus)
        vera-harness/           # Node manager, cluster builder, observability (test-only)
        vera-indexer/           # Block/tx/light-block indexes backing RPC queries
        vera-jsonrpc/           # Native vera_* RPC and header subscriptions
        vera-modules/           # ACP, Bulletin, Vera, ValidatorRegistry module logic
        vera-node/              # Validator assembly: p2p, marshal, DKG, stateful glue, RPC
        vera-permission/        # Permission/record/prefix evidence types and verification
        vera-test-infra/            # Shared test primitives: process, ports, logs, binary resolver
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
cargo clippy --all --all-targets -- -D warnings  # lint
cargo fmt                    # format
```

## Development Principles

Vera has not been deployed live. Releases start with fresh state; do not retain
obsolete APIs, build markers or migration scaffolding for development formats.
Current backup/recovery support and malformed-state validation remain required.

Use Regolith for finalized history and Commonware QMDB for authenticated state.
Do not add RocksDB profiling, optimization or backend-selection work. Qualify the
native core and one compatible Defra, Backbone and Orbis set.
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
3. `cargo clippy --all --all-targets -- -D warnings` clean
4. `cargo fmt` applied
5. `cargo test -p vera-e2e --test vera_e2e_canonical` passes (requires `cargo build -p verad` first)

The e2e test (`vera_e2e_canonical`) is the baseline gate. It exercises native requests through a 4-node cluster: create policies, verify receipts, query state back, check cross-node consistency, and assert cluster health. Any change that breaks this test has broken the core pipeline.

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
An issuer revokes its own recorded token through any worker it names with
`invalidateJWSByIssuer`, under an operation it signs with scope
`vera:token:revoke` and an operation identity; the record then names the issuer
in invalidated_by. See `docs/token-lifecycle.md#revocation-by-the-issuer`.

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
