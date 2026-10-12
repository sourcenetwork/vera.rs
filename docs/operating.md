# Operating a validator

Deployment, recovery, monitoring and limits for a `verad` validator. Protocol
behaviour is documented in the linked pages; this one covers the operational
surface.

See [architecture and flows](architecture.md) for service boundaries and the
relationship between consensus, operator-managed membership, and ACP.

## Deployment

Use the [qualified native source set](native-qualification-20261011.md) when
reproducing the current consumer checks. Its evidence and outstanding gates are
explicit; green integration checks alone do not establish production readiness.

A network needs one `genesis.json` shared by all nodes, one validator key and
epoch-0 BLS share per node, and a `peers.json` listing every participant's
dialable address. Two paths produce that material:

- `verad genesis --peers peers.json` runs the distributed epoch-0 DKG across
  the participants and is the production path.
- `verad --chain-id <id> testnet --nodes 4 --init-only ...` generates
  trusted-dealer material locally; see [wan-gates.md](wan-gates.md) for a
  worked multi-host example.

Run a node with:

```sh
verad --config nodeN/config.toml --data-dir nodeN \
     --chain-id <id> validator --peers peers.json
```

`validator.key` and `secrets.json` in the data directory are the node's
identity: they are created owner-only and must never be regenerated for an
existing participant identity. Validator key creation rejects existing paths,
including symlinks; testnet initialization cannot replace a retained key. On Unix,
creation syncs the key and its parent directory before success. A failed initial
write may leave a file that needs inspection; do not remove or replace an existing
identity to retry initialization. Automatic key creation also stops if the key
is missing alongside retained `secrets.json`, `native-genesis.bin` or `history/`,
including dangling links. Restore the original identity with its retained state;
the node does not generate a replacement key for that directory.

Existing validator keys must contain exactly 32 bytes. The reader consumes at
most 33 bytes and rejects oversized or truncated material without resizing or
regenerating the retained key.

## Linux build artifacts

The Linux checks job bundles its normal release daemon after the native ring
lifecycle tests pass. Download `verad-x86_64-unknown-linux-gnu-regolith` from the
workflow run for the intended source. It contains a tarball and `SHA256SUMS`:

```sh
sha256sum --check SHA256SUMS
tar -xzf verad-x86_64-unknown-linux-gnu-regolith.tar.gz
```

The archive contains only `verad` and `build.json`. The manifest records the
actual checked-out source commit and tree (a merge commit on pull-request runs),
lockfile and toolchain-file hashes, compiler, target, release build command,
empty feature selection, Regolith history backend, binary hash and required shared
library names. Builds use the locked dependency graph and explicitly disable
default features; fault injection is excluded. Confirm the source against the independently selected revision.
Checksums detect corruption; they do not authenticate the publisher.

This artifact targets Linux x86-64 GNU on Ubuntu 24.04. It is dynamically linked;
use a compatible runtime with the required system libraries. It does not include
configuration, genesis, keys or validator state. Every node build uses Regolith
history. Existing RocksDB history requires a separate data directory and
authenticated synchronization; copying storage files does not convert it.
Archive timestamps, owners and member ordering are fixed, so packaging the same
binary and provenance produces the same bytes. Packaging alone does not establish
reproducible compilation or qualify an older runtime environment.

The release comparison verifier reads only the two canonical USTAR members,
checking each header before its payload. It bounds the executable to 512 MiB
and the manifest to 64 KiB, rejects links, extension records and extra entries,
and hashes executable bytes without extracting or loading the whole binary.
These checks enforce the bundle format; they do not authenticate its publisher.

[Reproducibility run 38134444674](https://github.com/sourcenetwork/vera.rs/actions/runs/38134444674)
compiled candidate `9d5c2b9` on two separate Ubuntu 24.04 hosted runners with
Rust 1.98.0, absent target directories and no restored build caches. Both normal
Regolith release compilations produced identical daemon bytes, matching the
executable already exercised by core CI 38124358657. Downloaded artifact,
archive and inner-binary checksums and build provenance were verified. The two
archives also match; their source, compiler, lockfile, features, source path and
recorded OS/package environment agree. This qualifies the recorded environment
and source path, not compilation across different toolchains or environments.
A successful Linux job does not replace the other release gates.

## Filesystem layout

| Path | Contents |
|------|----------|
| `config.toml` | Node, network, RPC, execution and pruning configuration |
| `genesis.json` | Shared deployment definition and epoch-0 key material |
| `peers.json` | Participant addresses for the authenticated network |
| `validator.key` | Ed25519 consensus identity (32 bytes, owner-only) |
| `secrets.json` | BLS shares and DKG state (owner-only, atomic writes) |
| `history/` | Durable execution and finalization records |
| `native-genesis.bin` | Published after all seven partitions first seal |

Retain `validator.key` and `secrets.json` together with independently provisioned
genesis, configuration, and peer material. Recovering the remaining state depends
on reachable peers and available authenticated state and history. A delayed
snapshot catch-up re-floors from stored gossiped finalizations when processing
stalls and converges without network quiescence, though it still exits at its
deadline if peers cannot serve any retained target; a secret backup alone does
not establish that a restore will succeed. Exercise restores before relying on this recovery path.

## Stopped-validator backup and restore

Stop the validator and confirm its process has exited before copying its entire
data directory. Retain the validator key, DKG secrets, all Commonware journals,
native genesis record and history together. A copy of only the application state
or keys is not a complete checkpoint. Store the backup in an owner-only directory
on protected storage; keep independently provisioned genesis, peers, configuration
and the exact node build alongside it. Verify the copy before removing the source.
Never run two processes with the same restored validator identity.

Restore into an empty directory using the same history backend and compatible
node build. Preserve key permissions and update explicit configuration paths if
the directory moves. Restore the participant's latest durable signing state:
an older backup must not replace journals from later signing activity. If those
journals are lost, use operator-authorized member replacement with a fresh
identity rather than assuming a stale backup is safe. The validator must remain
stopped between capture and restore for the qualification scenario below.

DKG material updates run on the blocking pool and are awaited before success.
Writers serialize through file and parent-directory synchronization; cached
readers keep the previous durable view until the replacement completes. A write
failure stops the caller before it can acknowledge the update.

A signing share must belong to this validator's position in the selected
committee and match its public sharing. Startup checks the genesis committee;
resharing registration checks the new committee. A valid share copied from
another member is rejected before the certificate provider is updated.

After startup, independently verify a certified revision and the expected policy
and revocation state at the current checkpoint. RPC availability alone does not
prove that the member has caught up or holds the current voting share. Exercise
a certified write requiring that member's quorum contribution before relying on
it for service availability. Peer retention and network reachability still bound
how far an offline member can recover.

The focused `cold_replay` case
`stopped_backup_restores_revocations_and_rejoins_pipelined_consensus` captures a
full stopped directory after a certified grant, commits its revocation on the
remaining replicas, discards the original directory and restores the backup.
The existing recovery assertions check historical receipts, policy and nonce
state, certified revocation denial, a current epoch share and a subsequent write
after stopping another voter. It uses four validators, normal timing, pipelined
Simplex and 192-revision epochs. Linux CI exercises the Regolith deployment
through the lifecycle job.

This is a prepared process-level filesystem-copy qualification. Passing results
must be tied to the tested source; it does not establish live filesystem snapshot
consistency, stale-signing-state rollback safety, backup encryption, physical
media failure or power-loss behavior. Those require deployment-specific validation.

## Recovery behaviour

- **Restart after clean stop** — startup aligns all journals to the durable
  anchor, rebuilds query indexes from durable history, then serves.
- **Restart after crash** — the same path: interrupted snapshot
  synchronization resumes from durable metadata; partially applied revisions
  rewind to the last durable anchor before execution continues.
- **Pruned peers** — a node joining late fetches a recent authenticated
  snapshot plus retained history; it does not need genesis-era data when
  pruning is configured (see [snapshot-recovery.md](snapshot-recovery.md)).
- **Reported persistence failures** — a write or synchronization error during
  finalization stops the node before acknowledgement. An error can leave a
  complete batch visible; startup reconciles stored history with the durable
  anchor. The [history storage qualification](history-storage.md) distinguishes
  reported errors from silent corruption, failed-device and power-loss behavior.

Do not delete `history/` or the genesis record to "reset" a node: existing
JMT directories or a missing genesis record alongside finalized history are
rejected and require an explicit migration decision, not silent reset.

## Configuration knobs operators own

- **Pruning** (`[pruning]`): `retained_consensus_revisions` bounds marshal
  archive retention; `retained_state_revisions = 0` prunes state snapshots
  aggressively. Retention must cover a complete DKG epoch. Memory retained by
  the archive window is bounded by retention divided by the section size —
  size deployments accordingly.
- **Snapshot catch-up** (`[snapshot]`): opt-in for newly admitted members;
  `record_bytes`, `peer_timeout_ms`, and `initialization_timeout_ms` must be positive.
  Initialization defaults to a five-minute deadline. Exceeding it stops the
  process; restart is not a guarantee of convergence. `floor_stall_seconds`
  (default 15, zero disables) bounds the quiet period before startup re-floors
  a stalled initialization from the newest stored gossiped finalization.
- **Finality watchdog** (`watchdog_stall_seconds`, default 600, `0` disables):
  remains unarmed while authenticated connectivity is unavailable. The current
  Commonware integration does not expose that telemetry, so this setting does
  not currently trigger supervised recovery. A watchdog that accounts for the
  active voting quorum still requires implementation and qualification. Snapshot
  initialization has its separate deadline; supervised restart does not guarantee recovery.
- **History backend**: Regolith with synchronous writes in every build. The
  `regolith-history` feature remains an accepted deployment marker. Foreign
  directory layouts are rejected before opening the store.
- **RPC exposure**: bind `http_addr` to an internal interface for validator
  operation; expose only through the intended client path. With `--config`,
  startup uses that address and port; `--rpc-port` changes only its port, preserving
  the interface. Without a config file, validators retain the indexed default
  port (`8545 + validator_index`); devnet defaults to 8545. Malformed listen
  addresses fail startup instead of falling back to a wildcard interface.
  The JSON-RPC server enforces its own batch, subscription and body-size limits (see
  [permission-proofs.md](permission-proofs.md) for proof-path budgets).

## Resident memory and measured workloads

Validators retain active module records and authenticated-state indexes in memory.
Sizing must account for live policies, objects, relationships and signer records,
as well as protocol queues, storage buffers and allocator retention. History-cache
limits do not bound total process memory.

| Resident cache | Entry limit | Retained payload budget |
| --- | ---: | ---: |
| Execution revisions, transactions and receipts | 1,024 revisions | 64 MiB target |
| Finalization proofs | 1,024 records | 64 MiB |
| Epoch verifier material, including genesis | 128 records | 8 MiB |

The execution cache retains its newest revision even when that revision exceeds
the byte target. Readers can hold references after eviction. The proof budgets
count retained vector capacities; map metadata and externally held references
are additional memory. Evicted records remain available from durable history.

Consensus entry releases full threshold schemes for earlier epochs, retaining
the entered epoch and any staged future epochs. History lookups cannot advance
that retirement boundary. Recovered certificates use a separate verifier bound
to the deployment's fixed group key, so historical verification does not retain
private shares or old participant sets. A registration changing that group key
stops before publication. Running engines can retain their own scheme copies;
staged epochs can accumulate if consensus entry stalls. This is retirement with
consensus progress, not a hard process-memory bound or a key-zeroization claim.

The [measured candidate workload](native-qualification-20261012.md#growing-registrations)
completed 90,000 distinct registrations at offered 50/s on four local validators,
with peak sampled RSS of 889.50–927.39 MiB per validator and successful restart inspection.
Its live dataset grows throughout the run. Use the recorded hardware, payloads,
allocator and sampling scope when assessing deployment headroom; this is not a
minimum RAM requirement or a hard memory bound for arbitrary policies.

## Admission under pressure

The pending queue accepts at most 4,096 requests and 64 MiB of wire payload.
Exhaustion rejects additional requests without evicting earlier admissions.
Queue capacity and startup readiness failures return `-32002` with
`{"retryable": true}`. Retry the same signed request with bounded backoff and
an overall deadline; signature and sequence validation failures remain permanent.
An admission response is not a certified outcome. If transport fails after
submission, check the existing request identity before creating another request.

The native admission workflow also has a `stalled-validator` selection. On Linux
it suspends one of four validators for at least 30 seconds while the remaining
three certify native writes across an epoch. After resuming the process, it
checks certified receipts, namespace ownership and sequences on every replica,
then removes another validator so the resumed member is required for quorum.
This is a bounded process-stall check; it does not establish a WAN latency limit
or a total memory bound.

The `delayed-validator` selection runs an explicitly enabled, otherwise ignored
Linux transport case on an isolated hosted runner. It identifies the managed
validator's established P2P sockets and applies a 100 ms packet delay and a
shared 20 Mbit/s rate using [netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html),
with a 1,024-packet queue. Exact TCP flow filters cover both directions and leave
RPC traffic unshaped. The test requires unchanged socket coverage and advancing
fault-queue packet counters throughout its certified epoch-progress phase.
It restores only its own queue, checks all replica records and requires the
affected member for a subsequent quorum. This is local transport-fault coverage;
real WAN latency and capacity measurements still require separate hosts.

The ordered-state recovery unit test separately exercises all 128 durable
subsets of the seven journals after an interrupted generation. It checks the
actual persisted targets, rejects unanchored state, recovers the selected anchor
before publishing query state, and verifies subsequent writes and reopening.
This models completed partition writes around a process exit; it does not
simulate the loss of unsynchronized filesystem writes during a power cut.

## Monitoring

- `vera_nodeStatus` reports `finalizedHeight`, `finalizedEpoch` and
  `finalizedView` from one published execution revision, including restored
  durable history. They are null until observed. `snapshotRevision` separately
  records the recovered snapshot floor. Use height changes for progress alarms;
  `finalizedCount` counts callbacks in this process and is not a height.
- `currentView`, `isLeader`, `peerCount` and `nullifiedCount` are null because
  this Commonware integration does not expose the corresponding live observations.
  Null does not mean zero peers, no nullifications or a known non-leader.
  `validatorIndex` and `validatorCount` describe startup configuration, not the
  active membership after operator changes. Rust clients represent unavailable
  fields as `Option`; JSON consumers must accept null. The compatibility
  `net_peerCount` method returns resource-unavailable (`-32002`) until an actual
  count is observed; it does not substitute zero for unknown connectivity.
- While backfilling, the compatibility `eth_syncing` response uses the published
  finalized height for `currentBlock`. Its `highestBlock` is only the maximum of
  that height and the recovered snapshot floor, not an estimate of the network
  tip. Consensus views and process counters are never used as heights.
- `RUST_LOG=warn,vera_resource_diagnostics=debug` emits a resource snapshot every 30
  seconds (runtime metrics, resident execution index, cache occupancy,
  history-backend memory counters). Collection runs off the async executor and
  is opt-in. `vera_publication_diagnostics=debug` enables per-revision apply and
  publication times; `vera_diagnostics=debug` enables both kinds of diagnostics.
- Consensus warnings (`floor not updated`, view skips) at `warn` are normal
  during epoch transitions; sustained notarization timeouts are not.

## Capacity reference

Size a deployment from a measured workload and its exact source, storage backend
and host configuration. The [October 6 hosted Linux baseline](performance.md#hosted-linux-baseline-on-october-6-2026)
at `04206bec` completed every operation in four 3,000-write runs offered at 50/s,
covering growing registrations and fixed-object updates with both history
backends. Each included certified permission checks, four-replica reconciliation
and a member restart with zero receipt or state mismatches. Those approximately
60-second runs on separate hosts establish that bounded load point, not maximum
throughput, a backend speed comparison or a sustained memory bound.

The [mixed-policy qualification](mixed-policy-workload.md#current-schema-local-qualification)
at `a1cbace6` records a four-validator release run with 512 workflows and 2,048
objects. All 3,075 submissions were certified successful, including revocation
and regrant checks; five verification phases covered all four replicas and a
hard restart. The timed workload offered 4 workflows/s for 129.988 seconds
including drain. Its offered load and short RSS sample do not establish maximum
capacity or sustained memory behavior.

Wide-area gate criteria are defined in [wan-gates.md](wan-gates.md); a qualified
WAN capacity result is still required. Re-baseline with `operation_baseline`
(local) and `wan_baseline` (remote) after material changes. Compare only matching
workloads and measurement boundaries.

## Security notes for operators

- `validator.key` and `secrets.json` are created with owner-only permissions.
  On Unix, startup rejects symlinks, non-regular files, hard links and group or
  other access to existing private material. Reads check the opened descriptor
  before decoding; they do not repair permissions. Restore independent files
  with owner-only permissions (`chmod 600`), and protect the data directory and
  its parents from other writers. Keep the data directory off shared storage.
- Peer messaging is authenticated (see `peers.json`); RPC traffic should be
  TLS-terminated or network-isolated as appropriate for the deployment.
- Certificate and proof endpoints apply fixed budgets; a client exceeding
  them receives retryable `-32002` errors and must back off, not reconnect
  harder.

## Certified read check

Use an independently provisioned consensus key, a known existing policy and a
positive finalized checkpoint to check the native read path:

```sh
verad client --url https://<rpc-host> --compact check-read \
  --policy-id <policy-id> --trusted-key <consensus-key-hex> \
  --minimum-revision <checkpoint> --max-age-seconds 30
```

The command verifies the finalization certificate, policy membership proof and
policy identity through the shared native client. It rejects certified absence,
revisions below the selected checkpoint, timestamps older than the configured age
and timestamps more than five seconds ahead of the local clock. Override the
future allowance with `--max-future-seconds`; keep the monitoring clock accurate.
Age is checked after the response has been verified, so request time counts.
Success prints only policy ID, verified revision, execution timestamp and check
time as JSON; failures exit unsuccessfully. The request uses the client's bounded
transport and ten-second HTTP deadline and does not retry.

Obtain the key, policy and checkpoint independently of the endpoint being checked.
Retain the highest accepted checkpoint in the monitoring system and advance the
configured minimum; the command does not persist it. This checks one certified
policy read. It does not prove permission for an actor, current voting membership,
connected peers, renewed quorum contribution, write availability or the latest
possible revision. Continue using the backup/rejoin quorum checks above for a
restored validator.

## CI test evidence

Extended, native-ring and recovery jobs keep command output and node directories
on the runner. Their artifacts contain a bounded JSON summary: checked source
revision, command exit code, reported test counts and locations in tracked Rust
source files. Keys, state, raw logs, panic messages and endpoint addresses are not
uploaded. Disk-full RPC failures additionally record an allowlisted recovery
phase, error class and replica index, with deduplication and a sixteen-entry limit;
remote error text and numeric request identities are not exported. The summary
records skipped unreadable inputs and truncation or item
limits; missing evidence is not a successful test result. Raw files are removed
in job cleanup. These summaries help locate a failure but do not explain its
runtime cause; investigate a reproducible failure with private diagnostics.
