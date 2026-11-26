# Finalized history storage

Commonware stores authenticated current state, pending forks, and consensus
archives. Finalized execution history is a separate database containing records,
certificates, query indexes and snapshot-import progress. Its backend does not
change the revision commitments or proof format.

All builds use Regolith in the node's `history/regolith` directory:

```sh
cargo build --frozen -p verad
```

History always uses Regolith; there is no backend-selection feature.
Authenticated module state uses Commonware QMDB.

The [node manifest](../crates/vera-node/Cargo.toml) requires Regolith `0.2` from
crates.io, and `Cargo.lock` pins release `0.2.5`. The engine uses its commit
pipeline, read views and block cache, together with atomic compaction-manifest
edit batches and crash-aware WAL recovery. Compaction scans bypass the
foreground cache.

Keep backups paired with their node build and do not downgrade a written
history directory. Vera releases start with fresh state.

History writes explicitly request synchronous WAL persistence; they do not use
Regolith's default eventual durability. Execution, certificate and query-index
updates share one batch.

The earlier backend revision `061846fc870389391f77b8c2a3cf370b6e69d95f`'s
[durability run](https://github.com/sourcenetwork/regolith/actions/runs/37856386632)
passed eight power-loss-model cases, including cuts during memtable flush,
compaction, manifest append and recovery, plus its process-crash checks. The
recorded checkout matches that revision. These models discard unsynchronized
writes using the child's recorded syscall stream and verify acknowledged data;
the required fault interposer cannot silently fall back to a weaker model.
This qualifies those Regolith backend scenarios. It does not model all of Vera's
Commonware journals together or establish physical-device power-loss behavior.
See [current qualification](native-qualification-20261014.md) for later source-bound
checks and measured behavior; changing a dependency pin does not extend an older
run's scope.

Snapshots pin consistent reads and borrowed record values. Cursor reads check
status separately from exhaustion so errors cannot appear as empty history.
Recovery batches retain the existing flush threshold, using a running payload
estimate for the Regolith batch.

Compaction removes its input tables and installs replacement tables in one
checksummed manifest frame. Recovery retains or discards the complete edit batch,
and uncertain manifest writes stop further edits until reopening. Use the same
qualified node build when restoring a stopped backup.

A history-write error stops finalization before updating the in-memory head or
acknowledging execution. An error does not establish that the batch is absent:
if a complete batch is visible, its stored head can be ahead of memory. Startup
reconciles stored history before serving requests. The focused write-failure
regression checks both absent and visible batches using injected
errors; it does not qualify device-level write or synchronization failures.

Archived receipt polling returns pending while the receipt's revision is ahead
of the live published index. This prevents a receipt from becoming available in
the interval between its durable history write and publication of query state.

Startup rejects foreign history layouts before creating storage files. Vera
releases start with fresh state; development data from incompatible builds is
unsupported. Existing members recover through the documented backup and
authenticated synchronization paths.

Backend selection does not establish throughput, memory bounds, or power-loss
durability. Numeric diagnostics report used and reserved memtable bytes, retired
arena-pool bytes, block-cache usage and pinned table metadata separately. These
counters are non-atomic and do not account for all validator allocations.

The daemon uses Regolith's default 512 MiB decompressed block-cache target
and 64 MiB memtable flush threshold. An embedded node selects both through
`EmbeddedConfig::history_memory`, 8 MiB and 4 MiB by default; see
[embedded node memory](embedded-node.md#memory). The cache fills on reads; reaching the
memtable threshold starts rotation and flushing. Large entries and write batches
can exceed these targets, and readers can retain buffers after eviction. These
values describe storage settings rather than a whole-validator memory ceiling.

The two-hour fixed-object run at `f3bbd7d2` recorded about 222 MiB of history
block-cache usage and 61 MiB of live memtable data at the final diagnostic sample.
The execution index stayed at 1,024 revisions and the proof caches at their
configured entry limits. Diagnostics continued through historical verification
and restart, beyond the timed workload's RSS series. Current resource configurations
record `started_at_unix_ms` alongside monotonic elapsed time to align those phases;
the older recording cannot establish that alignment exactly.

Linux recovery CI runs `disk_full_validator_recovers_acknowledged_operations`
with Regolith history. Before startup, the fixture places one validator's
data on a private 256 MiB tmpfs and keeps its logs on separate storage. Filling
that filesystem must produce a real `ENOSPC` write failure and stop that
validator; the remaining three must continue committing native policies. After
space is restored, recovery must preserve every acknowledged receipt, policy
and actor sequence, match certified headers, and restore quorum participation.
The fixture uses only its own mounts and reaps validators before unmounting.
It requires non-interactive `sudo` mount access; unavailable access fails the
test. This checks filesystem exhaustion and durable-anchor recovery, not
power-loss persistence, failed-device fsync or storage capacity.

The Linux `sync_failure_recovers_acknowledged_operations` case first confirms
one native operation and its independently verified revision on all four
validators. It then attaches `strace` to that validator alone and injects `EIO`
into its first matching `fsync`/`fdatasync` calls per thread. Injection is filtered
to files already open beneath that validator’s `history` directory, leaving
Commonware journals and DKG secrets outside the fault. The private trace must
show an injected synchronization error on a finalized-history descriptor. The validator must stop, the remaining three must keep committing,
and restart must preserve all acknowledged receipts, policy state and actor
sequences. A later write with another voter stopped checks restored quorum
participation. Linux recovery CI runs this case against Regolith.

This fixture requires Linux `strace` and non-interactive `sudo` attachment;
unavailable prerequisites fail the case. It changes the syscall result without
simulating lost device writes or volatile-cache loss. Passing results must be
bound to the tested source and backend. See the [strace fault-injection
contract](https://github.com/strace/strace/blob/master/doc/strace.1.in) for the
per-thread injection semantics. This checks handling of a reported sync error,
not physical failed-device or power-loss durability. Trace files and attachment
logs stay in a private temporary directory and are removed after the tracer exits.

To exercise authenticated snapshot import from pruned peers with Regolith,
build the daemon above, then point the harness at that binary:

```sh
VERAD_BINARY="$PWD/target/debug/verad" RUST_LOG=warn,vera_storage=info \
  cargo test --frozen -p vera-e2e --test snapshot_catchup \
  snapshot_replica_recovers_from_pruned_peers -- --exact
```

This case checks historical receipts and proofs, restored revocation state,
restart, and subsequent writes requiring the recovered member's participation.
The prepared Linux CI workflow runs it after building the Regolith node.

The `snapshot_interrupt` case `interrupted_snapshot_resumes_from_pruned_peers`
combines pruning with a process abort after a durable history-import record.
It removes the explicit snapshot request before restarting, exercising automatic
import resumption. Run it with both the node and test built with
`fault-injection`.
Keep `vera_storage=info` enabled. This checks process-crash recovery, not power-loss
or failed-write behavior.

Snapshot database and history initialization has a five-minute deadline,
configurable through `snapshot.initialization_timeout_ms`. While databases are
pending, startup watches marshal's finalized-processing progress: after
`snapshot.floor_stall_seconds` without progress (default 15, zero disables),
it re-floors marshal from the newest stored gossiped finalization, resuming
dispatches from a retained anchor so the database sync retargets. A pause
while marshal holds the next block, which the sync has not acknowledged yet,
while it repairs a gap from the top down, or while the handoff imports
history re-floors nothing. Exceeding
the overall deadline still exits with `snapshot initialization deadline
exceeded`. Under continuous finalization the state sync completes at its
reached target and settles on the newest one at the first update lull, so
stale targets converge without waiting for network quiescence. Increase the
budget when the expected dataset and network require
longer initialization. Durable import progress is preserved. Actor failures are
also reported while database startup is pending.

The `snapshot_interrupt` case `stale_snapshot_target_recovers_after_sync_fixes`
pauses the joining node after discovery while peers advance beyond retention,
then requires convergence into durable history import, where an injected crash
exercises recovery, certified state, receipts, restart persistence and quorum
participation.

## Physical history-table damage

Three focused storage cases materialize and close a compacted history table, then
change its actual bytes: one flips a trailing footer bit, one removes the
eight-byte table magic, and one flips a byte in the first data-block payload
while leaving its checksum and the complete footer unchanged. The payload case
requires a block-checksum failure rather than accepting any recovery error.
The fixture synchronizes and rereads the damaged file
before reopening history. Opening or recovery must report physical table damage
without publishing a block or stored finalization. Restoring the pristine table
must recover the exact durable records and stored finalization bytes and permit
a subsequent append.

```sh
cargo test --frozen -p vera-node --lib history::tests::physical_tests::
```

The `History file corruption` workflow runs all three cases against Regolith and
lints the affected node tests. The compacting hook
exists only in test builds; production history behavior and dependencies are
unchanged. Hosted execution must pass before these cases count as qualification.

This is physical file-corruption coverage at the history boundary, using small
synthetic finalized records. It does not qualify device power loss, writes during
compaction, Commonware journal corruption or restoration of a complete running
validator. Those require separate checks; replacing individual files is not an
operator recovery procedure.

## Compaction I/O failures

The history fault test flushes three tables, then injects one partial output
write, output-table sync failure or MANIFEST sync failure during foreground
compaction. Each case requires the selected fault to fire. The partial-write
case also checks that a strict subset of the submitted bytes reached the file.
Stored execution records, finalization bytes, receipt lookups and both history
heads must remain unchanged.

An output failure before publication must remove the unreferenced table. A
MANIFEST sync failure must retain the inputs and potentially referenced output:
its uncertain tail can only be resolved by reopen. The test rejects another
metadata update on that handle, reopens through normal history startup, and
requires a subsequent failed receipt to survive another reopen.

```sh
cargo test --frozen -p vera-node --lib \
  history::tests::compaction_tests::failed_compaction_preserves_history_receipts_and_durable_reopen \
  -- --exact
```

The focused history workflow runs this test with the physical damage cases.
The fixture uses real Regolith files and codecs, synthetic execution/finality
records and test-only I/O wrappers. Background compaction is disabled in the
fixture so faults land in the selected foreground operation. Production
settings are unchanged. This checks history recovery after reported I/O
failures; it does not verify live consensus certificates or simulate a physical
power cut across the validator's other stores.

## Retention and the floor

The daemon keeps every finalized record unless `history_retention` in
`config.toml` names how many revisions below the head to keep. An embedded node
keeps `EmbeddedConfig::HISTORY_RETENTION`, 16,384 revisions, unless its host sets
`history_retention` to another value or `None`. After each finalized revision
that the maintenance interval selects (`pruning.maintenance_interval`, or every
64 revisions when consensus pruning is not configured), the node runs one
maintenance pass on the blocking pool after the revision is published: it
raises the floor to that many revisions below the head and sweeps at most 1,024
heights below it. A pass leaves a pending history import alone. A failed pass
stops the node the way a failed append does: a store that refuses that write
would refuse the next append.

The floor is the first block of an epoch, or height 1 while nothing is pruned;
a pass rounds its target down to an epoch's first block, so at least the
configured revisions stay. The `floor` key holds its height and block hash.
The store serves the records from the floor through the head and keeps the
floor's parent, the last block of the previous epoch, which carries the floor
epoch's verifier material: light-block assembly reads it for a revision of that
epoch whose material is not cached, and a start reads it to fill the epoch cache
before walking from the floor. Readers do not serve the floor's parent as a
revision.

Raising the floor is one small atomic write. It stores the new floor with its
block's hash, removes every certificate, imported finality and proof block below
it, and removes the hash mappings of the new floor's parent. From then on readers
refuse heights below the floor, and a mapping that still names one reads as
pruned. The records left below the floor's parent are removed afterwards by a
sweep driven by the `sweep` key, the lowest height whose record may remain. Each
sweep batch is one atomic write over at most 256 heights that ends after the
record bringing its mapping deletes to 4,096: it removes the block-hash and
submission mappings that still name those records, then the records with the
block identifiers kept under their heights, and advances the cursor. A submission hash that a retained revision repeats keeps its
mapping. A crash after the floor write or between sweep batches resumes from the
cursor, and the sweep never reaches the floor's parent.

The participant provider reads a roster from history only for epoch `E + 2`
while the last block of the current epoch `E` is derived, so the boundary it
reads is that block, inside any retained window. A roster whose boundary lies
below the floor's parent fails with `HistoryPruned`.

The node refuses a retention below the windows it reads under its head: the
1,024 revisions of the execution index, the 1,024-revision suffix a recovery
rewinds and two epochs (`minimum_history_retention`, 2,560 revisions for a solo
deployment's 256-revision epochs). The daemon fails to start; an embedded start
fails with `EmbedError::HistoryRetention`.

Reads below the floor fail with the `HistoryPruned` error, which names the
floor:

| Read | Below the floor |
| --- | --- |
| Point lookup by height (`execution_bounded`), light block | `HistoryPruned`; over JSON-RPC code `4444` with `{"retryable": false, "floor": F}` |
| History chunk or proof served to an importing peer | served for the floor's parent; `HistoryPruned` below it, which the peer receives as a refusal naming the floor |
| Lookup by block or submission hash | not found once the mapping is removed; a mapping that still names a pruned revision fails with `HistoryPruned` |
| Receipt (`vera_getTransactionReceipt`, `vera_getReceiptProof`) | `null` for a pruned submission, as for an unknown one; it does not become available later. `4444` when a stale mapping names a pruned revision, or while the in-memory execution index still holds a revision whose finalization is pruned |
| Cut back to a block (`standing`, `rewind_to`) or a recovery anchor | `HistoryPruned`; nothing is removed |
| Term ancestry search | compares blocks only from the higher of the two devices' floors; differing there refuses with `TermRefusal::Pruned` instead of reporting a shared block |

Code `4444` is the code Ethereum clients return for pruned history. It is not
retryable on the same node. Receipts and light blocks below the floor are
unavailable on every device of a deployment, since a device that catches up
adopts its peer's floor. A pruned submission's receipt reads as unknown: a client
polling for it sees `null` until its own deadline, because the node cannot tell
a pruned submission from one it never received once the mapping is gone. The
Rust client's `wait_for_receipt` then returns `ReceiptTimeout`, and returns
`ReceiptUnavailable` at once for a `4444` reply.

### Importing from a pruned peer

A snapshot import walks back from the selected block to the importer's own head,
genesis for an empty directory. A peer serves records and proofs down to its
floor's parent and answers a lower request with a refusal naming its floor. When
every peer fails the next record and at least one refused it as pruned, the
importer finishes at a floor of its own choosing: the lowest epoch start whose
parent it has already imported. The records from that parent through the
selected block are one run authenticated by ancestry from the certified
selection; a peer's stated floor is never used. The refusal itself is not
authenticated: a peer that refuses falsely can leave the importer with less
history, never with wrong history. A peer that keeps the floor's parent hands
on the same floor to the next importer.

The floor may not lie above the first block of the selected block's epoch:
recovery at the selected block needs it at or below the anchor, and the anchor
epoch's verifier material lies in the floor's parent. A higher floor fails the
import with `HistoryPruned`, the snapshot handoff fails and the node stops with
that error.

Finishing is one atomic write. It removes every record below the floor's parent,
including older records the importer held of its own, with their block
identifiers, certificates and imported finality, and every hash mapping; it stores the floor, a sweep
cursor at the floor's parent and the selected block as head, and completes the
import at the floor's parent. Dropping records of the importer's own logs a
warning naming their heights. The
recovery that publishes the import then rebuilds the mappings from the floor. A
crash before the write repeats the attempt; a crash after it leaves a completed
import that recovery publishes. A later selection imports down to the floor's
parent again.

## Recovery of recent execution indexes

Startup rebuilds the resident caches from the most recent 1,024 revisions: it
constructs their transaction indexes, reads their certificates and restores
epoch material. A certificate missing from the store is requested from marshal
and stored. An older certificate is not decoded at startup: a malformed one
fails the proof request that reads it, and one that was never stored is treated
as an ancestor finalized through a descendant. When the history head is at most
1,024 revisions past the anchor and its mappings are current, recovery removes
only the discarded revisions' hash mappings, in the batch that rewinds the head,
and restores any submission mapping they had overwritten. A missing or
mismatched mapping head, a longer or unreadable suffix, or a pending import
rebuilds every mapping. Older executions and receipts remain available through
durable history lookups; consumers still verify their finality evidence
independently.

### The validated head

The `validated` key holds a height and block hash. It states that every record
from the floor through that block decodes, matches its receipt commitment and
names its predecessor as parent, and that the record at the floor is the block
the floor names. Only a batch that establishes the statement writes it:

| Write | Validated head |
| --- | --- |
| First open | genesis |
| Append whose parent is the validated head | the appended block; the append checks contiguity and the receipt commitment before writing |
| Recovery | its anchor, after checking the chain through it, in the batch that sets the history head |
| Cut back to a block of the chain it covers | that block, in the batch that removes the later records |
| Import | unchanged, at or below the committed prefix the import builds on |
| Prune | unchanged; removing records from the start of the claim leaves it true |

The key shares its batch with the records and head it describes, so a write that
fails or is torn leaves both or neither. An import therefore leaves the
validated head below its records, and the recovery that publishes them checks
the whole chain.

A start rereads only the resident window when all of these hold: the query
mappings are current, or only lose a discarded suffix that carried no
submissions; no import is pending; and the validated head equals the durable
history head, lies at or above the recovery anchor and names the block stored
at its height. The window starts no lower than the floor. Before the window it
reads the last block of each of the 128
newest epochs, by height from the fixed epoch length, so the epoch cache holds
what a walk of every record would leave. The window's records are decoded,
checked against their receipt commitments, chained to one another and to the
anchor.

Otherwise startup decodes every retained record and checks receipt commitments
and ancestry from the floor through the anchor, the first record against the
block the floor names, after reading the epoch boundaries below the floor: when the validated head is absent,
malformed, or names another block or height than the durable head; when the
mappings need a rebuild; when an import is being published; and when a
discarded suffix carried submissions, whose earlier mappings are found again by
reading every record. Deleting the `validated` key makes the next start check
every record.

A start over a validated head does not reread records older than the window, so
damage to one of them on disk is not found at start. It is found where the
record is read. Hash and submission lookups decode the record, check its receipt
commitment and require it to match the requested key
(`FinalizedHistory::execution_bounded`). A lookup by height decodes the record
and checks its commitment; proof assembly also checks ancestry across the
descendants it reads, and consumers verify the finality certificate against the
block. Epoch-boundary reads check the record they decode in the same way.
Writes check what they always have.

The focused history regressions compare the recovered cache with full replay and
check that missing records, broken ancestry and altered receipts outside the cache
window still reject recovery. An ignored component timing fixture uses 5,120
revisions containing 20,480 signed reverted native submissions. It measures record
validation and index construction; it does not measure consensus, ACP throughput
or production restart readiness.

`start_cost_against_history_length` measures recovery against history length.
It builds idle histories through `append_finalized`: empty native revisions with
pseudo-random roots, a 236-byte pseudo-random finalization each, and the epoch
artifact on the last revision of every 256-revision epoch. Its writes skip the
log sync to build long histories quickly; the store is reopened with the
embedded memory budgets before each timed recovery. Measured on an Apple M5 Max
with a release build, one run, each recovery directly after the previous one:

```sh
HISTORY_START_REVISIONS=10000,100000,1000000 cargo test --release -p vera-node --lib \
  start_cost_against_history_length -- --ignored --nocapture
```

| Revisions | Store size | Every record checked | Validated head |
| --- | --- | --- | --- |
| 10,000 | 6.5 MB | 0.063 s, 11,028 reads | 0.013 to 0.018 s, 2,088 reads |
| 100,000 | 54 MB | 0.40 s, 101,028 reads | 0.016 s, 2,181 reads |
| 1,000,000 | 772 MB | 4.1 s, 1,001,028 reads | 0.015 to 0.016 s, 2,181 reads |

Checking every record costs about 4 µs a revision with the store in the
operating system's page cache. A start over a validated head reads the window's
records and certificates and at most 128 epoch boundaries, each with the record
after it, whatever the length. A recovery whose anchor is behind the durable
head first reads the records it discards, at most 1,024, to remove their hash
mappings.
The fixture stores 545 to 772 bytes a revision, less than the 1.05 kB a running
node's idle revisions take, and the measurement leaves out a cold disk and the
rest of node start-up.

Restart qualification emits a bounded `recovery_readiness_failure` record when
cluster RPC readiness exceeds its deadline. It identifies unavailable member
positions without endpoint addresses or remote error messages. Readiness requires
a matching successful JSON-RPC response within the shared deadline; an HTTP 200
containing an RPC error is insufficient. This check establishes RPC availability,
while the following certified receipt and state checks establish recovery outcomes.
