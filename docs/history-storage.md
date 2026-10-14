# Finalized history storage

Commonware stores authenticated current state, pending forks, and consensus
archives. Finalized execution history is a separate database containing records,
certificates, query indexes and snapshot-import progress. Its backend does not
change the revision commitments or proof format.

All builds use Regolith in the node's `history/regolith` directory:

```sh
cargo build --frozen -p verad
```

`regolith-history` remains an accepted build marker for existing deployment
manifests; omitting it selects the same Regolith implementation. The history
implementation and module persistence no longer depend on RocksDB. Authenticated
module state uses Commonware QMDB; the separate JMT/RocksDB store is removed.

The [node manifest](../crates/vera-node/Cargo.toml) selects the exact Regolith
revision. It includes atomic compaction-manifest edit batches, batched WAL
rewriting during recovery and compaction scans that bypass the foreground cache.
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
and uncertain manifest writes stop further edits until reopening. The reader
accepts legacy manifests; new manifests use format V1, which older Regolith
readers reject. Rollback requires a complete stopped backup from before upgrading,
rather than opening upgraded history with an older node.

A history-write error stops finalization before updating the in-memory head or
acknowledging execution. An error does not establish that the batch is absent:
if a complete batch is visible, its stored head can be ahead of memory. Startup
reconciles stored history before serving requests. The focused write-failure
regression checks both absent and visible batches using injected
errors; it does not qualify device-level write or synchronization failures.

Archived receipt polling returns pending while the receipt's revision is ahead
of the live published index. This prevents a receipt from becoming available in
the interval between its durable history write and publication of query state.

Startup rejects foreign history layouts before creating storage files. There is
no automatic conversion from RocksDB history. Use a separate node directory and
authenticated snapshot recovery to populate Regolith history. Copying files
between storage layouts is not a migration.

Backend selection does not establish throughput, memory bounds, or power-loss
durability. Numeric diagnostics report used and reserved memtable bytes, retired
arena-pool bytes, block-cache usage and pinned table metadata separately. These
counters are non-atomic and do not account for all validator allocations.

Vera currently uses Regolith's default 512 MiB decompressed block-cache target
and 64 MiB memtable flush threshold. The cache fills on reads; reaching the
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
dispatches from a retained anchor so the database sync retargets. Exceeding
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

## Recovery of recent execution indexes

Startup still decodes every retained execution record, checks receipt commitments
and ancestry through the selected durable anchor, restores epoch material and
reconciles query mappings and certificates. Transaction indexes are constructed
only for the most recent 1,024 revisions, matching the resident cache limit. Older
executions and receipts remain available through durable history lookups;
consumers still verify their finality evidence independently. Cache eviction does not weaken history validation or change durability.

The focused history regressions compare the recovered cache with full replay and
check that missing records, broken ancestry and altered receipts outside the cache
window still reject recovery. An ignored component timing fixture uses 5,120
revisions containing 20,480 signed reverted native submissions. It measures record
validation and index construction; it does not measure consensus, ACP throughput
or production restart readiness.

Restart qualification emits a bounded `recovery_readiness_failure` record when
cluster RPC readiness exceeds its deadline. It identifies unavailable member
positions without endpoint addresses or remote error messages. Readiness requires
a matching successful JSON-RPC response within the shared deadline; an HTTP 200
containing an RPC error is insufficient. This check establishes RPC availability,
while the following certified receipt and state checks establish recovery outcomes.
