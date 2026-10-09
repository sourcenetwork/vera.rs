# Finalized history storage

Commonware stores authenticated current state, pending forks, and consensus
archives. Finalized execution history is a separate database containing records,
certificates, query indexes and snapshot-import progress. Its backend does not
change the revision commitments or proof format.

Normal builds use RocksDB in the node's `history` directory. The opt-in
`regolith-history` build uses Regolith in `history/regolith`:

```sh
cargo build --frozen -p verad --features regolith-history
```

Regolith is pinned to the revision used by DefraDB. History writes explicitly
request synchronous WAL persistence; they do not use Regolith's default eventual
durability. Execution, certificate and query-index updates share one batch.
Snapshots pin consistent reads and borrowed record values. Cursor reads check
status separately from exhaustion so errors cannot appear as empty history.
Recovery batches retain the existing flush threshold, using a running payload
estimate for the Regolith batch.

A history-write error stops finalization before updating the in-memory head or
acknowledging execution. An error does not establish that the batch is absent:
if a complete batch is visible, its stored head can be ahead of memory. Startup
reconciles stored history before serving requests. The focused write-failure
regression checks both absent and visible batches for each backend using injected
errors; it does not qualify device-level write or synchronization failures.

Archived receipt polling returns pending while the receipt's revision is ahead
of the live published index. This prevents a receipt from becoming available in
the interval between its durable history write and publication of query state.

Each build rejects the other backend's history layout before initializing its
own store. There is no automatic on-disk conversion. Keep an existing node on its
original backend, or use a separate node directory and authenticated snapshot
recovery to obtain history with the selected backend. Copying storage files
between the two layouts is not a migration.

The Regolith feature is for qualification. Backend selection does not establish
throughput, memory bounds, or power-loss durability. Its `memtables` diagnostic
reports the engine's current memtable-size counter; it is not directly comparable
to RocksDB's allocation accounting. Unsupported `table_readers` accounting remains
absent, and block-cache usage is reported separately.

Linux recovery CI runs `disk_full_validator_recovers_acknowledged_operations`
with each history backend. Before startup, the fixture places one validator's
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
participation. Linux recovery CI selects each history backend separately.

This fixture requires Linux `strace` and non-interactive `sudo` attachment;
unavailable prerequisites fail the case. It changes the syscall result without
simulating lost device writes or volatile-cache loss. Passing results must be
bound to the tested source and backend. See the [strace fault-injection
contract](https://github.com/strace/strace/blob/master/doc/strace.1.in) for the
per-thread injection semantics. This checks handling of a reported sync error,
not physical failed-device or power-loss durability. Trace files and attachment
logs stay in a private temporary directory and are removed after the tracer exits.

To exercise authenticated snapshot import from pruned peers with Regolith,
build the feature above, then point the harness at that binary:

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
`fault-injection`, and the node additionally built with `regolith-history`.
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
