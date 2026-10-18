# History finalization measurements, October 19, 2026

Issues [#229](https://github.com/sourcenetwork/vera.rs/issues/229) and
[#231](https://github.com/sourcenetwork/vera.rs/issues/231) refresh Commonware and
evaluate whether history persistence warrants a grouped writer. The decision is
to retain the existing synchronous history boundary. These measurements show a
real write cost, but do not establish a throughput benefit from grouping
consecutive revisions. The new aggregate instrumentation makes that decision
retestable on deployment hardware.

## Source and setup

The [numeric record](history-finalization-20261019.json) contains the complete
configuration, outcome counters, stage summaries and raw artifact hashes.

- Vera source: `348e502de82f73c1edce5cd3ef202ef3216ebfcf`, clean checkout.
- Commonware official base: `12772870feec3d7058fd38bcd2a1200a5624ee34`.
  Integration: `b8bdee194ee8d4933d0c2867e1c104f229d94e96`; the only delta is
  the two pending DKG retry commits from upstream
  [#5263](https://github.com/commonwarexyz/monorepo/pull/5263).
- Regolith: `e844baef` from the recorded Vera lockfile; no storage option changes.
- Rust 1.98.0, release profile; Apple M5 Max, 18 logical CPUs, 64 GiB RAM,
  macOS 27.0, default allocator. This was a shared development host.
- Four validators on one host, pipelined Simplex, normal timing preset,
  100 ms proposal batching, 192 revisions per epoch, 256 retained consensus
  revisions. The workload used 32 objects/signers, 128-byte update payloads,
  and one permission read after each certified native object update.
- Runs were sequential: measured 50/s, uninstrumented control 50/s, measured
  100/s. Each scheduled arrivals for 120 seconds, then drained outstanding
  workflows. Updates to each object wait for its preceding workflow.
- Measured runs enabled only `warn,vera_resource_diagnostics=debug`; the control
  used `warn`. No per-revision tracing or syscall tracer ran.

The recorded node SHA-256 is
`a91e321421a09e5c12d16ac3da49e7efb9e1bd09ef1515dc160838a546fcca9d`;
the workload runner SHA-256 is
`68bfd3bf132f5e010a75e24ccdc05c05cef6969655e751babcf790cd99982a2f`.
Both binaries were built from the runtime source in `59f7a1b97f`; the subsequent
`348e502de8` changed only the recovery test's logging configuration.

## Workload outcomes

| Run | Completed / offered | Completion rate, including drain | Scheduled arrival to certified receipt p95 | Read throttles |
| --- | --- | --- | --- | --- |
| Measured, 50/s | 6,000 / 6,000 | 46.60/s | 8.44 s | 319 |
| Control, 50/s | 6,000 / 6,000 | 40.67/s | 20.85 s | 1,692 |
| Measured, 100/s | 12,000 / 12,000 | 43.79/s | 148.79 s | 2,629 |

Every operation was verified across all four replicas. Each run restarted one
validator and inspected every operation: zero receipt or state mismatches.
There were no unknown, rejected, reverted, unsubmitted or verification-failed
operations. Read throttling was retried, and is reported rather than hidden.

The 100/s recording also passed the archive-retention audit: 10–11 samples per
member, at least 867 finalized heights of span, and zero maximum excess lookup
entries over retained records in both archives. Separate focused checks passed
for upstream archive pruning and sync, pending-epoch DKG retry, all 128 durable
state-partition recovery subsets, corruption/write-failure history recovery,
canonical module behavior, and cold recovery from already-pruned peers followed
by requiring the recovered validator for quorum.

These are finite workload results, **not sustainable capacity or consensus
finality figures**. Scheduled-arrival latency includes client scheduling and
per-object waiting. Its p95 scheduling lag reached 7.80 s, 20.02 s and 148.35 s
respectively; 100/s was not sustained by this deployment/workload. The control
also fell behind. Its host load increased substantially during the run, and one
control cannot quantify diagnostic overhead or a performance regression. It
does not support a claim that instrumentation improves performance.

## Where the time went

Values below are ranges of the four validators' per-observation means. Numeric
snapshots were aligned to original process IDs and the workload clock, excluding
setup and restart. Observed intervals were about 90 seconds per member at 50/s
and 240 seconds at 100/s, including drain within the workload window.

| Stage | Measured 50/s | Measured 100/s |
| --- | --- | --- |
| Complete application callback | 38.01–41.57 ms | 43.04–45.50 ms |
| Certificate/artifact lookup | 1.59–2.57 ms | 3.64–4.47 ms |
| Blocking-pool scheduling | 0.012–0.014 ms | 0.033–0.064 ms |
| History preparation before head lock | 0.012–0.016 ms | 0.013–0.014 ms |
| History head-lock acquisition | 0.0002–0.0003 ms | 0.0002–0.0004 ms |
| Synchronous history batch | 33.96–38.20 ms | 37.63–39.30 ms |
| QMDB apply | 14.72–16.25 ms | 17.02–18.99 ms |
| QMDB durability wait | 9.31–13.13 ms | 11.60–15.33 ms |
| QMDB durability completion from finalize entry | 113.26–116.13 ms | 123.82–129.57 ms |

These intervals overlap and must not be added. In particular, durability
completion includes work before its first wait. They measure revisions or
barriers, not individual transactions. Independent snapshot boundaries can
produce a one-observation difference between nested stage counts.

History batches occupied 12.1–13.9% of each member's observed elapsed time.
Regolith's WAL histogram accumulated 12.1–13.9% over the same intervals. Its
17.06–19.63 ms means combine separate append and synchronization observations;
they are **not the duration of one fsync or one batch**. The backend records both
operations under `WalWriteTime`, explaining approximately two observations per
history batch. The close aggregate totals locate most history time in WAL work;
they do not isolate the operating system's synchronization cost.

## Persistence decision

Keep one ordered synchronous batch per finalized revision for this change:

1. Head-lock contention, preparation and blocking-pool scheduling are negligible
   here. More history worker threads would not address the measured cost.
2. Commonware's stateful processor awaits the application's finalized callback
   before processing the next revision. Waiting inside that callback for a
   second revision to form a group cannot make progress. Returning early would
   change the callback's durable publication contract and require a coordinated
   acknowledgement, failure and recovery design.
3. History synchronization costs tens of milliseconds, but occupied roughly
   one eighth of elapsed time. This is worth measuring on target hardware; it
   is not evidence that a concurrent history writer would eliminate the
   observed backlog. QMDB, revision production, per-object sequencing, RPC read
   throttling and host variability remain in these results.

No candidate queue or extra writer was added. Revision/certificate/index
atomicity, contiguous ordering, fatal write-failure behavior and publication
only after synchronous persistence remain unchanged. Existing crash, corruption
and restart checks validate that boundary on the refreshed dependencies.
If a later isolated capacity study identifies a material benefit, a candidate
must explicitly bound revisions and bytes, define cancellation/failure handling,
and pass interleaved release comparisons plus deterministic recovery tests.
[Issue #232](https://github.com/sourcenetwork/vera.rs/issues/232) tracks the
separate capacity study; this report establishes no new operating limit.

## Reproduction

Build the daemon and workload runner with the locked source:

```sh
cargo +1.98.0 build --frozen --release \
  -p verad -p vera-e2e --bin verad --example operation_baseline
```

For the measured 50/s profile, use new private output directories:

```sh
VERA_E2E_KEEP=1 VERA_E2E_DIR=/private/path/member-logs \
python3 tools/performance/record.py \
  --node target/release/verad \
  --runner target/release/examples/operation_baseline \
  --history regolith --output /private/path/run \
  --rust-log warn,vera_resource_diagnostics=debug \
  6000 50 128 1 normal 100 192 0 32 256 1 1
python3 tools/performance/report.py /private/path/run
python3 tools/performance/snapshot_metrics.py /private/path/run \
  --node-logs /private/path/member-logs --minimum-samples 2
python3 tools/performance/finalization_summary.py /private/path/run
```

The existing report command requires its documented plotting dependencies. Use
`warn` for the control, without snapshot extraction. For the higher-load profile
replace `6000 50` with `12000 100`. Retain raw logs privately; the committed
numeric record exports outcomes and hashes, without keys or node data paths.
