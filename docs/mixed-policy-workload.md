# Local mixed-policy workload

`mixed_policy_workload` exercises certified native mutations and permission
checks over a growing dataset on four local validators. It uses normal timing,
pipelined Simplex, 192 finalized revisions per epoch, and native BLS signers.
The daemon is supplied separately through `VERAD_BINARY`; the driver never builds
or substitutes a daemon.

Each workflow has its own owner and four registered objects: a leaf group, a
nested team group, a folder and a document. Two readers belong to the leaf group;
the team references its `member` userset, the folder references the team's
`member` userset, and the document follows `parent->read`. An explicit `blocked`
relation excludes a reader from the document. A third actor has no grants.
All workflows share one policy but distinct objects and owner signing sequences.

The timed workflow creates the objects and grants in one native submission,
then revokes a member, regrants that member, blocks that reader on the document,
and removes the block. Each phase waits for a verified successful receipt and
checks all four objects for both readers and the outsider, using permission
evidence at least as recent as that receipt. Signing and writes remain serial
within each workflow. Completed workflows leave their records in place, so the
dataset grows throughout the run.

After the timed phase, the driver verifies every object and owner on all four
replicas. It removes the policy's `member` definition, verifies denial, restores
the definition, and verifies that the old grants remain denied. It explicitly
regrants both memberships and both retired userset edges, verifies restored
access, then hard-restarts one replica and checks all expected states again on
all four replicas. Owner proofs must remain valid throughout these policy edits.
These checks are separate from timed workload latency. Replica verification runs
up to eight flows concurrently on one replica at a time. Each flow checks its
objects sequentially at the same minimum revision; the first failure stops that
verification phase. JSONL records the verification concurrency.

## Build and run

Build the daemon and driver from the same candidate source tree, then stage the
daemon and record both executable hashes and source revisions with the results.
The driver embeds the ACP proof verifier, so a driver from an older relationship
schema cannot qualify a current daemon.
Finish all compilation before starting the workload; do not measure while
another build or workload is running.

```sh
cargo +1.98.0 build --frozen --release -p verad --bin verad
cargo +1.98.0 build --frozen --release -p vera-e2e --example mixed_policy_workload
export VERAD_BINARY=/absolute/path/to/staged/verad
export VERA_E2E_DIR=/absolute/path/to/private/mixed-policy-evidence/clusters
export VERA_E2E_KEEP=1
export RUST_LOG=warn
# The results directory must exist. Use a new output path for every run.
"${CARGO_TARGET_DIR:-target}/release/examples/mixed_policy_workload" 16 2 8 900 \
  > /absolute/path/to/private/mixed-policy-evidence/results.jsonl \
  2> /absolute/path/to/private/mixed-policy-evidence/driver.log
```

Arguments are workflow count, scheduled arrivals per second, maximum outstanding
workflows, and whole-run deadline in seconds. Defaults are `16 2 8 900`; zero is
rejected. Outstanding workflows are bounded by backpressure, which may delay an
arrival; `schedule_lag_ms` records that delay. The configured arrival rate is an
offered schedule, not an achieved service rate.

A native submission contains one or more embedded mutations: individual ACP
command calls such as registration, grant, deletion, creation or editing. These
counts are not physical key/value writes; a batch wrapper is not an extra mutation. The timed default
issues 80 distinct submissions containing 208 mutations. JSONL counters separately
report distinct issued submissions, submission attempts, issued embedded
mutations, certified successes and mutations, verified permission/owner checks,
and explicit throttling responses. The policy setup, edits and post-edit regrants
appear separately; `counts_before` and `counts_after` delimit the timed phase.

Every submission keeps one signed identity across explicit throttling retries.
Transport errors are not retried as new submissions. Receipt absence is polled;
verification errors and unexpected permissions fail immediately. Requests have a
fixed 30-second deadline, workflows 120 seconds, and the whole run its configured
deadline. Initial readiness has a 30-second limit. Warm restart allows the existing
30-second retained-history probe plus the harness readiness allowance, including
any configured deadline scaling; the effective limit is recorded in JSONL.
A failure or deadline exits nonzero and records its stage and error;
issued submissions without certified successes remain unresolved, not successful.
`VERA_E2E_KEEP=1` is required to preserve node logs and state. Keep these artifacts
private: node directories include fixture keys and databases.

The configuration row reports `debug_assertions`; release qualification should
record `false` for the driver and retain the separate daemon build manifest.
JSONL includes submission and workflow-stage latency, scheduled-to-completion
latency, replica checks and restart latency. The existing resource sampler emits
per-process RSS and cumulative CPU time every second during the timed phase;
filesystem samples surround the workload and final checks. Sampling errors remain
errors rather than zero-valued resource measurements.

This is a local functional and offered-load qualification with a small synthetic
dataset. It is not a capacity result, a WAN or adversarial-network test, or complete
production qualification. It does not qualify other replica counts, threshold
changes, or every failure point during recovery.

## Linux CI gate

The Linux checks job builds the existing mixed-policy driver in the normal
release profile and runs sixteen workflows at two offered workflows per second,
with at most eight outstanding workflows. It uses the same RocksDB release
daemon as the native-ring check and release bundle. The driver retains its
900-second whole-run deadline; the recorder allows 960 seconds for termination.

The gate requires all five timed grant, revocation and exclusion phases and all
five later verification phases on every validator, including definition removal,
reintroduction without resurrecting old grants, explicit regrant and hard restart.
The complete run must certify 99 distinct submissions containing 275 mutations,
verify 4,800 permission decisions and 1,280 ownership proofs, and preserve every
workflow. Missing or duplicate workflow/replica checks, mixed checkpoint values,
incomplete resource sampling and uncertified submissions fail qualification.

Only `mixed-policy-evidence.json` is uploaded. It contains source and executable
hashes, bounded counters, latency percentiles, restart time and sampled RSS peaks.
Workflow timings cover the timed phase; submission timings include setup, edits
and later regrants. Node directories, keys, policy/request identifiers, paths,
raw JSONL and error messages remain private and are removed after collection.
Failed qualification exports a fixed failure stage rather than private output.

This is a short functional gate for the four-validator Linux RocksDB deployment.
It does not establish sustainable capacity, steady-state memory, WAN behavior,
other storage backends or equivalence to the historical local measurement below.

## Current-schema local qualification

On October 6, 2026, clean source
[`a1cbace66f2f88afaa0ee87148cdbfb7158db9a6`](https://github.com/sourcenetwork/vera.rs/commit/a1cbace66f2f88afaa0ee87148cdbfb7158db9a6)
completed `512 4 16 900` on one Apple M5 Max host with 18 logical CPUs and
64 GiB RAM. The daemon and driver used that same source, Rust 1.98.0 and the
normal release profile. Four validators used RocksDB history, normal timing,
pipelining and 192-revision epochs. The daemon was staged before test-feature
unification; the driver was built and staged before measurement. Profile,
deadline and KDF overrides were cleared. Span tracing was disabled and
`RUST_LOG=warn`. The `relationship/v5/` dataset grew to 2,048 objects.

| Measurement | Result |
|---|---:|
| Timed workflows completed | 512 / 512 |
| Offered arrival rate | 4 workflows/s |
| Maximum outstanding workflows | 16 |
| Timed interval, including drain | 129.988 s |
| Completed workflows / timed interval | 3.939/s |
| Certified submissions in timed phase | 2,560 |
| Embedded mutations in timed phase | 6,656 |
| Verified permissions in timed phase | 30,720 |
| Submission-to-verified-receipt p50 / p95 / p99 | 517.28 / 794.52 / 1,335.15 ms |
| Complete-workflow p50 / p95 / p99 | 2,838.97 / 4,546.89 / 5,734.20 ms |
| Schedule lag p50 / p95 / p99 | 2.36 / 920.08 / 1,726.93 ms |
| Peak sampled RSS per validator during timed phase | 259.61–270.78 MiB |
| Explicit throttling responses across the run | 1 |
| Hard restart plus all-replica verification | 66.124 s |
| Whole recorder command | 708.34 s |

Each timed workflow contains five serial certified submissions and 60 verified
permission checks. Percentiles use the same nearest-rank rule as
`operation_baseline`. Receipt latency starts before signing and includes
submission, polling and proof verification. Workflow latency starts when that
workflow begins; schedule lag separately measures delay from its offered arrival.
The maximum schedule lag was 2,126.32 ms. Backpressure delayed arrivals rather
than dropping workflows, so the completed rate differs from the offered rate.

Across setup, workload and final checks, all 3,075 issued submissions and 8,707
embedded mutations were certified successful, with 3,075 submission attempts.
The run verified 153,600 permissions and 40,960 ownership proofs. All five
replica-check phases passed: after workload, after relation removal, after
relation recreation with old grants still denied, after explicit regrant, and
after hard restart. No issued submission was left unresolved.

The restart timer includes readiness and verification of all 512 workflows on
all four replicas; the latter phase took 61.866 seconds. The 66.124-second total
is not an isolated startup or recovery latency. The whole recorder command also
includes setup, policy edits, serial regrants, all replica checks and cleanup;
it is not 708 seconds of sustained arrivals.

Resource sampling recorded 130 complete one-second samples per validator during
the timed phase, spanning 205.14–270.78 MiB RSS. Each validator's peak was its
last sample as the dataset grew. RSS and CPU sampling exclude the subsequent
policy edits, replica checks and restart. Resource and storage sampling reported
no errors. Per-validator filesystem snapshots were:

| Snapshot | Logical file bytes (MiB) | Allocated file bytes (MiB) |
|---|---:|---:|
| Before timed workload | 0.56–0.57 | 0.73–0.73 |
| After timed workload | 54.45–54.48 | 57.20–57.25 |
| After all verification | 86.02–94.92 | 89.18–98.18 |

These are recursive file-size snapshots, not physical write-volume measurements.
This single local run qualifies the stated workload and offered load. It does
not establish maximum capacity, sustained memory behavior, WAN finality or a
comparison with the Go implementation. Its workflow rate is not comparable to
the single-write workflows in `operation_baseline`.

Executable SHA-256 values for reproduction:

- Driver: `e0104fd88f180f0a5cc85b5093f64c2794a157a1b6d7896dafc70a5342ed12d5`
- Daemon: `94b520010684a1692f99a4a6e5dd9055a3c790139d6939f04fa4598e96a1ed03`
