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

## Current-schema local qualification

On October 6, 2026, source `7d1b35ae356d16751553a62a8c778a803e10ebf4`
completed `128 4 16 900` on one Apple M5 Max host with 18 CPU cores and 64 GiB RAM.
Four validators used the normal release profile, RocksDB history and no span
tracing (`RUST_LOG=warn`). The staged daemon was built from `4a91e354`, whose Git
tree exactly matches the driver source. The `relationship/v5/` dataset grew to
512 objects.

| Measurement | Result |
|---|---:|
| Timed workflows completed | 128 / 128 |
| Offered arrival rate | 4 workflows/s |
| Timed interval, including drain | 34.382 s |
| Completed workflows / timed interval | 3.723/s |
| Certified submissions in timed phase | 640 |
| Embedded mutations in timed phase | 1,664 |
| Submission-to-verified-receipt p50 / p95 / p99 | 517.55 / 728.60 / 773.25 ms |
| Complete-workflow p50 / p95 / p99 | 2,859.13 / 3,488.46 / 3,622.32 ms |
| Peak sampled RSS per validator during timed phase | 224.03–231.48 MiB |
| Explicit throttling responses across the run | 1 |
| Hard restart plus all-replica verification | 19.804 s |
| Whole run | 186.20 s |

Each timed workflow contains five serial certified submissions and 60 verified
permission checks. Percentiles use the same nearest-rank rule as
`operation_baseline`; receipt latency includes submission, polling and proof
verification. The restart measurement includes verification of all 128 workflows
on all four replicas.

Across setup, workload and final checks, all 771 submissions and 2,179 embedded
mutations were certified successful. The run verified 38,400 permissions and
10,240 ownership proofs. All five replica-check phases passed: after workload,
after relation removal, after relation recreation with old grants still denied,
after explicit regrant, and after hard restart. No issued submission was left
unresolved. Resource and storage sampling reported no errors.

These measurements qualify this local workload at the stated offered load.
They do not establish maximum capacity, sustained memory behavior, WAN finality,
or a comparison with the Go implementation. They are not comparable throughput
figures to the single-write workflows in `operation_baseline`.

Executable SHA-256 values for reproduction:

- Driver: `7fc8a7acae33b76f21254eb45af0db81ce13694811e5e70d5677a4b8c966ffa0`
- Daemon: `90b2c738af83e10a96ac49d4fafa3ed1dbc884518a142592a95c7863869422e1`
