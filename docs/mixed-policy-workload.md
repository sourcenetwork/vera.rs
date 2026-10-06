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

Build the example from the candidate source. Use the independently staged release
daemon from Vera `382b36356de56ea17efdbda6b3ecf44da524fddc`, with its artifact hash
recorded alongside the run. The driver source is layered on that revision.
Finish all compilation before starting the workload; do not measure while
another build or workload is running.

```sh
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
