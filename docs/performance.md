# Performance measurements

Vera has two workload drivers:

- `operation_baseline`: four local members; certified native ACP writes,
  optional verified permission reads, per-member resource samples, replica
  reconciliation, and hard-restart checks. Growing registrations and repeated
  updates to a fixed object set exercise different memory behavior.
- `wan_baseline`: externally provisioned members, with explicit network and
  deployment settings. See [WAN gates](wan-gates.md).

The [Performance workflow](../.github/workflows/performance.yml) runs after a
successful main-branch CI push, or through manual dispatch. It builds release
binaries before measurement and runs RocksDB and Regolith history on separate
hosted runners. Each backend measures 3,000 operations at 50 offered arrivals/s,
first with growing registrations and then with 128 repeatedly updated objects.
These are fixed-load baselines, not searches for maximum throughput. They are
not part of every pull request's test loop.

Before final-state reconciliation, `operation_baseline` selects the highest
measured receipt revision and waits up to 30 seconds for that exact receipt on
every replica. It compares the transaction hash, block hash, height and status
before checking final ownership and permissions. Earlier receipts alone do not
establish that later updates are visible. The `replica_state_barrier` record
reports the selected receipt, replica count and wait duration separately from
workload latency and throughput. Existing receipt, state and restart assertions
remain required.

## ACP lifecycle components

`component_baseline` includes policy edits and deletions with 32, 256 and 2,048
objects. Each object has an owner, a direct grant, an incoming userset grant,
a registration commitment and an amendment event. A separate case holds the
target at 32 objects while adding 2,048 objects and their dependent records to
another policy. This exposes both target-policy cost and work caused by unrelated
state.

Every measured operation starts from a fresh shared snapshot. Timings exclude
fixture construction, snapshot cloning, result disposal and restoration checks.
Before sampling, the fixture checks grant pruning, unchanged unrelated records,
snapshot isolation, serialization restoration and absence of resurrected grants
when a removed relation is reintroduced. These are module costs; they exclude
consensus, durable storage and RPC/proof generation.

Fixture version 3 retains the previous eleven measurements and adds
`acp_policy_logical_edit_32` and `acp_policy_logical_edit_2048`. These hold the
policy definition fixed and time removal of one relation with 32 or 2,048 target
objects. Each object has an owner and one direct reader grant. Outside timing,
the fixture checks the exact removed count, immediate access revocation,
restoration and no resurrection after recreating the relation. Physical rows
remain throughout these checks; `end_blocker` cleanup is excluded from the edit
timing. The report includes the 2,048/32 cost ratio for each head pass.

Comparisons still accept version 1 or 2 baselines and show new measurements
without inventing a baseline. Matching measurements retain their comparisons;
missing measurements or inconsistent fixtures fail the report. These component
ratios do not measure service throughput or establish a production resource bound.

## Local pipelined load measurement

On September 19, 2026, four validators on one macOS host used RocksDB history,
16-view leader terms, optimistic distance 4, and a 100 ms proposal collection
window. The driver offered 48,000 native ACP workflows at 400/s for 120 seconds,
with one verified permission read per write and 1,024 outstanding workflows.
Builds and profiling were excluded from the measurement interval.

44,335 workflows completed in 121.342 seconds including drain (365.37/s).
Certified-receipt p95 was 2,643.88 ms; permission-read p95 was 1,288.77 ms;
complete-workflow p95 was 3,605.19 ms. The driver did not send 3,665 scheduled
workflows, so **the 400/s offered-load gate failed**. The completed-subset rate
is not a sustainable-throughput qualification or a comparison against the Go
implementation. All four replicas reconciled all 48,000 expected outcomes,
including absence of unsent requests; hard restart found zero receipt or state
mismatches. These local results do not establish WAN performance or 300 ms
finality.

A follow-up with direct storage-lock wakeups completed 44,515 workflows in
122.931 seconds (362.11/s), leaving 3,485 unsent. Receipt p95 was 2,562.16 ms,
permission p95 1,187.61 ms, and workflow p95 3,388.75 ms. Replica and restart
checks again found no mismatches. This also failed the offered-load gate;
these single trials do not establish a throughput improvement from the wakeup
change.

## Pull request comparisons

The [PR performance workflow](../.github/workflows/performance-pr.yml) measures
code-changing same-repository PRs on one hosted Linux runner. It checks out the
exact PR head and base-tip revisions and builds both node binaries with Rust
1.98.0 in the release profile. One head-built `operation_baseline` drives both
revisions, giving them identical workload generation and correctness checks.
Component executables remain specific to each revision. All binaries are preserved
before four passes run in head/base/base/head order, with no compilation or chart
rendering between them.
Fork PRs cannot run this job because the locked dependencies require credentials.

Each pass measures 600 operations at 20 offered arrivals/s on four local
validators: growing registrations and repeated updates to 32 objects, both with
verified permission reads. Receipt, permission and full-workflow p95, completed
workflows/s, and peak member RSS appear in the check summary. Every pass must
satisfy the existing completeness, certificate, replica and hard-restart gates.
A failed run is never presented as improved performance. Configuration changes
are listed explicitly and suppress full-stack percentage comparisons. The driver
also generates genesis/configuration and verifies native receipts and proofs.
Before running workloads, committed ACP source supplies the explicit relationship
namespace and matching record schema. Known `relationship/v3/`, `relationship/v4/`
and `relationship/v5/` schemas are mutually incompatible for permission verification.
The v5 schema requires relation generations and a mandatory `RelationshipRecord`
`incarnation: u64` without a deserialization default. For these boundaries,
baseline full-stack passes are recorded as **not run** in `unavailable.json`; both head passes still require every correctness and recovery
gate. Reports show head-only values, no baseline success and no full-stack delta.
Unknown or inconsistent schemas fail. Other interface errors and failures on a
compatible baseline still fail the job. There is no verifier relaxation or fallback
to a different workload driver. Component passes retain their existing independent
fixture and sampling checks. Earlier measurements do not qualify the v5 archive
or proof paths; this schema check supplies no new performance result.
Block limits printed by the driver are its compiled configuration assumptions, not measurements of the base node's
capabilities.

The component executable separately measures native BLS request verification,
ACP owner-read evaluation with read capture, and consensus-certificate verification
through `verify_light_block`. Fixed fixture construction and signing occur before
timing; each component warms for 200 ms then records nine 100 ms samples. These
are repeated hot-fixture costs, not distributed consensus latency, disk proof
construction, or representative complex-policy performance. A component newly
introduced by the PR is reported without a fabricated base measurement.

The report compares medians of two passes per revision. Changes below 5% are
within threshold; larger changes with overlapping pass ranges are inconclusive.
Within-revision pass spread above 5% also makes a larger change inconclusive.
Otherwise, separated ranges are labelled improvement or regression **signals**, not
statistical confidence. Performance changes are advisory on shared runners;
missing measurements, build failures and failed correctness gates fail the job.
The workflow summary and 30-day artifacts contain pass ranges, raw measurements,
separate node and workload-runner source revisions, binary hashes, workload
configuration, host provenance and per-pass charts. Version 2 comparison records
require the same head-sourced driver hash for every pass and reject dirty or
misattributed sources. Historical version 1 artifacts retain their original
per-revision runner identities when re-read. The workflow has read-only repository permissions and does not
post comments or publish a site. Throughput at this fixed offered rate is not a
maximum-throughput benchmark.

Run the same comparison locally after building each revision into separate
`binaries/head` and `binaries/base` directories. Each contains its own `verad` and
`component_baseline` when available; the head component executable is required.
Only `binaries/head` needs `operation_baseline`:

```sh
python tools/performance/run_pr.py --head /path/to/head --base /path/to/base \
  --binaries /path/to/binaries --output /path/to/new-results
```

Use an environment with `tools/performance/requirements.txt` installed. Both
checkouts must be clean and match their binaries. The main/manual Performance
workflow also retains the component samples alongside its RocksDB and Regolith
full-stack runs.

Each artifact includes:

- Node and runner checkout revisions, their dirty status and binary hashes,
  platform, CPU count, memory, runner image,
  load averages, backend selection, exact arguments, and process exit status.
- Raw versioned JSONL observations, including rejection, uncertainty, throttling,
  and incomplete workflows.
- A machine-readable report, Markdown summary, and SVG/PNG plots of certified
  receipt latency distribution and member RSS over the measured interval.
- Replica reconciliation and hard-restart results. Missing results or correctness
  failures fail report generation or mark the run failed, never successful.

Only measurement files are uploaded. Member data directories, identities, and
secret stores are outside the artifact directory. Artifacts retain 30 days of
results; no performance site is published by this workflow.

## Measured local results

Release builds with bounded parallel native verification produced these results
on an Apple M5 Max host (18 logical CPUs, 64 GiB RAM). Each run used four local
validators, QMDB state, RocksDB history, and growing ACP object registrations
with certified receipt verification. Permission reads were disabled. Signing
happened before timing.

| Preset | Offered duration | Offered writes/s | Operations | Completed writes/s | Median confirmation | p95 confirmation | p99 confirmation |
|---|---:|---:|---:|---:|---:|---:|---:|
| Normal | 30 s | 200 | 6,000 | 194.04 | 729 ms | 1,588 ms | 2,001 ms |
| Fast | 30 s | 200 | 6,000 | 195.88 | 783 ms | 1,975 ms | 2,390 ms |
| Fast | 120 s | 200 | 24,000 | 199.23 | 777 ms | 2,006 ms | 2,580 ms |
| Normal | 30 s | 400 | 12,000 | 388.54 | 1,143 ms | 2,675 ms | 4,179 ms |

Every offered operation completed. All four replicas agreed, and receipt/state
checks passed after a member was forcibly restarted. None of these runs had
uncertain, rejected, reverted or unverifiable outcomes. Bounded submission and receipt-read
retries handled admission throttling. The 400/s run observed 488 submission
throttles and 32,119 receipt-read throttles; these are individual retry responses,
not failed operations. This higher offered load increases the demonstrated load
point, but is not evidence that the optimization doubled capacity.

A two-minute follow-up at 400 offered writes/s did **not** pass the complete-load
qualification gate. It confirmed 47,961 of 48,000 scheduled writes; the driver
left 39 unsent when its 1,024-outstanding-workflow cap filled between 99.16 and
99.71 seconds. Submitted writes had no uncertain, rejected, reverted or
unverifiable outcomes, and replica/restart checks matched all expected results,
including absence for the unsent writes. The report correctly marks this run
failed. The short 400/s result therefore does not establish sustained capacity.
The failed run observed 2,154 submission and 127,746 receipt-read throttle
responses. These older counters combined local client saturation and remote
rejections; they cannot establish a server admission bottleneck.

A subsequent 30-second run with separate throttle-origin counters completed all
12,000 writes at 389.66/s (median 1,091 ms, p95 2,343 ms), including replica and
restart checks. It recorded 26,602 local client-capacity events and 1,495 remote
throttles. Its successful receipt calls, including client verification, took
6.93 ms median and 21.15 ms p95. This identifies client request scheduling as an
investigation target, but does not close the failed two-minute 400/s gate.
A separate run with per-receipt diagnostic logging dropped 4,319 offered writes;
it remains failed evidence and is excluded from the passing results above.

With bounded client request queuing enabled, a subsequent Normal-preset run
completed **48,000/48,000 writes at 400 offered writes/s for 120 seconds**.
Including drain, throughput was **392.49 writes/s**; certified confirmation was
**976 ms median, 1,897 ms p95, and 2,249 ms p99**. All four replicas and the
hard-restart checks agreed on all 48,000 operations. There were no unsent,
uncertain, rejected, reverted or unverifiable outcomes. Local client throttles
were zero; 11,356 remote receipt-read throttles resolved within the deadline.
HTTP concurrency remained 64 and outstanding workflows remained capped at 1,024.
This passes the previously failing two-minute workload with different client
admission behavior; a single trial does not establish a repeatable speedup or
maximum capacity. Permission reads and WAN operation remain unqualified here.

Adding one verified current-owner permission read after each registration produced
the following results with the same binaries and bounded client queue:

| Offered workflows/s | Duration | Completed / offered | Complete-load gate | Completed workflows/s | Permission read median / p95 | Full workflow p95 |
|---:|---:|---:|---|---:|---:|---:|
| 200 | 30 s | 6,000 / 6,000 | Passed | 191.59 | 2.66 / 76.35 ms | 1,572 ms |
| 400 | 120 s | 46,158 / 48,000 | **Failed** | 380.06 | 68.18 / 2,113.09 ms | 4,027 ms |

Both runs passed replica and hard-restart reconciliation with zero uncertain,
rejected, reverted or unverifiable outcomes. The 400/s run left 1,842 operations
unsent when the outstanding-workflow cap filled; its throughput and latency
describe completed operations only, not qualified capacity. It recorded zero
local client throttles, 51,333 remote permission throttles and 28,947 remote
receipt throttles. Remote retryable errors include evidence waits as well as
admission rejection, so these counts alone do not identify the server bottleneck.
Permission latency includes retries, queuing and proof verification. These reads
check owner access on new objects; they do not qualify revocation workloads or WAN
latency. The passing write-only 400/s result does not extend to this combined path.

A follow-up separated bounded permission waiting from shared proof generation
(described below), without increasing the eight-permit evidence budget. The same
two-minute combined 400/s workload completed 46,573/48,000 operations and left
1,427 unsent: it **still failed** the complete-load gate. Replica and hard-restart
reconciliation passed for all expected outcomes. Completed-subset throughput was
382.54 workflows/s; permission p95 was 1,423 ms and full-workflow p95 was 3,234 ms.
It recorded 9,184 receipt and 43,482 permission remote throttles, with no local
throttles or uncertain, rejected, reverted or unverifiable outcomes. These are
individual trials; the reduced receipt throttling does not establish a repeatable
speedup or qualified 400/s combined capacity.

For comparison, the earlier sequential-verification revision
`c1f9cff9ac399757684b5dc539252934241278fa` passed these Normal-preset runs on the
same host:

| Offered writes/s | Operations | Completed writes/s | Median confirmation | p95 confirmation | p99 confirmation |
|---:|---:|---:|---:|---:|---:|
| 20 | 600 | 19.65 | 625 ms | 1,316 ms | 1,566 ms |
| 100 | 3,000 | 96.58 | 671 ms | 1,351 ms | 1,645 ms |
| 200 | 6,000 | 196.66 | 775 ms | 1,682 ms | 2,176 ms |

These are individual fixed-load measurements, followed by draining
outstanding work. Completed writes/s includes that drain interval. They establish
a passing local load point, not maximum or sustained capacity, or a statistically
established throughput improvement. At 200 offered writes/s, Normal had lower
tail latency than Fast in the new runs. Confirmation includes admission, execution, consensus, polling and
proof verification; these measurements do not establish 300 ms consensus
finality. WAN deployment and write-plus-permission workflows require separate
qualification.

The new workload arguments were:

```text
6000 200 1024 0 normal 100 20 0 0 32
6000 200 1024 0 fast 100 20 0 0 32
24000 200 1024 0 fast 100 20 0 0 32
12000 400 1024 0 normal 100 20 0 0 32
# Two-minute gate: failed with fail-fast admission; passed with bounded queuing:
48000 400 1024 0 normal 100 20 0 0 32
```

All runs used 50 ms receipt polling, a 30-second workflow deadline, 20 revisions
per epoch, and retention of 32 consensus revisions. The earlier 20/s and 100/s
runs used an outstanding-workflow limit of 256.

Before parallel verification, a Fast diagnostic at 100 offered writes/s stalled
at height 20: repeated 256-operation proposals took approximately 294–298 ms to
execute, exceeding its 100 ms leader and 200 ms notarization deadlines. A focused
follow-up measured median authentication around 590 microseconds per operation,
versus 8 microseconds for dispatch. These diagnostic runs used extra logging;
they are not throughput baselines. Parallel verification retains the original
Fast timeouts. The two-minute follow-up at implementation revision
`ecd431aa092301161c41406e162e70554796dd0f` confirmed operations from revision 28
through 377 and passed recovery at revision 421. This crosses the previously
observed revision-179 failure point, but does not qualify prolonged overload,
all epoch-transition failure scenarios, or WAN operation.

## Run locally

Build both executables from the same checkout and record any dirty changes:

```sh
cargo +1.98.0 build --frozen --release -p verad
cargo +1.98.0 build --frozen --release -p vera-e2e --example operation_baseline
python3 tools/performance/record.py \
  --node target/release/verad \
  --runner target/release/examples/operation_baseline \
  --history rocksdb --output /tmp/vera-performance-run \
  3000 50 128 1 normal 100 20 0 128 32
python3 -m venv /tmp/vera-performance-python
/tmp/vera-performance-python/bin/pip install -r tools/performance/requirements.txt
/tmp/vera-performance-python/bin/python tools/performance/report.py /tmp/vera-performance-run
```

The output directory must not already exist. For Regolith, build `verad` with
`--features regolith-history` and label that exact executable `--history regolith`.
The recorder hashes binaries but cannot infer their source revision or features;
its source field describes the checkout. The workflow binds that checkout to its
own build steps. Do not label an older prebuilt executable with a new checkout.

Each local run has a 15-minute process deadline; timeout terminates its process
group and remains a failed measurement. Compilation, report rendering, and
post-run correctness checks do not contribute to the driver's measured workload
interval. See [workload semantics and arguments](native-workload.md).

For diagnosis, pass `--rust-log warn,vera_storage=info,vera_diagnostics=debug`.
The `native execution stages` event separates block-wide signature authentication
from ordered native dispatch. The `receipt proof stages` event measures finality
evidence lookup/assembly (`finality_us`) and receipt construction/size checking
(`assembly_us`), before transport serialization. These are server request costs,
not consensus finality latency. Nodes share one Commonware verification pool across
executor clones, capped at four workers (or the available CPU count if smaller).
Every signature is still verified independently; nonce checks, module mutations,
receipts and error selection retain their original transaction order.
The recorder stores the selected filter in the manifest. Additional logging can
affect throughput and latency; treat diagnostic runs separately from baselines.

For permission reads, use the separate filter
`warn,vera_storage=info,vera_permission_diagnostics=debug`. It samples one in 128
admitted current-permission requests per process, reporting completed storage-lock,
proof-construction and finality-evidence stages, total elapsed time, selection
attempts and the last phase. The proof stage includes snapshot capture and server
verification. A timed-out stage contributes to total elapsed time but not its
completed-stage counter; requests cancelled by their caller may emit no sample.
Admission rejections are excluded from these samples. This target does not enable
the per-receipt diagnostics, and its timings are diagnostic evidence only.

`vera_publication_diagnostics=debug` separately records per-revision database apply
and module-snapshot publication, followed by certificate lookup, durable history
writing (including blocking-pool scheduling), and query-index publication. These
durations include lock waits and executor scheduling; database apply is not a
disk-only measurement. Use this target without `vera_diagnostics` to avoid the
per-receipt trace. It observes existing ordering and never publishes an index
before its history write succeeds. Both publication and general diagnostics also
record marshal tip/block delivery to the stateful mailbox, its feedback, and sink
entry/completion. A tip is not a durable block delivery or an application
acknowledgement; missing delivery does not identify a network failure.

Durability completion records the original barrier result, time from its first
poll, and time since synchronization began. These are observed waits, including
scheduling, not isolated disk latency. The height is unknown until a database
apply has been observed with diagnostics enabled. Diagnostics do not wait for
or acknowledge a barrier earlier than the normal finalization path.

### Offline measured-run replay

Generate a standalone interactive HTML file from an existing recorded run; this
requires only Python, with no browser packages or external web dependencies:

```sh
python3 tools/performance/replay.py /tmp/vera-performance-run \
  --output /tmp/vera-workload-replay.html
```

PR and main-branch benchmark artifacts include `replay.html` alongside each recorded
run. Rendering runs after measurements, including for failed runs, so retained
artifacts show their actual outcomes without adding work to the measured interval.

The output must be a new file. The generator reuses `report.py` correctness gates
and exits unsuccessfully after writing a clearly labelled failed or incomplete
report when those gates do not pass. The scrubber shows measured RSS and receipt
observations, with receipt times derived from the known arrival schedule plus
recorded latency. RSS has a separate elapsed-clock origin; its exact offset is
unavailable. Missing samples remain gaps; untimed outcomes and post-run proof and
restart checks are not assigned invented timestamps. At most 1,000 actual receipt
points are drawn; totals include every observation. Exact recorded source hashes,
binary hashes and host details remain attached. Build details absent from the
manifest stay unknown. This is a replay, not live telemetry, a capacity result or
a measurement of consensus finality. Existing recordings retain their historical
source identity when rendered by a newer checkout.

## Interpret the charts

Receipt latency runs from scheduled arrival through verified confirmation. It
includes scheduling delay, admission, execution, consensus, polling, and proof
verification. It is **not** consensus finality latency. Workflow latency includes
any configured permission read after confirmation. Throughput counts completed
workflows over the driver's measured arrivals-and-drain interval.

The Rust client limits each instance to 64 concurrent HTTP calls, including
response decoding. `with_max_concurrent_requests` changes this bound. Calls
over the limit return `ClientCapacityExhausted` before transmission by default.
`with_request_queue` optionally enables FIFO waiting with a bounded waiter count
and timeout; cancellation releases capacity. It does not increase HTTP concurrency.
The workload enables this queue with its outstanding-workflow limit as the waiter
budget and a one-second admission timeout. Its configuration records these values;
older runs used fail-fast admission. Queue time remains included in measured RPC
and confirmation latency, within the unchanged workflow deadline. Client and
server throttle counters distinguish local admission failures from remote limits.
The outstanding-workflow limit is separate from the HTTP concurrency bound.

The server admits at most eight current-permission requests, including requests
waiting for storage publication. They acquire a separate shared proof permit only
after obtaining the partition read guards and selecting a sufficiently recent
revision. Publication retries release that proof permit. A generated proof keeps
its permit through finality lookup and size validation; at most eight shared
proof operations can hold evidence at once. This lets receipt requests use shared
proof capacity while permission requests wait for storage, without an unbounded
waiting queue or a higher evidence-allocation budget.

Current permission requests acquire all four native partition readers without
waiting while holding a partial set. If any writer is active or queued, the
request releases its acquired readers, waits only for the busy partition, and
retries the complete set. Storage availability does not require a publication
notification or a polling timer.
The existing two-second deadline, eight-request permission limit, shared proof
budget and authenticated root checks still apply.

RSS is sampled once per second. Missing samples are counted, not filled with
zero; short peaks may be missed. A short fixed-state run cannot establish a
memory plateau, and growing state has a different working set. Plots contain
measured data only and show failed-run status explicitly.

Hosted runner hardware and contention vary. Compare matching workload settings,
backends, toolchains, and host classes; repeat runs before drawing conclusions.
Load averages are context, not proof of exclusive CPU or storage access. There
is no automatic percentage-regression gate on these shared hosts.

## Live visualization

A live view and a benchmark report answer different questions. The native RPC
already exposes member status and finalized-header subscriptions. Those can show
actual revision progress and connectivity. A client must verify finality evidence
against operator-provisioned trust before presenting authenticated results.

Browser-observed latency also needs an explicit clock-skew policy. Receipt
latency, revision interval, and client-observed finalization must remain separate
series. Unknown or disconnected members must show stale/missing data rather than
continued simulated activity. Gateway and Orbis workflow latency are additional
measurements; they cannot be inferred from a consensus header stream.

There is currently no deployed live Vera dashboard or qualified WAN capacity
result. The reports here provide reproducible evidence for that work without
claiming current release throughput from historical runs.


### Pipelined consensus measurements

`operation_baseline` accepts an optional eleventh argument, `1`, to enable the
native-only Simplex configuration from `docs/consensus-membership.md`. Omission
or `0` retains rotating leaders. The output records the exact `simplex` parameters;
comparisons across different configurations must not report an isolated code
speedup. Epoch length, history backend, arrival rate and verification gates remain
independently configurable. Pipelining does not establish a transaction capacity
or latency guarantee.

PR comparisons and the main-branch performance jobs explicitly enable pipelining,
with 192 revisions per epoch and 256 retained consensus revisions. This gives the
four participants room to complete DKG with stable leader terms and retains a
complete epoch for recovery. Both sides of a PR comparison use the same settings;
their emitted configuration must match before a performance delta is reported.
`run_pr.py --consensus classic` retains the rotating-leader comparison with
20-revision epochs and 32 retained revisions. Changing these settings requires a
new baseline; historical classic measurements are not directly comparable.

## Storage tracing

For diagnostic runs, set `VERA_TRACE_SPANS=1` and select Commonware storage spans
with `RUST_LOG=warn,commonware_glue::stateful::db=info`.
Add `commonware_utils::sync=info` only when lock attribution is needed; its
higher event volume can substantially perturb the workload.
Span-close events report busy and idle time for database apply/finalize and
labelled lock acquisition. The database index follows `OrderedDatabases` order:
accounts, storage, code, ACP, bulletin, identity, native sequences, commitment.
Idle time includes awaited I/O and scheduling; it is not a direct disk-latency
measurement. Tracing is off by default and recorded in workload provenance.
Do not treat traced runs as throughput qualification.


### Manual Linux storage attribution

The existing Performance workflow accepts a manual `storage_attribution` option.
It selects RocksDB only and builds the node and `mixed_policy_workload` in release
mode before running `32 4 16 300` twice: first as an uninstrumented comparator,
then with storage
spans and `strace` restricted to `fsync` and `fdatasync` in the workload executable
and its child processes. Recorder provenance commands run outside strace.
All permission, ownership,
policy-edit and hard-restart assertions remain required in both runs. Default
scheduled and manual performance baselines are unchanged.

```sh
gh workflow run performance.yml --repo sourcenetwork/vera.rs --ref main \
  -f storage_attribution=true
```

The artifact retains each run's executable/source manifest and workload JSONL,
plus `storage-attribution/summary.json` with numeric span and syscall summaries.
Raw node stdout, syscall traces, configuration and fixture keys remain under
`RUNNER_TEMP` and are not uploaded. The offline parser accepts only paths
inside its supplied private run root and emits fixed labels, numbers and input hashes.
It joins interleaved unfinished/resumed syscalls by thread ID; incomplete calls
and failed calls remain explicit rather than becoming successful observations.

Partition summaries use only complete execution-finalization windows, from
applied-state publication to synchronization-start completion at the same height.
This excludes bootstrap's reused partition indices. Concurrent readers can still
share those windows. Lock spans measure acquisition, not guard holding; finalize
and start-sync spans overlap. Syscalls cover the whole run, including startup and
restart, and do not identify a consensus revision or a QMDB partition. Neither
span idle time nor syscall elapsed time isolates physical disk latency. Tracing
and ptrace perturb scheduling; neither the uninstrumented comparator nor the
traced run establishes capacity, and their difference does not qualify a
production optimization.
