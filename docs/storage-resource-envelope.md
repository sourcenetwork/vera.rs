# Qualified workload and storage envelope

Vera uses Commonware QMDB for authenticated state and synchronous Regolith batches
for finalized history. Two normal-release workloads qualify the finite storage
envelope below. Both use four validators and a client on one four-logical-CPU
Ubuntu runner, pipelined Simplex, 100 ms proposal batching, 192-revision epochs,
256 retained consensus revisions and one verified permission read per write.

| Profile | Timed workload | Peak sampled RSS/member | Allocated files/member after workload |
| --- | --- | ---: | ---: |
| `fixed-360k` | 360,000 updates to 128 objects and signers; 50/s for two hours | 415.91–461.62 MiB | 322.98–324.33 MiB |
| `growing-90k` | 90,000 distinct objects and signers; 50/s for thirty minutes | 802.67–816.31 MiB | 323.89–324.74 MiB |

The fixed profile passed at `f3bbd7d2ed4559c43dab9e171d1bf70b0e639c64`
in [run 38431246384](https://github.com/sourcenetwork/vera.rs/actions/runs/38431246384).
The growing profile passed at `2c2bf3600f8c81e51c258bb16b63587bed8b5f59`
in [run 38503258544](https://github.com/sourcenetwork/vera.rs/actions/runs/38503258544).
All 450,000 operations completed across these runs, all four replicas agreed,
and hard-restart inspection found no receipt or state mismatches.
Their sources, build recipes, machines and raw artifact checksums are recorded in
[measurement provenance](measurement-provenance-20261014.md).

## Repeatable resource gate

[`resource_envelope.py`](../tools/performance/resource_envelope.py) checks the
already validated workload report and raw retained-file records. Sustained growing
and extended fixed-state selections in the [Performance workflow](../.github/workflows/performance.yml)
run this gate and retain `resource-envelope.json`.

```sh
python3 tools/performance/resource_envelope.py /path/to/qualified-case --profile growing-90k
python3 tools/performance/resource_envelope.py /path/to/qualified-case --profile fixed-360k
```

Each profile must match its workload configuration, pass operation verification
and restart checks, and retain complete one-second RSS sampling for all four
original processes across the timed interval. Failed or incomplete reports,
short runs, missing members, failed file scans and exceeded budgets fail the gate.

The regression budgets are **1,024 MiB sampled RSS** and **512 MiB retained
allocated files per member**. These round budgets leave at least 20.28% unused
RSS budget and 36.57% unused file budget in the measured growing profile;
the fixed profile leaves at least 54.92% and 36.65%, respectively.
They were selected from the retained measurements to detect resource regressions.
They are not independently provisioned deployment capacity, cgroup limits or an
assertion of unseen peaks. RSS sampling excludes setup and restart; file scans
cover the validator's entire data directory immediately after the timed workload.

The same gate checks completion rate, latency and certified recovery:

| Gate | Budget | Fixed measured result | Growing measured result |
| --- | ---: | ---: | ---: |
| Completed workflows/s | At least 49 | 49.999 | 49.996 |
| Scheduled arrival to certified receipt p95 | At most 400 ms | 294.069 ms | 275.807 ms |
| Scheduled arrival to certified receipt p99 | At most 600 ms | 331.431 ms | 292.985 ms |
| Verified permission read p95 | At most 25 ms | 12.948 ms | 7.702 ms |
| Restart to observed certified probe | At most 30 s | 4.430 s | 9.842 s |

The completion rate may be up to 2% below the offered 50/s after including final
drain time; every operation must still complete and verify. Receipt and permission
distributions must each cover all operations. The slower measured receipt p95
leaves 26.48% of its latency budget unused; the slower permission p95 leaves
48.21%. These are margins against selected regression budgets, not measured spare
throughput above 50/s. Both historical artifacts pass the version 2 gate.

Receipt latency includes scheduling, RPC, finalization, polling and verification;
it is not an isolated consensus finality measurement. Restart timing includes
observing the certified probe after RPC readiness. The gate does not change
production request deadlines, batching, durability or admission limits.

## Storage and recovery coverage

The Regolith integration, synchronous publication and QMDB storage implementation
are unchanged between these measured sources and the qualified recovery source
`218d957671be4b5089b85c6890f25ada50614d42`; history-directory rejection text changed.
[CI run 38538707863](https://github.com/sourcenetwork/vera.rs/actions/runs/38538707863)
passed commit-crash, disk-full, lifecycle, authenticated snapshot catch-up,
interrupted snapshot import and reported synchronization-failure lanes.
[History damage run 38538708103](https://github.com/sourcenetwork/vera.rs/actions/runs/38538708103)
also passed. Earlier source-bound journal and backend loss-model tests retain
their original scope in [history storage](history-storage.md) and
[operating instructions](operating.md#recovery-behaviour).

Clock-aligned growing-state diagnostics measured Regolith encoded WAL, flush and
compaction output/input of 1.29358–1.29359, with no increase in its admitted-write
stall counter. The fixed run exercised compaction. Neither this accounting nor
the recovery fixtures proves physical-device write amplification or whole-node
power-loss behavior. See [storage accounting](measurement-provenance-20261014.md#clock-aligned-storage-accounting).

## Operator limits

Active module records and authenticated-state indexes grow with the live dataset.
Finalized history also consumes disk as operations accumulate. The growing run's
RSS trend does not establish a leak; the fixed run's last ten minutes added
0.26–3.66 MiB per member, which does not establish an indefinite plateau.

Do not extrapolate these budgets to larger payloads, complex policies, longer
history, more participants or independent hosts. Qualify the intended workload
before setting process limits, monitor resident memory and filesystem space,
and preserve capacity for startup, catch-up and backup. Exhaustion stops a
validator before it acknowledges failed persistence; it is not an operating mode.
The deployed caches, decoding limits, queue bounds and their exceptions are
listed in [operating a validator](operating.md#resident-memory-and-measured-workloads).
