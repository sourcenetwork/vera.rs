# Native admission saturation

See the [October 14 one- and four-worker measurements](native-qualification-20261014.md#admission-overload-and-recovery)
for measured rejection latency, every worker's observed backlog-tail time, source
and artifact bindings, and the unresolved earlier recovery deadline.

The multiworker case fills the same 4,096-entry queue with four independent
signers in round-robin order, 1,024 submissions each. Recovery waits for every
worker's tail, checks each sequence and verifies namespace ownership on all four
replicas. Its numeric artifact reports each worker's observed backlog-tail time
and their spread. These are observations after quorum restoration, including
polling; they are not ordinary write-confirmation latency or a fairness guarantee
for unequal producers. The retried 4,097th operation remains attributed to worker 0.

Select `multiworker` in the existing admission-pressure workflow to run that case
alone. The `all` selection measures both cases using the same prebuilt daemon and
fixture binary, with separate provenance-checked artifacts.

The admission fixture starts four pipelined validators, removes quorum and admits
4,096 signed namespace registrations. It then issues 1,200 concurrent rejection
checks over approximately thirty seconds. Rejected requests must return the
retryable capacity error; the worker's finalized sequence remains unchanged.
After restoring quorum, it retries the rejected request and verifies all 4,097
namespaces, ownership, sequences and certified retry outcomes on every replica.

The [hosted pressure workflow](../.github/workflows/native-pressure.yml) uses a
normal release daemon and the exact Cargo-reported release test executable:

```sh
gh workflow run native-pressure.yml --repo sourcenetwork/vera.rs -f case=admission
```

Its `native-admission-resources` artifact contains source and binary hashes,
hardware, rejection latency percentiles, recovery/reconciliation time, sampled
RSS and CPU, kernel I/O counters and retained file sizes. One-second sampling
tracks the two surviving processes through saturation and recovery. Restarted
processes have different identities and are outside that resource series. A
recovery phase shorter than the sampling interval may have no CPU/I/O interval;
that absence remains explicit.

Only validated numeric records are exported. Logs, keys, policy contents and
private fixture files remain on the runner. Per-revision tracing is disabled.
Incomplete outcomes, sparse saturation sampling, process replacement and invalid
counters fail qualification. This controlled saturation case does not establish
maximum throughput, a steady-state memory bound, physical write amplification or
WAN behavior. The [mixed workloads](mixed-policy-workload.md) measure a separate
policy workload with concurrent workers.

## October 14 qualification

[Run 38476315894](https://github.com/sourcenetwork/vera.rs/actions/runs/38476315894)
passed admission saturation, delayed-validator and stalled-validator cases on one
four-core AMD EPYC 7763 host with four pipelined validators. The test held 4,096
requests containing 1,146,496 wire bytes without quorum. All 1,200 capacity
rejections completed during 29.91 seconds of saturation; no rejected request
consumed its finalized worker sequence.

| Measurement | Result |
| --- | ---: |
| Capacity rejection p50 / p95 / p99 | 3.31 / 5.82 / 5.94 ms |
| Saturated survivor RSS peaks | 117.50 / 117.51 MiB |
| Saturation RSS change | +0.23 / +0.17 MiB |
| Recovery plus four-replica reconciliation | 79.48 s |
| Confirmed namespaces, including the retried request | 4,097 |
| Survivor RSS peaks across the complete run | 179.50 / 178.61 MiB |
| Retained allocated files after reconciliation | 15.02–16.07 MiB per validator |

The result used source `9d6ab2874db8d6a8f429dbe381a5f07f0b0409e1` through an
identical-tree test merge, `9e11fe2e4df67c1e7f86cd95a84f035688bc1bfa`.
Its normal daemon SHA-256 is
`a5349a3a3ad03f664dd5a9aae7b2556e7edf5203e43cddc6aef9d52824fd71f2`, matching
the separately reproduced storage build. The official artifact ZIP checksums,
tested tree, latency percentiles and all RSS/CPU/I/O summaries were independently
checked or regenerated. Both stable survivors have 121 complete samples;
the saturated interval has thirty samples each.

CPU accounting uses cumulative `ps` seconds, so short low-usage intervals are
quantized. Restored processes are outside the memory series. Recovery includes
processing admitted work, restarting the fourth replica and checking certified
state; it is not ordinary write-confirmation latency. This one bounded run does
not establish fairness between distinct workers, a long-run memory ceiling,
large-payload saturation, maximum throughput or WAN behavior.

## Pending-work rechecks

After finalization, Vera resets the admission validator to committed worker
sequences and rechecks retained requests in their original admission order.
Their signatures were authenticated at admission. Rechecks still validate the
deployment, target and public key before reserving the next worker sequence.
The compressed-key path uses blst validation, including rejection of infinity
and non-subgroup points, and derives the DID from the canonical key encoding.

Component fixture version 6 measures the former Arkworks decode-and-identify
path and the blst path against the same compressed key, with the same warmup and
sample windows. These are local key-validation and identity costs, not full
recheck, backlog-recovery or consensus latency. Full overload results retain
their recorded source and executable hashes; a component improvement alone does
not explain the earlier recovery deadline.
