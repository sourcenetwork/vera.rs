# Native release qualification

This record covers native ACP v1, bulletin, identity and operator-managed
membership on pipelined Simplex, with QMDB authenticated state and synchronous
Regolith history. Trust is a separate Go gateway; Orbis provides the separate
application threshold protocols. The first-release scope below separates package
publication from the later [four-host WAN qualification](wan-gates.md).

## First release: crates and daemon artifacts

The initial release targets native ACP v1, bulletin, identity, operator-managed
membership, verified client APIs and the Regolith-backed daemon. ACP v2 remains
future work. The four-host WAN test and the pending Commonware DKG boundary retry
are follow-ups, not first-release acceptance gates. DKG itself remains part of
consensus bootstrap and resharing; deferring the retry does not remove those
protocols or weaken boundary verification.

The unmerged Orbis service stack is outside this release's integration claim.
Its signing, encryption and membership-churn qualification remains separate.
Vera's bulletin, ring records and shared report formats remain supported code;
packaging them must not require merging the entire Orbis service stack. Consumer
qualification records must identify actual source revisions rather than assume
that a passing branch has reached a repository's default branch.

No crate or tagged release has been published from this repository yet. The
remaining first-release work is:

| Gate | Required result |
| --- | --- |
| Official Commonware source | Remove the fork from the release dependency set without waiting for the pending-epoch retry. Preserve the upstream archive and synchronization fixes. Qualify the selected unpatched source and document its boundary-recovery limitation. Current `main` still contains the retry patch until that source change is made. |
| Publishable crates | Version every packaged dependency, complete package metadata and verify the registry dependency graph without workspace patches. The client/verifier publication closure currently contains nine Vera crates. Their dependency closure includes the Git-only, unpublished `orbis-reporting` crate; resolve that shared-format packaging dependency independently of the service stack. |
| Release automation | Validate versions and packages and produce tagged daemon assets with checksums and provenance from the same commit. Existing workflows build and compare artifacts but do not create releases. Keep crate uploads manual; CI needs no crates.io publishing credentials. |
| Candidate validation | Run focused native authorization, membership, receipt and recovery checks affected by the dependency change. Verify the packaged client/verifier from a clean registry consumer, independent trust configuration, and the chosen daemon artifact. Reuse earlier source-bound evidence for unchanged code. |
| Publication handoff | Record exact source, versions, dependencies, target and limitations. Provide package checksums and dependency-ordered commands for the maintainer to publish manually, followed by registry installation and download checks. Crate uploads belong to the maintainer, not the automated workflow. |

The existing `0.1.0` workspace version is the initial package-version candidate.
The approved packaging scope is `vera-client`, `vera-verifier` and their seven
required Vera libraries, plus daemon binaries. An installable `verad` crate, test
harnesses and development tools are outside this first publication.
Crates.io cannot reproduce Git-only or path-only dependencies from this checkout;
adding version strings alone does not establish that the registry packages have
the APIs or behavior qualified here. See Cargo's
[published-dependency rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations).

The pending retry is tracked in [#230](https://github.com/sourcenetwork/vera.rs/issues/230).
It addresses epoch-boundary verification while finalized DKG replay is still
catching up. The unpatched release must disclose that recovery limitation and
check bounded cancellation; it must not claim the patched recovery result.
WAN work remains tracked in [#234](https://github.com/sourcenetwork/vera.rs/issues/234),
with its existing thresholds unchanged. Neither follow-up is marked completed.

## Measured operating envelope

The [resource envelope](storage-resource-envelope.md) defines repeatable local
profiles and their regression thresholds. Four validators and the client share
one four-logical-CPU Ubuntu host. Both profiles offer 50 writes/s and verify one
permission read per write, all four replicas and restart recovery.

| Profile | Completed work | Receipt p95 / p99 | Permission read p95 | Peak RSS/member |
| --- | --- | ---: | ---: | ---: |
| Fixed live data | 360,000 updates over 128 objects, two hours | 294 / 331 ms | 12.95 ms | 416–462 MiB |
| Growing live data | 90,000 registrations, thirty minutes | 276 / 293 ms | 7.70 ms | 803–816 MiB |

These source-specific results establish a sustainable measured load point, not
maximum throughput. The [provenance record](measurement-provenance-20261014.md)
retains the exact revisions, hosts, allocator settings and artifact checksums.
The thresholds remain completion at least 49/s, receipt p95 at most 400 ms and
p99 at most 600 ms, permission-read p95 at most 25 ms, restart to a certified
probe at most 30 s, sampled RSS at most 1 GiB and retained files at most 512 MiB
per member for these profiles. Every offered operation must complete and verify.

## Resource-growth review

Growing registrations add module records, authenticated index keys and worker
identities; finalized history consumes disk. Fixed-object updates still warm
storage caches and accumulate history. Neither trend alone establishes a leak.
The fixed run added 0.26–3.66 MiB RSS/member during its last ten minutes, while
longer windows still grew. There is no indefinite plateau or arbitrary-dataset
memory guarantee.

| Resource | Retention rule |
| --- | --- |
| Pending submissions | At most 4,096 requests and 64 MiB of request payload |
| Execution index | At most 1,024 revisions, with a 64 MiB payload target |
| Finalization evidence | At most 1,024 records and a 64 MiB payload budget |
| Epoch verifier material | At most 128 records and an 8 MiB payload budget |
| Proposal receipts | Owned by their sealed execution; clones share the receipts and discarded executions release them |
| Regolith cache/memtables | Configured engine targets, with pinned-reader and oversized-batch exceptions |
| Live module state and history | Scale with retained application data; provision for the intended dataset |

The proposal-receipt ownership rule removes the application-wide receipt map.
That map retained losing proposals by height even after their execution batches
were discarded. Receipts now travel with the sealed state that produced them;
finalization checks their commitment against the selected block. Storage roots,
receipt encodings and synchronous publication are unchanged. Regression coverage
exercises repeated discarded native proposals before finality advances, shared
sealed-state ownership, competing branches and commitment mismatches.

Cache payload targets exclude map overhead and references held by readers.
Protocol queues depend on committee configuration; active speculative work and
staged signing schemes follow consensus progress. The
[operator guide](operating.md#resident-memory-and-measured-workloads) records these
exceptions. Sampled RSS, tracked heap, allocator reservation and storage gauges
overlap and must not be summed into a process-memory ceiling. Monitor memory,
filesystem capacity, finality progress and readiness; preserve headroom for
startup, recovery and backup.

## Correctness and recovery

[Linux CI](../.github/workflows/ci.yml) exercises receipt ownership and binding,
policy/worker authorization, real member replacement and restart, commit-crash,
disk-full, snapshot catch-up, interrupted snapshot import and sync-failure
reporting. [History damage checks](../.github/workflows/history-corruption.yml)
cover corrupted records and compaction write/sync failures.
[Admission pressure](../.github/workflows/native-pressure.yml) verifies bounded
queues, overload rejection and quorum recovery with one and four workers.

Historical qualifications retain their exact sources in
[storage coverage](storage-resource-envelope.md#storage-and-recovery-coverage).
The original policy-read/readiness failures with missing diagnostics remain
unexplained; subsequent passing checks do not establish their cause. No current
acknowledged-operation loss was reproduced in those recorded follow-ups.

## Consumer compatibility

The [consumer qualification record](native-qualification-20261014.md#native-consumer-checks)
retains the exact compatible versions. Its frozen Vera runtime is
`e48e1d8f9f701da94554a176d913131e2e6a5277`:

| Consumer fixture | Revision | SDK revision |
| --- | --- | --- |
| Defra provider/document | `87a10b380446303e20587a6c48e05ec31f9695f0` | `1dab0c4562da551b1a7f00fcea643b914769891c` |
| Trust gateway/rings | `3003e203e5dc5c8e79d09fb012c616b278bc896c` | `9d5c2b9ea7cb971a7871028b7b0b22d488a7ecbf` |
| Orbis native lifecycle | `a0557e7018e98e2d680eb48c8a8844764ec84b93` | `9d5c2b9ea7cb971a7871028b7b0b22d488a7ecbf` |

These cover document access/replication/revocation, executable and container Go
contracts, both threshold curves, persistent restart and member replacement.
Orbis runtime and image bindings are recorded separately there. Some consumer
changes still await merging; these are tested revisions, not a claim that every
repository's main branch was tested together. Proposal receipt ownership and the
TLS patch do not change the native request encoding, policy/proof schema or
independent trust provisioning.

## Security and release inputs

The build qualified in PR #224 pins Rust 1.98.0 and locked dependencies. Commonware is 2026.9.0 at
`4f5db3d0dc30900015fb13347e9ec20ae085b79a`; Regolith is pinned to
`f6958cf0cea97f658dbdbc3572063a8122645101`. Their recovery and cache fixes retain
the qualification recorded in the storage and recovery reports. Those measurements
and artifact hashes remain tied to their recorded source versions. Current
Commonware integration and its source pin are described in
[snapshot recovery](snapshot-recovery.md#commonware-integration).

The official RustSec database was reviewed through
`caee11f41fab07d676c0a4655a2a5dd1f94da97c`. Rustls is updated to **0.23.46**,
which fixes RUSTSEC-2026-0346, 0347, 0348 and 0349. The newly listed `kuva` and
`ruzstd` packages are absent from the lockfile. Existing maintenance notices for
`derivative`, `paste` and `unsafe-libyaml` remain disclosed; parser limits do not
establish the memory safety of an unmaintained parser.

Key provisioning/recovery requires independently supplied genesis trust,
identity-bound shares and owner-only private files. Startup rejects unsafe file
types and permissions. Preserve the latest durable signing journals when
restoring; if signing state is lost, replace the member with a fresh identity.
Never run cloned validator identities. See
[key and backup instructions](operating.md#security-notes-for-operators).

The [release workflow](../.github/workflows/reproducible-linux-release.yml)
records immutable source, toolchain, features and checksums and compares two
independent clean builds. The normal Linux CI also packages the daemon it
exercised. Artifact provenance, key handling and process-crash tests are distinct
from a physical-device power-loss guarantee.

## Post-release WAN qualification

The WAN recipe requires four isolated validator hosts, measured peer RTTs,
independently provisioned trust, at least fifteen minutes at 20 offered writes/s,
verified receipts/permissions from every host and the documented latency gates.
Local CI and network-delay fixtures do not qualify that deployment. No such
hosts or WAN result are currently available.
