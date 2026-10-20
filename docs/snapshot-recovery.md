# Snapshot recovery

An admitted member can request initial snapshot catch-up by adding this section
to its node configuration. Genesis, the member's identity and its bootstrap peer
configuration must already be provisioned.

```toml
[snapshot]
record_bytes = 67108864
logs = 100000
peer_timeout_ms = 10000
```

An empty `[snapshot]` section selects these defaults. Without the section, a
node replays retained history. Interrupted snapshot synchronization always
resumes from durable metadata, even if the section is removed. Once snapshot
synchronization completes, subsequent starts recover from its persisted floor
and later consensus progress; they do not request another snapshot.

## Startup sequence

1. The DKG probe authenticates a synchronization floor against the provisioned
   consensus identity. Commonware synchronizes the seven storage partitions and
   may advance the selected revision as finalizations arrive.
2. After storage verifies the final selected roots, its handoff imports history
   through that exact revision. Every record must match the selected ancestry,
   receipt commitment and independently verified finality evidence. A record and
   its resume cursor enter one synced write batch.
3. History recovery rebuilds query indexes at the selected revision. The handoff
   then permits native query-state hydration and returns storage to the processor.
   Commonware makes any pending execution suffix durable and records completion
   before exposing the databases. Admission and RPC start after this handoff.

Peer response translation preserves Commonware's validation feedback. The sync
engine's rejection of an invalid proof reaches the original resolver, which can
block that peer and supply another candidate. Accepting a proof closes the
request; dropping feedback cancels it without accusing the peer. Translation
uses only the public `Feedback::new`, `accept` and `reject` API, with a one-entry
channel. It exits when the consumer closes, including when no further candidate
arrives. This feedback does not replace root verification or
acknowledge durable storage.

Resharing starts alongside database recovery. When execution state cannot yet
provide a committee selection, the membership provider uses the corresponding
finalized boundary in the consensus archive, checking its height, selected epoch
and nonempty roster. This lets epoch progress advance the transfer target while
admission and RPC remain unavailable until recovery finishes.
The outer application skips proposals and keeps verification pending until
execution state is ready, so speculative DKG requests cannot ask for future
committee selections before the recovered policy state is available.

An interrupted history import retains its selection, trust and cursor. If storage
resumes at a later verified revision, history starts a new descending pass from
that revision to the same previously committed prefix. This can refetch already
staged records. Unpublished imports remain unavailable to history clients.

A floor that ages out of peer retention strands transfer: ancestry backfill
cannot reach the gossiped tip, so no newer finalized targets arrive. While
databases are pending, startup watches marshal's processed height and, after
`floor_stall_seconds` without progress (default 15, zero disables), re-floors
marshal from the newest stored gossiped finalization. Dispatches resume from
that retained anchor and the transfer retargets; the overall
`initialization_timeout_ms` deadline still bounds the attempt. Sync completes
at its reached target and settles on the newest one at the first update lull,
so stale targets converge without network quiescence.

`vera_nodeStatus` includes `snapshotRevision` after snapshot recovery. On restart,
it reports the persisted snapshot recovery floor, which can also cover execution
completed during the original handoff. It is operational status; clients still
verify revision certificates and permission evidence independently.

## Commonware integration

All Commonware packages select official upstream
[`c18a6b9c47b8e55d0a6f2fdef3fa10a75d6641da`](https://github.com/commonwarexyz/monorepo/commit/c18a6b9c47b8e55d0a6f2fdef3fa10a75d6641da)
in `Cargo.toml` and `Cargo.lock`. No fork or local DKG retry patch is selected.
The package version alone does not identify this source.

The [pending-epoch retry](https://github.com/commonwarexyz/monorepo/pull/5263)
is deferred beyond the first release. During boundary verification, transient
pending epoch information can remain unresolved until cancellation, even when
finalized DKG replay subsequently catches up. Missing or mismatched information
must never authorize a boundary. Snapshot startup remains bounded by
`initialization_timeout_ms`; an operator can retry recovery from a fresh certified
target. This is a release limitation, not equivalence to the earlier patched
recovery behavior. See the [release scope](release-qualification.md#first-release-crates-and-daemon-artifacts).

Upstream supplies the [archive rewrite](https://github.com/commonwarexyz/monorepo/pull/5268)
and [sync progress and nonblocking channels](https://github.com/commonwarexyz/monorepo/pull/5282).
Target updates and reached reports use bounded ring channels; a lagging receiver
can skip intermediate values. Tuple coordination retains each database's latest
report independently. Each reached target is reported before adopting a newer
queued target. Vera's module-root commitment follows the same channel contract.

Archive sections own their translated keys, and pruning removes their lookup
handles in memory without reading discarded records or scanning the full index.
`keys_tracked` reports indexed records; historical `index_*` metrics belong to the
previous implementation. Vera's retention audit accepts each explicitly identified
metric schema and rejects a schema change within one member's recording. Its
single-record-per-height archives compare lookup records with retained heights.
`items_per_section` is fixed for the lifetime of archive data; changing it can
make initialization fail with `RecordCorrupted`.

There is no custom pruning response or near-tip target buffer. Useful in-flight
requests survive target updates and are verified against the root selected by
their request. When the lower bound advances, requests at or below it are retired
so the new boundary can be fetched. These retained DKG changes introduce no new
wire or storage encoding.

Native deployments use scheduled leader election and stage incoming-term
proposals without voting before their parent certifies. Recovery readiness gates
both prepared and ordinary proposals. The compatibility execution mode keeps
certificate-dependent election and declines speculative preparation.

Recovery supplies the authenticated target when each database opens. Every
partition must recover that target before the application verifies the combined
module commitment and hydrates query state. Startup does not first expose the
latest journal state and then rewind it. The persisted sync floor is also supplied
to the DKG probe on restart.

The upstream CPU baseline requires AVX2, BMI2 and ADX on x86-64, or NEON
on AArch64. Deployment hosts must meet this baseline.

Peer transport uses Commonware CUPS V1 with SAKE V1 authentication and
ChaCha20-Poly1305. Validator and bootstrap binaries must use the same pinned
Commonware build; mixed-version operation with the previous transport has not
been qualified. Coordinate the validator upgrade and retain backups before opening
existing state with the new storage implementation.

## Transfer bounds

`record_bytes` bounds each assembled execution record, and `logs` bounds its
decoded log count. `peer_timeout_ms` applies to one record or finality response
from one peer. After failure, the importer tries another eligible peer and keeps
using a successful peer. If all candidates fail, startup fails with its durable
progress retained. Synchronous verification and storage work can outlast the
asynchronous deadline.

Finality proofs retain their shared limits: 64 descendants, 35 MiB of decoded
artifacts, and 70 MiB plus 64 KiB for the JSON response. Peer responses contain at
most 64 KiB of data per chunk. These are transfer and decoding bounds; extra
buffers, caches and storage resources contribute to process memory. Aggregate
serving capacity and sustained catch-up throughput still require qualification.

## Unavailable data and retries

When a peer cannot serve a request, including because its history was pruned,
Commonware's resolver sends its existing generic error reply. Missing data is
retried after the configured delay and affects peer selection, without treating
the peer as malicious. A negative reply neither changes the authenticated target
nor establishes that every other peer lacks it.

Vera's peer regression first serves from a database that has pruned the selected
target, then makes a retained copy available without publishing a target update.
Synchronization must retry and reconstruct the same authenticated state. Further
cases cover cancellation, restart, invalid responses and advancing targets.

If every source has deleted the required history, retrying cannot recreate it.
The coordinator must select a newer certified target that peers retain, or obtain
the required data from another retained source. The startup initialization
deadline bounds the overall attempt.

## Queued targets and completion

An engine reports reaching its selected target before applying queued updates.
The coordinator can therefore observe a common completed anchor even when newer
targets arrive continuously. A finish request delivered during a backpressured
progress report takes precedence over advancing the engine again. Otherwise,
queued updates remain eligible; no separate target buffer delays them.

Query modules remain unpublished until all seven partitions converge, their roots
validate and history handoff completes.

## Private DKG material

Secret-store updates write a complete temporary file, sync its contents, replace
the destination atomically and sync the containing directory. Cloned store handles
serialize updates and publish in-memory changes after persistence succeeds. On
Unix, replacement files have mode `0600`. Debug output excludes private material.
Loading validates encoded shares, seeds and dealings before making them available.
The DKG actor treats persistence errors as fatal. A directory-sync failure can
leave the complete replacement visible on disk without establishing durability;
the failed update is not published to in-memory readers. Restart reloads the
stored file rather than assuming the failed update left it unchanged.
Malformed material or dealing keys stop startup without rewriting the file; they
are not treated as missing shares. Only a missing file starts an empty store.
The JSON file remains plaintext under the operating system's access controls.

An existing malformed or empty secret file fails startup and is preserved.
Recovery requires valid retained private material; the node does not silently
replace lost shares. Process-crash checks do not establish power-loss, failed-fsync
or disk-full guarantees for the deployment filesystem.

Genesis initialization preserves existing recovery markers even when their
symlink targets are missing or inaccessible. Filesystem errors stop initialization,
and an existing intent must match the configuration before journals are opened.

## Journal retention

Omitting `[pruning]` retains the consensus archives and state journals. To enable
coordinated pruning, configure all three limits in `config.toml`, for example:

```toml
[pruning]
maintenance_interval = 64
retained_consensus_revisions = 4096
retained_state_revisions = 128
```

These are revision counts, not durations or byte limits. Consensus retention must
be at least state retention; the maintenance interval must be positive. The total
consensus window (configured retention plus two safety revisions) must also cover
at least one full DKG epoch. Startup rejects a smaller window because it can remove
the boundary needed to recover the active epoch. Commonware
adds its acknowledgement safety window to both counts and schedules maintenance
at a randomized phase. The example is not a qualified deployment sizing target.

Execution and certificate history remain available in the separate history store.
Pruning waits for durable state and completed application callbacks. A node that
falls behind the consensus archive window may need authenticated snapshot catch-up;
size the window for expected downtime and observed revision rate. Increasing a
limit later does not restore deleted journals. This does not bound total disk or
resident memory use.
