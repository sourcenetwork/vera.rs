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

The pinned [runtime fork](https://github.com/iverc/commonware-upstream) follows
upstream `39d04ee1057ee03046973391d26e7101e4a3ef41`, which includes
[Commonware #5044](https://github.com/commonwarexyz/monorepo/pull/5044).
Upstream preserves verified operations across target updates and keeps pinned
nodes when the retention floor is unchanged. When the floor advances, it cancels
requests at the new boundary so a new boundary request is scheduled immediately.
Upstream MMR and MMB regressions cover delayed boundary responses, root eviction
and verified operations retained above a moved floor.

The fork's remaining changes cover bounded pruning retries, target convergence,
the source response codec, peer acceptance of pruning responses and reshare
boundary verification. `Pruned` is a fork wire extension, not an upstream
response. An exhausted invalid source fails with upstream's `InvalidResponse`
error; only explicit pruning hints receive bounded retries.

Boundary verification retries a pending epoch-info response every 100 ms while
the local DKG actor catches up. It still requires independently derived matching
epoch information before accepting a boundary. Follower responses remain pending,
and unavailable or mismatched artifacts are rejected. A temporarily early request
must not leave certification suspended after the DKG state becomes available.

Upstream [#5135](https://github.com/commonwarexyz/monorepo/pull/5135) moves batch
verification to the signer's public-key type. Vera's reshare configuration uses
that API instead of selecting a separate Ed25519 batch-verifier type. DKG signing
domains and encoded epoch and share material are unchanged.

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

## Pruning hints and retries

A peer's `Pruned` response describes only that source's claimed retention. It is
not proof that every peer lacks the target and cannot change the authenticated
state root or operation range. The sync engine pauses new fetches for 100 ms,
then retries even if the finalized target has not advanced. Further pruning
hints during that pause cannot extend its deadline. Already outstanding fetches
remain eligible; valid data clears the pause, and an advancing target can bypass
it. The startup initialization deadline still bounds the overall attempt.

The engine regression tests check retry timing, repeated hints and target
advancement. Vera's `pruned_hint` integration test confirms that synchronization
can recover after one false hint and reconstruct the correct stored value. This
source-level test does not establish liveness under every adversarial peer
selection or network partition.

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
