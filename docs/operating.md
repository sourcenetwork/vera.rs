# Operating a validator

Deployment, recovery, monitoring and limits for a `verad` validator. Protocol
behaviour is documented in the linked pages; this one covers the operational
surface.

See [architecture and flows](architecture.md) for service boundaries and the
relationship between consensus, operator-managed membership, and ACP.

## Deployment

A network needs one `genesis.json` shared by all nodes, one validator key and
epoch-0 BLS share per node, and a `peers.json` listing every participant's
dialable address. Two paths produce that material:

- `verad genesis --peers peers.json` runs the distributed epoch-0 DKG across
  the participants and is the production path.
- `verad --chain-id <id> testnet --nodes 4 --init-only ...` generates
  trusted-dealer material locally; see [wan-gates.md](wan-gates.md) for a
  worked multi-host example.

Run a node with:

```sh
verad --config nodeN/config.toml --data-dir nodeN \
     --chain-id <id> validator --peers peers.json
```

`validator.key` and `secrets.json` in the data directory are the node's
identity: they are created owner-only and must never be regenerated for an
existing participant identity.

## Filesystem layout

| Path | Contents |
|------|----------|
| `config.toml` | Node, network, RPC, execution and pruning configuration |
| `genesis.json` | Shared deployment definition and epoch-0 key material |
| `peers.json` | Participant addresses for the authenticated network |
| `validator.key` | Ed25519 consensus identity (32 bytes, owner-only) |
| `secrets.json` | BLS shares and DKG state (owner-only, atomic writes) |
| `history/` | Durable execution and finalization records |
| `native-genesis.bin` | Published after all seven partitions first seal |

Retain `validator.key` and `secrets.json` together with independently provisioned
genesis, configuration, and peer material. Recovering the remaining state depends
on reachable peers and available authenticated state and history. A delayed
snapshot catch-up re-floors from stored gossiped finalizations when processing
stalls and converges without network quiescence, though it still exits at its
deadline if peers cannot serve any retained target; a secret backup alone does
not establish that a restore will succeed. Exercise restores before relying on this recovery path.

## Recovery behaviour

- **Restart after clean stop** — startup aligns all journals to the durable
  anchor, rebuilds query indexes from durable history, then serves.
- **Restart after crash** — the same path: interrupted snapshot
  synchronization resumes from durable metadata; partially applied revisions
  rewind to the last durable anchor before execution continues.
- **Pruned peers** — a node joining late fetches a recent authenticated
  snapshot plus retained history; it does not need genesis-era data when
  pruning is configured (see [snapshot-recovery.md](snapshot-recovery.md)).
- **Disk write failures** — a failed or torn write during finalization stops
  the node before it acknowledges the revision; restart recovers to the last
  durable anchor. This is deliberate fail-stop, not a retry loop.

Do not delete `history/` or the genesis record to "reset" a node: existing
JMT directories or a missing genesis record alongside finalized history are
rejected and require an explicit migration decision, not silent reset.

## Configuration knobs operators own

- **Pruning** (`[pruning]`): `retained_consensus_revisions` bounds marshal
  archive retention; `retained_state_revisions = 0` prunes state snapshots
  aggressively. Retention must cover a complete DKG epoch. Memory retained by
  the archive window is bounded by retention divided by the section size —
  size deployments accordingly.
- **Snapshot catch-up** (`[snapshot]`): opt-in for newly admitted members;
  `record_bytes`, `peer_timeout_ms`, and `initialization_timeout_ms` must be positive.
  Initialization defaults to a five-minute deadline. Exceeding it stops the
  process; restart is not a guarantee of convergence. `floor_stall_seconds`
  (default 15, zero disables) bounds the quiet period before startup re-floors
  a stalled initialization from the newest stored gossiped finalization.
- **Finality watchdog** (`watchdog_stall_seconds`, default 600, `0` disables):
  remains unarmed while authenticated connectivity is unavailable. The current
  Commonware integration does not expose that telemetry, so this setting does
  not currently trigger supervised recovery. A watchdog that accounts for the
  active voting quorum still requires implementation and qualification. Snapshot
  initialization has its separate deadline; supervised restart does not guarantee recovery.
- **History backend**: default RocksDB; the `regolith-history` build feature
  selects Regolith with synchronous writes. The two backends reject each
  other's directory layouts — pick one per deployment.
- **RPC exposure**: bind `http_addr` to an internal interface for validator
  operation; expose only through the intended client path. The JSON-RPC
  server enforces its own batch, subscription and body-size limits (see
  [permission-proofs.md](permission-proofs.md) for proof-path budgets).

## Monitoring

- `vera_nodeStatus` reports `finalizedHeight`, `finalizedEpoch` and
  `finalizedView` from one published execution revision, including restored
  durable history. They are null until observed. `snapshotRevision` separately
  records the recovered snapshot floor. Use height changes for progress alarms;
  `finalizedCount` counts callbacks in this process and is not a height.
- `currentView`, `isLeader`, `peerCount` and `nullifiedCount` are null because
  this Commonware integration does not expose the corresponding live observations.
  Null does not mean zero peers, no nullifications or a known non-leader.
  `validatorIndex` and `validatorCount` describe startup configuration, not the
  active membership after operator changes. Rust clients represent unavailable
  fields as `Option`; JSON consumers must accept null. The compatibility
  `net_peerCount` method returns resource-unavailable (`-32002`) until an actual
  count is observed; it does not substitute zero for unknown connectivity.
- While backfilling, the compatibility `eth_syncing` response uses the published
  finalized height for `currentBlock`. Its `highestBlock` is only the maximum of
  that height and the recovered snapshot floor, not an estimate of the network
  tip. Consensus views and process counters are never used as heights.
- `RUST_LOG=warn,vera_diagnostics=debug` emits a resource snapshot every 30
  seconds (runtime metrics, resident execution index, cache occupancy,
  history-backend memory counters) plus per-revision apply and publication
  times. Collection runs off the async executor and is opt-in.
- Consensus warnings (`floor not updated`, view skips) at `warn` are normal
  during epoch transitions; sustained notarization timeouts are not.

## Capacity reference

Single-host baseline (four validators, one machine, release build): sustained
certified-registration throughput in the high tens of operations per second;
certified-receipt p95 in the 1-2 s range locally; resident memory per node
in the 300-500 MiB range with pruning active and a decelerating growth curve
as caches fill. Wide-area expectations and their gate criteria are defined in
[wan-gates.md](wan-gates.md). Re-baseline with the `operation_baseline`
(local) and `wan_baseline` (remote) drivers after material changes.

## Security notes for operators

- `validator.key` and `secrets.json` are created with owner-only permissions;
  keep the data directory off shared storage.
- Peer messaging is authenticated (see `peers.json`); RPC traffic should be
  TLS-terminated or network-isolated as appropriate for the deployment.
- Certificate and proof endpoints apply fixed budgets; a client exceeding
  them receives retryable `-32002` errors and must back off, not reconnect
  harder.
