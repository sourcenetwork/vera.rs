# vera-e2e

End-to-end integration tests. Each test stands up a real multi-node `verad`
cluster (BFT consensus needs ≥4 nodes) and drives it over JSON-RPC, exercising
both the EVM (`eth_sendRawTransaction`) and native BLS (`vera_sendNativeTx`)
transaction paths.

## Required pre-build

Tests spawn the real `verad` binary, so build it first:

```bash
cargo build -p verad
```

## Binary selection

The harness's `resolve_binary()` (via `test_infra::BinaryResolver`, `VERAD`
prefix) looks for the binary in this order:

1. `VERAD_BINARY` — explicit path, no version check
2. `HUBD_WORKSPACE` — a vera.rs checkout; builds the `verad` package there
3. `verad` on `PATH`
4. a `backbone.toml` manifest pin

It does **not** auto-discover `target/debug/verad`, so point it at a build
explicitly. The recommended, serial-safe invocation uses an absolute
`VERAD_BINARY` and runs one test target at a time:

```bash
cargo build -p verad
VERAD_BINARY="$(pwd)/target/debug/verad" \
  cargo test -p vera-e2e --test vera_e2e_canonical
```

## Serial / global-lock expectation

Each target starts a real multi-process cluster, and the Fast timing preset is
sensitive to host load. Run targets one at a time. Each cluster gets an isolated
run directory and ephemeral ports; `validator_bootstrap.rs` additionally uses a
process-wide `Mutex` (`validator_test_lock`) to serialize its two tests. Do not
run e2e targets concurrently in the same checkout.

## Test targets

All targets live in `crates/vera-e2e/tests/`:

| Target | Test(s) | Purpose |
|--------|---------|---------|
| `vera_e2e_canonical` | `canonical_module_test` | **Baseline gate.** Full module lifecycle on a 4-node cluster through both tx paths: ACP (policy, object, relationship, access), Bulletin (namespace, collaborator, post), cross-path verification (BLS write + EVM query and vice versa), and cluster health. Any change that breaks this has broken the core pipeline. |
| `contract_deploy` | `deploy_and_interact` | Deploys a minimal storage contract via CREATE, then exercises read (`eth_getStorageAt`) and write (`eth_sendRawTransaction`) paths against it. |
| `core_chain` | `cluster_observability_canonical` | 4-node BFT cluster with observability attached; cross-validates block heights and events between `LogTracker`, `RpcPoller`, and `ClusterState`. |
| `cross_object_acp` | `cross_object_grant_replicates_across_nodes` | Seeds a cross-object parent edge (subject is another object's userset) plus a child grant on node 0, then asserts on every other node that both replicate and that access resolves across the edge via `TupleToUserset`. |
| `gossip_headers` | `gossip_headers_subscription` | Verifies `eth_subscribe("headers")` delivers signed `GossipHeader` events (chain id, height, hashes, roots, signature) as blocks finalize. |
| `light_client` | `light_client_proof_verification` | Full light-client pipeline: gossip headers, `verify_light_block` on the BLS threshold certificate + epoch group key, module state proofs against `module_state_root`, and state-change detection across block boundaries. |
| `native_permission` | `native_permission_reads_follow_finalized_grants_and_denials` | Signed native grants and denial, independently authenticated current permission evidence on all four nodes, owner access, and rejection of old grant evidence at the later root. Uses combined revision/evidence responses without client proof retries; also runs 20 permission reads alongside four object registrations. |
| `native_object_archive` | `pipelined_object_archive_preserves_exact_counts_and_regrants_after_restart` | Four-validator native Simplex archive lifecycle with certified exact operation results, denial, unarchive without grant revival, regrant, incoming-userset preservation, physical cleanup and rolling restart. Uses fixed publication barriers and single evidence requests; cleanup/regrant overlap remains covered by module tests. |
| `node_restart` | `node_restart_preserves_state` | Starts 4 nodes, submits EVM + BLS txs, kills node 3, verifies the 3-node cluster continues, restarts it, and verifies pre-kill state survived (QMDB persistence), catch-up, post-restart txs on both paths, and tx submission *through* the restarted node. |
| `snapshot_catchup` | `snapshot_replica_recovers_history_and_rejoins_consensus` | An empty admitted replica uses authenticated state/history transfer after missing two epochs, restores exact receipts and verified permission reads, restarts from its recovery floor and later supplies a required quorum vote. |
| `snapshot_interrupt` | `interrupted_snapshot_resumes_without_an_explicit_request` | Requires `fault-injection` in both test and node builds. Aborts after one imported history record is durable, removes the snapshot request from configuration, and verifies automatic resume, restart, receipts, proofs, revocation and quorum participation. |
| `cold_replay` | `cold_replica_replays_across_epochs` | Starts a replica from bootstrap files after two epochs offline; checks recovered receipts, certified roots, native sequences and access revocation through combined revision/evidence responses, then requires its vote for continued quorum after another member stops. Uses retained peer history, not snapshot transfer or a new membership identity. |
| `validator_bootstrap` | `validator_bootstrap`, `validator_registry_adversarial` | Validators configured in genesis are readable via the ValidatorRegistry precompile; add/remove/status-change/self-update writes work through EVM txs, and adversarial inputs are rejected. Tests serialize on the global lock above. |
| `validator_epoch_transition` | `validator_epoch_transition` | Verifies ValidatorRegistry membership feeds resharing and that the engine actually enters the next epoch whose key material includes a newly registered validator. |

The native node uses ordered Commonware module storage. `light_client` still
exercises standalone JMT point/relation proofs and requires migration; those
endpoints are unavailable on a native node. `native_permission` covers the native
permission endpoint, without claiming historical proof availability or load qualification.

With both the binary and test built using `--features fault-injection`,
`module_commit_crash` aborts after each of the four native module journals becomes
durable, restarts the node, and verifies receipts, sequences, module records and
continued submission. Fault builds apply module journals sequentially to expose
these boundaries. This checks process recovery, not power-loss durability.

The fault-enabled `native_member_recovers_after_share_persistence_crash` case in
`native_membership` exits immediately after a newly generated share is durable,
before returning to the DKG caller. It restarts the incoming member without a
bootstrap share, then checks quorum participation, another restart, and member
removal. The marker is consumed before exit so recovery does not crash again.

## Harness environment and file contracts

- `VERA_E2E_DIR` — base directory for run artifacts (default `target/e2e`).
  Each run gets an isolated `{timestamp}-{random}` directory.
- `VERA_E2E_KEEP=1` — preserve the run directory on drop instead of deleting it.
- `RUST_LOG` — forwarded to every node process (default `info`); `NO_COLOR=1`
  is always set for node logs. Pruning tests require `vera_storage=info` to
  verify completed pruning from the logs; keep that target enabled when
  overriding the default filter.
- Per-node layout under the run dir: `node{i}/` holds the node's config,
  data dir, and `logs/`; `TestNode` exposes `rpc_url()` / `ws_url()` on
  ephemeral OS-allocated ports (RPC and P2P allocated together per node).
- `GenesisBuilder` produces the genesis file (funded Hardhat accounts,
  optional `ValidatorConfig`s, `blocks_per_epoch`); `ConsensusPreset` selects
  Fast/Normal/Stress timing.
- Receipt polling constants `RECEIPT_POLL_INTERVAL` (300 ms) and
  `RECEIPT_POLL_ATTEMPTS` (400) are re-exported from `vera_e2e` for tests.

## Diagnostic preservation

When a test fails, the cluster's run directory is the primary diagnostic: node
logs under `node{i}/logs/`, per-node config/genesis, and data dirs. Re-run the
failing target with `VERA_E2E_KEEP=1` to retain the whole run directory for
inspection instead of letting RAII cleanup remove it.

### `VERA_E2E_DEADLINE_SCALE`

Multiplies the 30-second cluster-readiness base deadline; CI sets 8 (Linux native) or 4 (studio e2e).
