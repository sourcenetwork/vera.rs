# Embedded node

`vera_node::EmbeddedNode` runs a validator inside another program. It is the
same node `verad` runs: the same consensus, execution, storage and recovery.
The host calls its JSON-RPC methods in-process instead of over a socket.

This first version hosts a single-validator deployment. Adding validators to an
embedded deployment and changing its membership are not implemented yet.

## Starting a node

```rust
let genesis = SoloGenesis { chain_id, operators, timestamp };
let node = EmbeddedNode::start(EmbeddedConfig::new(data_dir, genesis, p2p_listen)).await?;
let status: NodeStatus = node.rpc().call_empty("vera_nodeStatus").await?;
node.stop().await?;
```

`start` returns after startup recovery has completed and the node serves
requests. It can be awaited from any async runtime. A host crate needs no
`recursion_limit` attribute: the node's actor graph is built inside `vera-node`
and the host holds it behind a pointer.

A directory that another node holds, in this process or another, fails with
`EmbedError::DirectoryInUse`. The check runs just before the node's runtime
takes the directory, so a holder that arrives in between is waited for instead.

## Deployment identity

`SoloGenesis` fixes the deployment when its directory is first used:

- `operators` is the account's administrative policy. It, not the device's
  validator key, is the authority for later administrative changes. Its keys
  may be secp256k1, Ed25519 or P-256; see
  [operator keys](consensus-membership.md#operator-keys). For a personal
  deployment, list the account key and each master device's key with a
  threshold of two: every change then needs two distinct approvals, and one
  device alone approves nothing.
- The device's validator key (`validator.key`) is created in the directory and
  becomes the only validator.
- The consensus share is dealt once from operating-system randomness and stored
  in `secrets.json`. `verad devnet` instead derives its share from a fixed
  public seed, which is suitable only for local test networks.
- The genesis uses pipelined, native-only consensus with 256-block epochs.

Reopening the directory reuses the stored genesis (`solo-genesis.json`) and
share. A different chain identifier, operator policy or validator key is
rejected, and so is a directory that holds a genesis without its share. Losing
`secrets.json` or `validator.key` makes the deployment unrecoverable; back them
up with the rest of the directory.

Finality proofs verify against `EmbeddedNode::consensus_key()`.

## Calling the node

`EmbeddedNode::rpc()` returns a `vera_jsonrpc::LocalRpc`. It dispatches into the
method table the network server uses, so results, errors and method-level
limits are the same: proof admission slots, request deadlines and the
retryable `-32002` response all apply. `LocalRpcError::is_retryable` identifies
that response.

Method bodies run on the node's runtime, not on the caller's. The futures that
`LocalRpc` returns can be awaited from any executor, including one that is not
Tokio, and from any thread. After the node stops they fail with
`LocalRpcError::Stopped`.

- `request` and `call_empty` take positional JSON parameters and decode the result.
- `request_raw` returns the result as JSON text, so a host can apply its own
  response byte limit. Transport limits (request size, batching,
  per-connection subscriptions) belong to the network server and do not apply
  in-process.
- `subscribe` returns a `LocalSubscription`; `vera_subscribeHeaders` delivers
  each finalized header. Dropping the subscription ends it, and it ends when the
  node stops.

Set `EmbeddedConfig::rpc_listen` to also serve the same methods over the
network. It is off by default.

## Threads

The node runs on a dedicated thread with its own Commonware runtime. The host's
runtime is not used. Every other thread of the node is created by the node
thread or by a thread it created.

| Group | Name | Count | Bound | Started |
| --- | --- | --- | --- | --- |
| Node thread | `vera-node` | 1 | fixed | by the thread that calls `start` |
| Async workers | `tokio-rt-worker` | `worker_threads`, default 2 | `EmbeddedConfig::worker_threads` | when the runtime is built |
| Blocking threads | `tokio-rt-worker` | 0 to `max_blocking_threads`, default 512 | `EmbeddedConfig::max_blocking_threads` | on demand, by the node thread that submits the work; they exit after ten idle seconds |
| Verification pool | unnamed | `verification_threads` | `EmbeddedConfig::verification_threads` | at startup |
| History store | `regolith-compaction-0` | 1 | fixed: Vera opens Regolith with one background worker, which flushes and compacts, and without its log-writeback thread | when the history store opens at startup |

The verification pool checks native request signatures and digests blocks.
`EmbeddedConfig::new` sets `verification_threads` to the machine's available
parallelism, at most four, which is what the daemon uses. The field holds the
resolved number, so the count does not change if the host later narrows the
CPUs the node may use.

The node starts no Commonware dedicated thread. In Commonware 2026.10 only the
partitioned QMDB index build spawns them, and Vera's stores build their indexes
serially. Storage operations, name resolution, history reads and the reshare
verification task use the blocking threads, and so does the replacement worker
that the runtime starts when a worker blocks in place. The node uses no
process-global thread pool: the verification pool is private to the node, and
BLS arithmetic is built without its own pool.

`EmbeddedConfig::thread_budget()` returns these counts as a `ThreadBudget`.
`persistent()` is the number of threads that live as long as the node, and
`max()` adds the blocking bound.

```rust
let mut config = EmbeddedConfig::new(data_dir, genesis, p2p_listen);
config.worker_threads = Some(1);
config.max_blocking_threads = Some(16);
config.verification_threads = 1;
config.thread_setup = Some(ThreadSetup::new(move || pin_to(&edge_cpus)));
let budget = config.thread_budget();
```

`thread_setup` runs once per `start`, on the node thread, before the runtime is
built and so before any other thread of the node exists. If it returns an
error, `start` fails with `EmbedError::ThreadSetup` and no other thread was
started.

In-process calls do not add threads outside this set. `LocalRpc` queues a call
on the node's runtime and waits for the result; the calling thread starts
nothing, and blocking work done for the call starts from a node thread.

What a thread passes on to the threads it creates depends on the platform:

- **Linux.** A new thread inherits its creator's CPU affinity mask. A mask that
  `thread_setup` applies with `sched_setaffinity` therefore holds for every
  thread in the table. `crates/vera-node/tests/embedded_thread_affinity.rs`
  checks this for every thread the process gains, and that their number stays
  within the budget.
- **macOS.** There is no CPU affinity mask to inherit, so a node cannot be
  confined to a set of cores this way. The ordering and the counts above still
  hold.
- **Windows.** A thread affinity mask applies to the thread it is set on; new
  threads start from the process affinity mask. `thread_setup` therefore places
  only the node thread.

CI runs the embedded test targets on Linux and on macOS arm64. Windows is not a
supported host: nothing builds or tests the node there.

The inventory covers the default build. The optional `nuclei-rpc` transport
uses a process-global proactor and is not covered.

## Shutdown

`stop` ends the node between views and waits for its thread. It first holds
back new proposals, then waits up to two seconds for the blocks already
proposed to finalize, and only then drops the runtime. Dropping an
`EmbeddedNode` requests the same stop without waiting.

The wait matters for the next start. Commonware does not replay a validator's
own votes after a restart, so a lone validator that stopped after voting for a
block and before storing that block's certificate waits out the certification
timeout, 4 s by default, before its next block. A stop that outlasts the two
seconds, a crash and a killed process can still leave the node there; the
node recovers by itself and loses nothing, but the first write after that
start is late by the timeout.

Stopping still has no storage shutdown protocol: the stores rely on the same
recovery path as an interrupted daemon.

Once the node has stopped, by `stop` or by itself, its directory is free and
another node can start on it. That holds while clones of its `LocalRpc` are
still alive: the node releases the method table they share, and their calls
return `LocalRpcError::Stopped`.

`failed` resolves if the node stops by itself. An embedded node never exits the
host process: the finality watchdog stops the node with an error instead. It
trips when the node has finalized before and then finalizes nothing for ten
minutes, checked every 30 seconds. An idle node keeps finalizing heartbeat
blocks, so idleness is not a stall.

## Files and ports

Everything is under `EmbeddedConfig::data_dir`: `validator.key`, `secrets.json`,
`solo-genesis.json`, `native-genesis.bin`, `commonware/` and
`history/regolith/`. The directory must not be shared with another store; a host
that also embeds DefraDB gives each its own directory.

A single validator dials no peers, but the consensus network still binds
`p2p_listen`. The listener cannot be switched off: Commonware 2026.10's
`authenticated::discovery` network takes a required listen address, always
starts its listener actor, treats a failed bind as fatal and stops when the
listener stops. The node's other actors are wired to that network, so it
stays.

For a deployment that no other validator reaches, pass `127.0.0.1:0`. The
listener then binds loopback on a port the operating system chooses, so the
host reserves no port and nothing outside the machine can connect. A
connection from the same machine is accepted only from a peer the node tracks,
after the authenticated handshake. Use another address only when other
validators must reach the node.

## Disk

`EmbeddedConfig::pruning` sets how much consensus archive and state journal the
node keeps. The default, `EmbeddedConfig::RETENTION`, keeps 512 revisions of
consensus archives (two epochs) and 256 of state journals, pruned every 64
revisions. `None` keeps everything, as the daemon does without a `[pruning]`
section. A lone validator has no peer that needs older consensus data from it.

Finalized history, which serves receipts and historical lookups, is not
pruned by this setting or any other. It is what still grows.

Measured on an Apple M5 Max with a release build: an idle node at the daemon
cadence (`pacing: None`, about 6.6 revisions a second) for five minutes, about
1,970 empty revisions, one run each.

| Retention | Directory after 5 min | Growth per revision | Of which finalized history |
| --- | --- | --- | --- |
| none | 10.6 MB | about 5.1 kB | about 1.05 kB |
| 512 consensus, 256 state | 5.3 MB and levelling off | about 1.05 kB once the window is full | about 1.05 kB |

At the default heartbeat of one revision every 10 s, 360 an hour, that is
about 1.8 MB an hour without retention and about 0.4 MB an hour with it, all
of it finalized history. Both figures are computed from the per-revision
growth above, not measured at this cadence; the retention window takes about
85 minutes of idling to fill, and until then the node grows at the first
rate. Revisions that carry requests are larger.

## Memory

`EmbeddedConfig::sizing` sets the two allocations a node makes when it starts,
before any request. The embedded defaults are `NodeSizing::EMBEDDED`; the
daemon uses `NodeSizing::DAEMON`.

| Size | Embedded default | Daemon |
| --- | --- | --- |
| `channel_burst`: burst of each peer channel's rate limit | 1 | 64 |
| `page_cache_pages`: 4 KiB pages shared by the state and consensus journals | 256 | 4,096 |

Commonware allocates each of the 16 peer channels an inbound queue of tracked
peers times the burst, and the router the sum of those, whether or not a peer
connects. A solo deployment tracks 100 peers, so a burst of 64 reserves about
56 MiB for a validator that has none. The embedded sizes assume no peers; a
deployment that gains validators needs the daemon's.

Measured with
`PROFILE_WRITES=1000 cargo test --release -p vera-node --test embedded_solo_profile -- --ignored --nocapture`
on an Apple M5 Max (18 cores, 64 GiB, macOS 27.0.1), one run per row, selected
with `PROFILE_CHANNEL_BURST` and `PROFILE_PAGE_CACHE_PAGES`. Memory is the peak
resident size of the test process, which measured 8.0 MiB before the node
started. The restart is a stop followed by a start on the same directory.

| Burst | Cache pages | After start | After 1,000 policy writes | Receipt p50 | Restart |
| --- | --- | --- | --- | --- | --- |
| 64 | 4,096 (daemon) | 105.7 MiB | 132.8 MiB | 193 ms | 436 ms |
| 1 | 4,096 | 50.2 MiB | 75.0 MiB | 191 ms | 424 ms |
| 1 | 1,024 | 38.8 MiB | 62.8 MiB | 195 ms | 441 ms |
| 1 | 256 (default) | 35.3 MiB | 59.7 MiB | 195 ms | 453 ms |
| 1 | 64 | 34.8 MiB | 59.3 MiB | 194 ms | 483 ms |

Below 256 pages the saving is under 1 MiB. The state these runs build is small
(1,000 policies), so they do not show what a small cache costs once the state
no longer fits in it.

`EmbeddedConfig::history_memory` bounds what the finalized-history store keeps
in memory. The embedded defaults are `HistoryMemory::EMBEDDED`; the daemon
keeps Regolith's own sizes.

| Budget | Embedded default | Daemon |
| --- | --- | --- |
| `block_cache_bytes`: decompressed table blocks kept for reads | 8 MiB | 512 MiB |
| `write_buffer_bytes`: records held before a flush | 4 MiB | 64 MiB |

Both fill with use, the cache on reads and the buffer as revisions finalize.
Regolith also keeps flushed buffers for reuse, so memory attributable to the
write buffer can reach a few times its budget. A smaller buffer flushes more
often and writes smaller tables.

Everything else about the store is as the daemon opens it, including the
64 MiB value limit and the background worker. Regolith's `Options::embedded()`
preset is not used: it caps a value at 256 KiB, and one history record holds a
whole block, up to 17 MiB, with its receipts. A record larger than the write
buffer is accepted and stays in memory until it is flushed. A block cache of
zero disables the cache. `start` rejects a write buffer of zero, the one size
Regolith refuses.

The table below predates `NodeSizing` and was taken with the daemon's start-up
sizes. Measured with
`cargo test --release -p vera-node --test embedded_solo_profile -- --ignored --nocapture`
on an Apple M5 Max (18 cores, 64 GiB, macOS 27.0.1), two runs of the first row
and three of the second. The first row sets `PROFILE_HISTORY_CACHE_MIB=512 PROFILE_HISTORY_BUFFER_MIB=64`.
The figures are the peak resident size of the test process, which holds the
node, the test harness and its Tokio runtime; that process measured 8.3 MiB
before the node started.

| History budgets | After start | After 100 policy writes | After 30 s idle |
| --- | --- | --- | --- |
| 512 MiB cache, 64 MiB buffer | 107.2 to 109.6 MiB | 121.1 to 121.2 MiB | 121.3 MiB |
| 8 MiB cache, 4 MiB buffer (default) | 107.0 to 109.0 MiB | 119.4 to 120.0 MiB | 119.4 to 120.0 MiB |

This workload leaves about 0.3 MiB of history on disk and reads little of it
back, so neither pair of budgets is reached and the rows do not differ beyond
run-to-run variation. The budgets limit growth over a longer life; they do not
lower the starting footprint, which the start-up sizes above set. The
machine was running other builds (load average 9 to 30), which does not change
what the node allocates but did make the system reclaim idle memory: the
current resident size fell as low as 36 MiB during the idle period in some
runs while the peak stayed put. Receipt latencies from these runs are not
comparable with the table under [Proposal pacing](#proposal-pacing).

## Proposal pacing

`EmbeddedConfig::pacing` controls how the lone validator paces proposals. The
default has two parts:

- **Idle wait.** With no request pending and no unfinalized block that carries
  requests, the proposer waits up to `EmbeddedConfig::HEARTBEAT` (10 s) for a
  first request, then proposes an empty block as a heartbeat. A request ends
  the wait at once. The wait must stay below the leader timeout, 12 s by
  default, and that below the certification timeout and the solo genesis stall
  timeout of 30 s; `start` rejects settings that would not.

  The heartbeat cannot be dropped: a client that verifies state against
  finalized headers refuses a state older than its freshness limit, which is
  30 seconds in Backbone's light client. A host that lengthens the idle wait
  must keep it inside the limit its clients use.

  The leader timeout is also how long a lone validator waits before it tries
  again after a proposal it could not build.
- **Batch window.** Once a request has arrived the proposer collects more for
  50 ms. While a block that carries requests is unfinalized it keeps this
  cadence, because the wait runs on the actor that also processes finalization.

`pacing: None` keeps the standalone daemon's cadence.

Measured on one Apple-silicon laptop with a release build: 100 sequential
policy creations, each timed from submission to a verified certified receipt,
then 30 seconds idle. Reproduce with
`cargo test --release -p vera-node --test embedded_solo_profile -- --ignored --nocapture`
(`PROFILE_IDLE_MS` and `PROFILE_BATCH_MS` select a row).

| Idle wait | Batch window | Receipt p50 | Receipt p95 | Idle blocks/s | Idle disk growth |
| --- | --- | --- | --- | --- | --- |
| none | 100 ms (daemon) | 281 ms | 340 ms | 6.97 | 158 MB/h |
| 1.5 s | 100 ms | 280 ms | 340 ms | 0.67 | 12.4 MB/h |
| 1.5 s | 50 ms | 185 ms | 244 ms | 0.67 | 11.9 MB/h |
| 1.5 s | 25 ms | 148 ms | 202 ms | 0.67 | 12.4 MB/h |
| 1.5 s | 15 ms | 220 ms | 377 ms | 0.67 | 12.7 MB/h |
| 1.5 s | 5 ms | 377 ms | 604 ms | 0.73 | 15.6 MB/h |

The idle wait was 1.5 s when those rows were measured. The 10 s default was
compared with it afterwards on an Apple M5 Max, with the same 100 writes and
five minutes idle (`PROFILE_IDLE_SECONDS=300`), one run each. The 1.5 s row
ran without retention; the 10 s row ran with the default retention, whose
512-revision window does not fill in a run this short, so neither row shows
pruning at work:

| Idle wait | Batch window | Receipt p50 | Receipt p95 | Idle blocks/s | Idle disk growth |
| --- | --- | --- | --- | --- | --- |
| 1.5 s | 50 ms | 194 ms | 260 ms | 0.65 | 14.9 MB/h |
| 10 s (default) | 50 ms | 187 ms | 253 ms | 0.10 | 2.4 MB/h |

No run abandoned a view. Below roughly 25 ms the receipt latency rises again
on this machine; that point depends on how fast the disk commits, so the
default leaves margin. These are single-process results on one machine. They
are not a capacity or multi-validator measurement.

## Limits

- One validator. A stopped or lost device stops the deployment.
- An idle deployment still produces a heartbeat block about every 10 s, and
  finalized history has no retention, so the directory grows without bound;
  see [Disk](#disk).
- Memory was measured for short workloads on one machine; see
  [Memory](#memory). Growth over hours, larger states and Linux are not
  measured, and the embedded page cache has not been measured against a state
  larger than it.
- The smallest workable `max_blocking_threads` has not been established.
  Blocking tasks that wait on storage hold threads that storage needs, so a
  bound that is too small can stall the node. On one Apple-silicon laptop a
  debug build with one worker started, finalized a policy and idled with bounds
  of 1, 2, 4 and 16, filling the bound each time, and used 46 blocking threads
  under the default bound. Resharing at an epoch boundary was not part of that
  run.
