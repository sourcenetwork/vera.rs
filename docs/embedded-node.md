# Embedded node

`vera_node::EmbeddedNode` runs a validator inside another program. It is the
same node `verad` runs: the same consensus, execution, storage and recovery.
The host calls its JSON-RPC methods in-process instead of over a socket.

This first version hosts a single-validator deployment. Adding validators to an
embedded deployment and changing its membership are not implemented yet. Other
devices of the account can follow the deployment as
[backups](#backup-devices), which validate nothing.

## Starting a node

```rust
let genesis = SoloGenesis { chain_id, operators, timestamp };
let node = EmbeddedNode::start(EmbeddedConfig::new(data_dir, genesis, p2p_listen)).await?;
let status: NodeStatus = node.rpc().call_empty("vera_nodeStatus").await?;
node.stop().await?;
```

`start` returns after startup recovery has completed, the node has applied
the finalized blocks its consensus archive holds (for up to 30 seconds), and
it serves requests. It can be awaited from any async runtime. A host crate needs no
`recursion_limit` attribute: the node's actor graph is built inside `vera-node`
and the host holds it behind a pointer.

A directory that another node holds, in this process or another, fails with
`EmbedError::DirectoryInUse`. Once its deployment's records are checked or
created, an embedded node locks `.node-hold` in its data directory, before it
changes its term record or consensus storage, and keeps the lock until its
runtime has stopped, so a second embedded node is refused before it touches
either; `EmbeddedNode::resume_stopped` takes the same lock. Commonware's
own lock in `commonware/` is checked just before the runtime takes it, and a
holder of that lock alone that arrives in between is waited for instead.

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
rejected, and so is a directory that holds a genesis without its share. A first
start interrupted after the share is stored leaves the genesis as
`solo-genesis.pending`; the next start publishes it. Losing
`secrets.json` or `validator.key` makes the deployment unrecoverable; back them
up with the rest of the directory.

Finality proofs verify against `EmbeddedNode::consensus_key()`.

## Key material held by the host

By default the validator key and the consensus share are plaintext files in the
directory, protected only by their permissions. A host that keeps secrets in
the operating system's keystore holds them itself instead:

```rust
let deployment = SoloDeployment::create(&genesis, p2p_listen)?;
// Store deployment.record(), deployment.keys().validator_key() and
// deployment.keys().share() in the keystore before the first start.
let node = EmbeddedNode::start(EmbeddedConfig::adopt(data_dir, deployment, p2p_listen)?).await?;
```

`SoloDeployment` is an existing deployment as its host holds it: the genesis
record, which is the content of `solo-genesis.json`, and `SoloKeys`, the
validator key and consensus share. `SoloGenesis` still describes the identity;
`SoloDeployment::create` deals a deployment for one in memory and writes
nothing, and `EmbeddedConfig::adopt` reads the identity back from the record.
On later starts the host rebuilds the value from its keystore with
`SoloDeployment::new(record, SoloKeys::decode(validator_key, share)?)`.

A node started this way signs from memory. It writes the genesis record to the
directory and never the validator key or the share: there is no `validator.key`
and no `secrets.json`. `SoloKeys` prints only the validator's public key, its
byte accessors return buffers that are erased when dropped, and no error
carries key material. The node does not lock or protect its own memory.

The share is checked against the record before anything is stored. Everything
else is checked as for a deployment kept in files: the chain identifier,
operator policy, seeded policies and the validator derived from the supplied
key.

- An empty directory receives the genesis record, written under
  `solo-genesis.pending`, synchronized and renamed, and the node starts that
  deployment from its genesis.
- A directory that already holds the same deployment is opened unchanged.
  Key files left there by an earlier start that kept them in files are not
  removed; the host removes them once the keystore holds the material.
- A directory that holds another deployment fails with `SoloError::Mismatch`,
  and one that holds node state without a genesis with `SoloError::Incomplete`.
- A share that the record's genesis was not dealt with fails with
  `SoloError::ShareMismatch`, and nothing is written.

### The share after the first epoch

Each epoch ends with a resharing ceremony, and the node looks its share up by
epoch. With one validator the ceremony's polynomial is constant, so the dealing
the validator sends itself and the share of the next epoch both equal the share
it started with. A node that keeps its keys in files stores that same value
under each new epoch. The host therefore holds one share for the life of the
deployment, and the node serves it for every epoch.

Two parts of the ceremony are not kept across a restart when the host holds the
keys. The dealer's random seed is drawn again, which changes nothing because a
constant polynomial has no random coefficient. The dealing the validator
received from itself is rebuilt from the share; without it a node restarted
after its dealing was finalized would finish the epoch as an observer and hold
no signing scheme for the next one.

This holds for one validator only. A ceremony that yields a different share,
as one with a second validator does, stops the node: a share that exists only
in the node's memory would be lost with it.

### A second device

`EmbeddedNode::export()` returns the running deployment as a `SoloDeployment`:
the genesis record with the validator key and the newest share, read from the
files or from the material the host supplied. It can be called only in the
host process, is not an RPC method and logs nothing. The host carries the
result to another device over its own protected channel, and that device
opens it with `EmbeddedConfig::adopt`.

- The export carries no state. A device that adopts it has the same chain
  identifier, consensus key and validator identity, and an empty chain at
  height 0. Adopting runs the device as the deployment's validator; a device
  that should hold the deployment's state without validating it runs as a
  [backup](#backup-devices) instead, and needs only the genesis record.
- Nothing stops two devices from running the deployment as validator at the
  same time. Each then finalizes its own blocks under the same key, the two
  histories diverge, and both verify against the deployment's consensus key.
  Run the deployment on one device at a time, and move it between devices
  with a [term certificate](active-term.md).
- Without `EmbeddedConfig::switching`, nothing detects it: neither device
  asks the other, neither stops, and a client sees both histories verify.
  With it, each device lists the others, and two that both validate notice
  each other as soon as one can reach the other: a device does not start
  proposing while another answers as the validator, and an active device
  asks again every `Switching::freshness`. One of the two then stops
  proposing and reports it (`EmbeddedNode::contested`, or
  `EmbeddedNode::demoted` when the other holds a later term), and the host
  settles it with a certificate; the device that follows drops what it
  finalized alone and reports it (`EmbeddedNode::discarded`). Blocks both
  finalized before they reached each other are not prevented. See
  [The wake check](active-term.md#the-wake-check).
- Every copy is a full signing capability. A copy cannot be revoked short of
  creating a new deployment.

## Backup devices

A backup is a second device of the account that keeps the deployment's state
current without validating it. It connects to the active device, the one that
runs as validator, catches up from an empty directory, then receives every
finalized block, verifies its certificate against the deployment's consensus
key, re-executes it and serves reads and proofs from the result. It builds no
block, casts no vote and takes no part in resharing.

```rust
// On the backup. `record` is SoloDeployment::record() of the deployment.
let key = DeviceKey::load_or_create(&data_dir)?;
let backup = EmbeddedNode::start(
    EmbeddedConfig::backup(data_dir, record, p2p_listen, active_address)?,
).await?;

// On the active device, with the backup's key.public_key().
let mut config = EmbeddedConfig::new(data_dir, genesis, p2p_listen);
config.backups = vec![backup_public_key];
```

`EmbeddedConfig::role` is `DeviceRole::Active` by default, which is the node
described in the rest of this document. `EmbeddedConfig::backup` sets
`DeviceRole::Backup` with the genesis record and the address of the active
device's consensus listener.

### What a backup holds

A backup holds the genesis record and its own transport key. It holds neither
the validator key nor the consensus share, in memory or on disk: a start that
names a `deployment` together with the backup role fails with
`EmbedError::Config`, and a directory that keeps `validator.key` or
`secrets.json` fails with `SoloError::Mismatch`. Its consensus scheme can
verify certificates and cannot sign, and `EmbeddedNode::export()` fails on it.

The transport key (`DeviceKey`) authenticates the device to the active device
and signs nothing else. With `Backup::transport_key` unset it is kept in
`transport.key` in the directory, created on first use and readable only by
its owner; `DeviceKey::load_or_create` returns it before the node starts so
the host can read its public key. A host that keeps keys in a keystore
supplies it instead (`DeviceKey::generate`, `encode`, `decode`), and no file
is written. `EmbeddedNode::identity()` returns the key other devices know a
node by: the transport key on a backup, the validator key on the active
device.

The active device has no separate transport key. Commonware identifies a
validator on the network by its consensus key: a node blocks a peer that sends
votes under a key outside the committee, and the catch-up probe asks the
committee's keys and blocks any other peer that answers. The validator key is
therefore the active device's network identity, and only a backup, which is
in no committee, runs under a key of its own.

### How devices are listed

`EmbeddedConfig::backups` on the active device lists the transport public keys
of its backups. The active device accepts a connection only from a listed
key, after the authenticated handshake. It is given no backup's address, so a
backup needs no reachable address; once a backup has connected, the active
device also learns the address the backup announces and can reach it there
after the backup restarts, which a test that cut the two apart with a relay
observed. A backup dials the active device at the address it was given and
retries while that device is away. Backups do not connect to
each other, and a backup ignores the list.

The list is configuration. Nothing in the deployment's state records which
devices are backups, no operator approval is involved, and changing the list
takes a restart of the active device. A later version records the devices in
state under operator approval.

The active device's listener must be reachable by its backups, so it cannot
stay on `127.0.0.1:0` unless the host tunnels the connection to it. The
listener keeps the local discovery settings, which admit loopback and private
addresses.

A listed backup is a secondary peer of every epoch. It receives what the
active device sends to all connected peers (votes, certificates, new blocks
and gossiped requests, the last of which it drops) and the answers to its own
requests for blocks, state ranges, history chunks and the epoch probe. Each
channel keeps the per-peer rate limit it has for a validator. The active
device's queues are not resized: a tracked set may hold up to 25 peers with
256-block epochs, and the validator and its backups must fit in it, or the
start fails. A backup's queues grow by one burst per channel for the active
device it dials.

### Catching up and staying current

A backup started on an empty directory asks the active device for its newest
finalized block, transfers the authenticated state at that revision, imports
the finalized history behind it, and then follows. Receipts and proofs for
requests finalized before the backup existed are served from the imported
history. `start` returns once this has completed. It fails with
`EmbedError::Stopped` if the active device does not answer within
`EmbeddedConfig::catch_up_timeout` (5 minutes by default), or if the transfer
and import then take longer than that again. The import takes longer the
older the deployment is; see [the limits](#limits-of-this-version).

A backup that restarts continues from its own directory. It first asks the
active device how far the deployment has advanced, for up to 30 seconds, so a
restart while the active device is away takes that long. If the deployment
is so many epochs ahead that the active device may have pruned the backup's
next block, the backup transfers the state again instead of asking for blocks
that are gone, and imports the history it missed. With the default epochs of
256 blocks and retention of 512 consensus revisions that is two epochs, which
an idle deployment finalizes in 43 to 85 minutes. The backup judges this by
its own `EmbeddedConfig::pruning`, so the devices of an account should share
one retention setting.

A backup that is behind when the active device crosses an epoch boundary
receives certificates of an epoch it has not entered. Commonware's
orchestrator drops such messages and only fetches the epoch's last block, so
the backup keeps the newest 256 of them, within 1 MiB, on the certificate
channel and hands them to consensus again once it has entered their epoch. It finalizes the
blocks they certify from its own buffer of recent blocks, also when the
active device has stopped meanwhile.

The channel a catching-up device fetches finalized blocks and certificates
on keeps at least the daemon's burst on every node with a peer, whatever
`channel_burst` says: with a burst of one, all but one of the answers to its
parallel requests are dropped and it advances by one fetch timeout per
block.

While the active device is away a backup keeps serving the state it has.
Once it has finalized the blocks it already holds certificates for, it
finalizes nothing more, its height stays there, and
`vera_nodeStatus` reports `peerCount` 0. Clients that require fresh state
refuse it after their freshness limit, as they would for a stopped
deployment. The finality watchdog (`EmbeddedConfig::watchdog_stall`, 10
minutes by default) stops a backup only when it is connected to the active
device and still receives no finalized block for that long; the host restarts
it, and the restart re-synchronizes if needed.

A backup re-executes every block and compares the result with the state the
block commits to. A certified block that does not reproduce its committed
state is not applied: Commonware's stateful actor panics on it, which stops
the node, and a restart meets the same block again. The backup's directory
keeps the state of the block before it. This follows from the code and has
not been exercised by a test, which would need a validator that certifies an
invalid block.

### What a backup refuses

A submission (`vera_sendNativeTx`) fails on a backup with the
retryable code `-32002` and the data `{"retryable": true, "role": "backup"}`;
`LocalRpcError::is_backup_refusal` identifies the response. Nothing is
admitted or forwarded: the host sends the request to the active device.
`eth_call`, `eth_estimateGas` and `vera_simulateNativeCall` run on a backup as
on any node, against its own state.

### Limits of this version

- A backup becomes active only through a term certificate; see
  [Terms and the active device](active-term.md). Opening a backup's directory
  as the validator with `EmbeddedConfig::adopt` alone records no switch, and
  the device that was active does not learn of it.
- Nothing enforces a single active device beyond the term. Two devices
  started as active each finalize their own blocks under the same key and
  fork the deployment while they cannot reach each other, as described under
  [A second device](#a-second-device). Both use the validator key as their
  network identity, so they cannot connect to each other as validators; they
  find each other only through the term check of devices configured with
  `switching`.
- A backup is as current as its connection. A request finalized on the active
  device while a backup is disconnected is absent from that backup until it
  reconnects, and a device lost before then takes the request with it.
- The first start needs the active device. A backup cannot be created from
  another backup.
- The first start imports the deployment's whole finalized history, one block
  at a time, and its cost grows with the deployment's age. On one
  Apple-silicon laptop, with both nodes in one process on loopback and a
  release build, a backup started on an empty directory was serving after
  13.8 s behind a deployment of 401 blocks and after 118 s behind one of
  1,601 blocks, one run each. An idle deployment adds 8,640 blocks a day, so
  the default `catch_up_timeout` of 5 minutes covers only a young deployment
  and has to be raised for an older one. Why the cost per block rises, and
  whether a start that ran out of time resumes the import it began, are not
  established.
- In the same setting a backup following an idle deployment processed the
  active device's 6 blocks a minute and added 1.9 MB an hour to its directory
  over 5 minutes, against 1.8 MB for the active device, and the process's
  resident memory was 46 MiB with the active device alone and 63 MiB with the
  backup beside it. A backup's memory was not measured in a process of its
  own.
- A backup must be able to dial the address the active device listens on.
  After the first connection Commonware redials the address the active device
  announces, which is its `p2p_listen`, so a backup that reaches the active
  device at another address, through a tunnel or address translation, has not
  been shown to reconnect.

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
  node stops. A consumer that falls more than 64 headers behind skips to the
  oldest retained header and keeps receiving; heights show the gap, and
  `vera_getLightBlock` fills it.

Set `EmbeddedConfig::rpc_listen` to also serve the same methods over the
network. It is off by default. The address is bound during start, so an
address in use fails the start.

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

## Seeded policies

`SoloGenesis::policies` lists ACP policies the deployment starts with. Each
entry names its definition, the counter its identifier is derived from and the
DID recorded as its owner, so a host that already names a policy by an
identifier, as a content-derived one with a fixed counter, finds it under that
identifier on a new deployment. Two entries may share a counter when their
definitions differ. Policies created later take counters above the highest one
seeded and above the number of policies seeded.

The list is part of the deployment's identity: reopening a directory with a
different list is refused. A list that does not compile, or names one
identifier twice, is refused with `SoloError::Policies` before anything is
stored, so a corrected list starts in the same directory. A seeded policy
records no creating transaction, worker or creation revision.

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
`history/regolith/`, and `term.json`, which records the
[term](active-term.md#what-a-device-stores) and the role consensus storage was
last opened in. A start that clears consensus storage for a switch also keeps
`kept-finalizations` there until it is done; see
[Consensus storage across a switch](active-term.md#consensus-storage-across-a-switch).
The first two are absent when
[the host holds the key material](#key-material-held-by-the-host) and on a
[backup](#backup-devices), which keeps `transport.key` instead unless the host
holds that key too. The directory must not be shared with another store; a host
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
validators or the account's backups must reach the node.

The embedded listener states the local discovery settings, which admit
loopback and private addresses, instead of the daemon's recommended profile
([settings](operating.md#configuration-knobs-operators-own)). `EmbeddedConfig`
does not expose them.

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
deployment that gains validators needs the daemon's. A node with a backup or
an active device to follow keeps the daemon's burst on the block-fetch
channel, about 3.5 MiB of it, so a backup can catch up.

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
  30 seconds in Backbone's light client. A header reaches clients one idle
  wait after its block was proposed, because the node processes a block's
  finalization only when the next proposal returns. With the 10 s default an
  idle node's newest published state is therefore between 10 and 20 seconds
  old, which leaves room for one late heartbeat. A host that lengthens the
  idle wait must keep twice the wait inside the limit its clients use.

  The wait does not apply until one block has been finalized since the start,
  so a node that just started publishes a current state at once.

  Block timestamps follow the device's clock. A solo genesis lifts the limit
  on how far a timestamp may advance past its parent's
  (`timestamp_step_secs`, five seconds on other deployments), which would
  otherwise leave an idle or paused deployment further behind the clock at
  every block.

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

- One validator. A stopped or lost device stops the deployment until a
  backup takes it over with a term certificate; see
  [Terms and the active device](active-term.md).
- Running a second device as validator forks the deployment while the two
  cannot reach each other, and without `switching` for as long as both run;
  see [A second device](#a-second-device).
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
