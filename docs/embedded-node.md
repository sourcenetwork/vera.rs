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
requests. It can be awaited from any async runtime.

## Deployment identity

`SoloGenesis` fixes the deployment when its directory is first used:

- `operators` is the account's administrative policy. It, not the device's
  validator key, is the authority for later administrative changes.
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

Transport limits do not apply in-process: request-size checks, batch limits
and per-connection subscription limits belong to the network server.

Set `EmbeddedConfig::rpc_listen` to also serve the same methods over the
network. It is off by default.

## Threads and shutdown

The node runs on a dedicated thread with its own Commonware runtime, and that
runtime owns its worker threads. The host's runtime is not used.

`stop` ends the node and waits for its thread. Stopping drops the runtime
without a separate shutdown protocol, so durability relies on the same recovery
path as an interrupted daemon. Dropping an `EmbeddedNode` requests the same stop
without waiting.

`failed` resolves if the node stops by itself. An embedded node never exits the
host process: the finality watchdog stops the node with an error instead.

## Files and ports

Everything is under `EmbeddedConfig::data_dir`: `validator.key`, `secrets.json`,
`solo-genesis.json`, `native-genesis.bin`, `commonware/` and
`history/regolith/`. The directory must not be shared with another store; a host
that also embeds DefraDB gives each its own directory.

A single validator dials no peers, but the consensus network still binds
`p2p_listen`. Use a loopback address unless other validators must reach it.

## Limits

- One validator. A stopped or lost device stops the deployment.
- Idle deployments keep producing empty blocks at the pipelined cadence.
- Resource use is that of a validator; it has not been measured for embedded
  hosts.
