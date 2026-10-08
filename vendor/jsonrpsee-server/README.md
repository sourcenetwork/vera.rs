# Vera transport patch

This directory vendors jsonrpsee-server 0.26.1 from crates.io, upstream commit
bcc84901f3c882f4233f293e5acf018643cbd412 (server/). Original source copyright and
MIT notices are preserved. The registry archive SHA-256 is
c01a2a627365144221ad5883ce2ea3953e152e29d102f2eeca8cbfc1be4bb286.

The change in src/transport/ws.rs replaces detached request tasks with a
connection-owned JoinSet. Its size is limited by message_buffer_capacity;
the receive loop waits for a task to finish before accepting another message.
The slot covers parsing, method execution and response enqueueing. On an
observed disconnect, outstanding tasks are aborted and joined. Server shutdown
retains graceful completion behavior. Response and ping writes have a ten-second
deadline; failed or timed-out writes terminate the connection. Closing the
socket has a one-second deadline so a non-reading peer cannot hold shutdown
open indefinitely. The receive loop observes writer termination, including
while dispatch is full, and releases the connection slot.

Vera uses a direct path dependency so downstream Git builds retain this patch.
The focused regression is vera-jsonrpc's websocket_dispatch_applies_backpressure.
Remove this fork when upstream provides equivalent dispatch and task ownership
bounds. The original README follows.

---

# jsonrpsee

[![GitLab Status](https://gitlab.parity.io/parity/mirrors/jsonrpsee/badges/master/pipeline.svg)](https://gitlab.parity.io/parity/mirrors/jsonrpsee/-/pipelines)
[![crates.io](https://img.shields.io/crates/v/jsonrpsee)](https://crates.io/crates/jsonrpsee)
[![Docs](https://docs.rs/jsonrpsee/badge.svg)](https://docs.rs/jsonrpsee)
![MIT](https://img.shields.io/crates/l/jsonrpsee.svg)
[![CI](https://github.com/paritytech/jsonrpsee/actions/workflows/ci.yml/badge.svg)](https://github.com/paritytech/jsonrpsee/actions/workflows/ci.yml)
[![Benchmarks](https://github.com/paritytech/jsonrpsee/actions/workflows/benchmarks_gitlab.yml/badge.svg)](https://github.com/paritytech/jsonrpsee/actions/workflows/benchmarks_gitlab.yml)
[![dependency status](https://deps.rs/crate/jsonrpsee/latest/status.svg)](https://deps.rs/crate/jsonrpsee)

JSON-RPC library designed for async/await in Rust.

Designed to be the successor to [ParityTech's JSONRPC crate](https://github.com/paritytech/jsonrpc/).

## Features
- Client/server HTTP/HTTP2 support
- Client/server WebSocket support
- Client WASM support via web-sys
- Client transport abstraction to provide custom transports
- Middleware

## Documentation
- [API Documentation](https://docs.rs/jsonrpsee)

## Examples

- [HTTP](./examples/examples/http.rs)
- [WebSocket](./examples/examples/ws.rs)
- [WebSocket pubsub](./examples/examples/ws_pubsub_broadcast.rs)
- [API generation with proc macro](./examples/examples/proc_macro.rs)
- [CORS server](./examples/examples/cors_server.rs)
- [Core client](./examples/examples/core_client.rs)
- [HTTP proxy middleware](./examples/examples/http_proxy_middleware.rs)
- [jsonrpsee as service](./examples/examples/jsonrpsee_as_service.rs)
- [low level API](./examples/examples/jsonrpsee_server_low_level_api.rs)
- [Websocket served over dual-stack (v4/v6) sockets](./examples/examples/ws_dual_stack.rs)

See [this directory](./examples/examples) for more examples

## Roadmap

See [our tracking milestone](https://github.com/paritytech/jsonrpsee/milestone/2) for the upcoming stable v1.0 release.

## Users

If your project uses `jsonrpsee` we would like to know. Please open a pull request and add your project to the list below:
- [parity bridges common](https://github.com/paritytech/parity-bridges-common)
- [remote externalities](https://github.com/paritytech/substrate/tree/master/utils/frame/remote-externalities)
- [polkadot-sdk](https://github.com/paritytech/polkadot-sdk)
- [substrate-api-client](https://github.com/scs/substrate-api-client)
- [subwasm](https://github.com/chevdor/subwasm)
- [subway](https://github.com/AcalaNetwork/subway)
- [subxt](https://github.com/paritytech/subxt)
- [Trin](https://github.com/ethereum/trin)
- [Uptest](https://github.com/uptest-sc/uptest)
- [zkSync Era](https://github.com/matter-labs/zksync-era)
- [Forest](https://github.com/ChainSafe/forest)

## Benchmarks

Daily benchmarks for jsonrpsee can be found:
- Gitlab machine: <https://paritytech.github.io/jsonrpsee/bench/dev2>
