# vera-client

Rust client for a Vera node over JSON-RPC. It provides native transaction,
administration and certified query APIs. Configure consensus trust independently
of the endpoint when verifying certified responses.

## Installation

```toml
[dependencies]
vera-client = "0.1.2"
```

See the [API documentation](https://docs.rs/vera-client) and
[Vera repository](https://github.com/sourcenetwork/vera.rs) for details.

## License

Licensed under the MIT license. See the included license file.

This crate depends on [`orbis-reporting`](https://crates.io/crates/orbis-reporting),
which is licensed under the Business Source License 1.1. Its terms restrict
managed-service use and change to Apache 2.0 on March 13, 2030; review them
before use.
