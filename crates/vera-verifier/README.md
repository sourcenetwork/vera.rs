# vera-verifier

Native policy compilation and proof verification for Vera, including a
C-compatible API. Verification requests must use independently configured trust
rather than trust supplied by the queried endpoint.

## Installation

```toml
[dependencies]
vera-verifier = "0.1.2"
```

See the [API documentation](https://docs.rs/vera-verifier) and
[Vera repository](https://github.com/sourcenetwork/vera.rs) for details.

## License

Licensed under the MIT license. See the included license file.

This crate depends on [`orbis-reporting`](https://crates.io/crates/orbis-reporting),
which is licensed under the Business Source License 1.1. Its terms restrict
managed-service use and change to Apache 2.0 on March 13, 2030; review them
before use.
