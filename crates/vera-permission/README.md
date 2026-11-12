# vera-permission

Types and evaluation logic for replaying Vera access-control decisions against
supplied state evidence. Consumers must independently configure the trust
anchors used to authenticate that evidence.

## Installation

```toml
[dependencies]
vera-permission = "0.1.2"
```

See the [API documentation](https://docs.rs/vera-permission) and
[Vera repository](https://github.com/sourcenetwork/vera.rs) for details.

## License

Licensed under the MIT license. See the included license file.

This crate depends on [`orbis-reporting`](https://crates.io/crates/orbis-reporting),
which is licensed under the Business Source License 1.1. Its terms restrict
managed-service use and change to Apache 2.0 on March 13, 2030; review them
before use.
