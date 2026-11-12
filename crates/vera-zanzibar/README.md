# vera-zanzibar

A permission engine for Vera access-control policies. It evaluates relationships
and userset expressions, including unions, intersections and exclusions. Storage
is supplied through the `ZanzibarStore` trait; `MemoryZanzibarStore` is
available for in-memory use. Unresolved exclusions fail closed.

## Installation

```toml
[dependencies]
vera-zanzibar = "0.1.2"
```

See the [API documentation](https://docs.rs/vera-zanzibar) and
[Vera repository](https://github.com/sourcenetwork/vera.rs) for details.

## License

Licensed under either Apache License 2.0 or MIT, at your option. See the
included license files.
