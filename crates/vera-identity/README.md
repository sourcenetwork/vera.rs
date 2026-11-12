# vera-identity

Identity types shared by Vera's Rust client and access-control libraries.

## Usage

```toml
[dependencies]
vera-identity = "0.1.2"
```

```rust
use vera_identity::Did;

let actor = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")?;
assert!(actor.key_portion().is_some());

let wildcard = Did::wildcard();
assert!(wildcard.is_wildcard());
# Ok::<(), vera_identity::Error>(())
```

`Did` accepts `did:key:` identifiers and `did:opk:` provider identifiers. It
also provides a wildcard subject for access-control relationships. Parsing a
`did:key:` checks its prefix; it does not validate the encoded key. Parsing a
`did:opk:` checks the identifier's representation; it does not authenticate a
provider claim. Verify keys, signatures and provider claims separately before
using an identity as proof of authority.

## License

Licensed under either Apache License 2.0 or MIT, at your option. See the included
license files.
