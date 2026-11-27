# vera-identity

Identity types shared by Vera's Rust client and access-control libraries.

## Usage

```toml
[dependencies]
vera-identity = "0.2.0"
```

```rust
use vera_identity::Did;

let actor = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")?;
assert!(actor.key_portion().is_some());

let wildcard = Did::wildcard();
assert!(wildcard.is_wildcard());
# Ok::<(), vera_identity::Error>(())
```

`Did` accepts `did:key:` identifiers, `did:opk:` provider identifiers and
`did:emailhash:` email-hash identifiers. It also provides a wildcard subject
for access-control relationships. Parsing a `did:key:` checks its prefix; it
does not validate the encoded key. Parsing `did:opk:` or `did:emailhash:`
checks the identifier's representation; it does not authenticate the provider
or email claim. Verify keys, signatures and claims separately before using an
identity as proof of authority.

## License

Licensed under either Apache License 2.0 or MIT, at your option. See the included
license files.
