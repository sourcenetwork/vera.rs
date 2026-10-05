# Native relationship keys

Native relationships use `relationship/v3/{policy_id}/v2/{resource_hex}/{object_hex}/{relation_hex}/{subject_digest}`. Field encodings are lowercase hexadecimal UTF-8 bytes. Separators cannot occur inside an encoded field, so object and relation prefixes are exact even for path-like identifiers. Policy IDs are the canonical generated policy IDs.

The subject digest is lowercase hexadecimal SHA-256 over `vera/acp-subject/v1` followed by one zero byte and the compact JSON encoding of the typed subject. The encoding uses the externally tagged variants `Entity`, `Wildcard`, `TypedWildcard`, and `EntitySet`. Entity-set fields are ordered `resource`, `object_id`, `relation`; typed wildcards carry `resource`. The digest replaces the shared engine's 64-bit storage hash. Changes to this canonical representation require a coordinated format upgrade.

The builders live in `vera_modules::acp::keys`; native permission, owner and relationship proof readers use those builders. The shared Zanzibar engine and Defra's own persisted storage format are unchanged. Callers must not construct native keys with `Relationship::storage_key()`.

The outer `v3` namespace accompanies atomic logical policy deletion. Old owner
readers derive a different prefix and find no current owner in fresh v3 state.
Updating only their key builder is insufficient: current readers must also verify
policy presence at the same finalized revision as the relationship evidence. Use
`PolicyPrefixResponse::verify_object_owner` or the policy-scoped page APIs in
[permission proofs](permission-proofs.md). Raw prefix evidence can contain records
awaiting cleanup and does not establish current ownership or access.

This release targets fresh state. Recovery rejects every relationship key outside
`relationship/v3/`, including mixed old/new state, and validates retained records
against their canonical keys. The optional JMT relationship index uses format 2;
older index markers are rejected. There is no automatic key migration or index
backfill. All validators and consumers must use matching formats.

Native genesis fingerprints remain `vera/native-genesis/v2` followed by one zero
byte and the serialized genesis configuration. This relationship cutover does not
change that fingerprint domain or the receipt/finality formats. Genesis records
and initialization intents predating the v2 fingerprint remain incompatible.
