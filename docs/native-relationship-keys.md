# Native relationship keys

Native relationships use `relationship/v4/{policy_id}/{target:016x}/{subject:016x}/v2/{resource_hex}/{object_hex}/{relation_hex}/{subject_digest}`. Field encodings are lowercase hexadecimal UTF-8 bytes. Separators cannot occur inside an encoded field, so object and relation prefixes are exact even for path-like identifiers. Policy IDs are the canonical generated policy IDs.

The subject digest is lowercase hexadecimal SHA-256 over `vera/acp-subject/v1` followed by one zero byte and the compact JSON encoding of the typed subject. The encoding uses the externally tagged variants `Entity`, `Wildcard`, `TypedWildcard`, and `EntitySet`. Entity-set fields are ordered `resource`, `object_id`, `relation`; typed wildcards carry `resource`. The digest replaces the shared engine's 64-bit storage hash. Changes to this canonical representation require a coordinated format upgrade.

The builders live in `vera_modules::acp::keys`; native permission, owner and relationship proof readers use those builders. The shared Zanzibar engine and Defra's own persisted storage format are unchanged. Callers must not construct native keys with `Relationship::storage_key()`.

The outer `v4` namespace binds each record to its target relation generation and
its userset subject generation. Surviving names retain their identities; removed
and recreated names receive new identities. Both generation fields use fixed-width
lowercase hexadecimal. Object ownership uses the permanent pair `(0, 0)`.
See [policy edits](acp-policy-edits.md) for catalog, index and cleanup semantics.

Readers verify policy presence and the generation catalog at the same finalized
revision as the relationship evidence. Updating only a key builder is insufficient.
Use `PolicyPrefixResponse::verify_object_owner`, verified permission evaluation or
the policy-scoped page APIs in [permission proofs](permission-proofs.md). Raw prefix
evidence can contain retired records and does not establish current access.

`relationship_generation_key` and `relationship_generation_prefix` build arbitrary
current relation keys from a validated pair. The older-shaped `relationship_key`
and `relationship_storage_prefix` helpers select only the permanent owner pair;
they must not be used to derive keys for other relations.

This release targets fresh state. Recovery rejects every relationship key outside
`relationship/v4/`, including mixed old/new state, and validates retained records
against their canonical keys and generation bindings. The optional JMT relationship
index uses format 3; older index markers are rejected. There is no automatic key
migration or index backfill. All validators and consumers need matching formats.

Native genesis fingerprints remain `vera/native-genesis/v2` followed by one zero
byte and the serialized genesis configuration. This relationship cutover does not
change that fingerprint domain or the receipt/finality formats. Genesis records
and initialization intents predating the v2 fingerprint remain incompatible.
