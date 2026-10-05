# Native relationship keys

Native relationships use:

```
relationship/v5/{policy_id}/{target:016x}/{subject:016x}/v3/{resource_hex}/{object_hex}/{incarnation:016x}/{relation_hex}/{subject_digest}
```

Resource, object and relation fields are lowercase hexadecimal UTF-8 bytes.
Separators cannot occur inside an encoded field, so prefixes are exact even for
path-like identifiers. Policy IDs are the canonical generated policy IDs. Relation
generations and the target object's incarnation use fixed-width lowercase hex.

The subject digest is lowercase hexadecimal SHA-256 over `vera/acp-subject/v1`
followed by one zero byte and compact JSON for the typed subject. Its externally
tagged variants are `Entity`, `Wildcard`, `TypedWildcard`, and `EntitySet`.
Entity-set fields are ordered `resource`, `object_id`, `relation`; typed wildcards
carry `resource`. Changes to this representation require a coordinated format
upgrade.

The builders live in [`vera_modules::acp::keys`](../crates/vera-modules/src/acp/keys.rs).
`relationship_storage_key` and `relation_prefix` require an explicit incarnation.
`object_prefix` covers every physical incarnation; `object_incarnation_prefix`
selects one. `relationship_generation_key` and `relationship_generation_prefix`
select a validated relation pair. `relationship_key` and
`relationship_storage_prefix` select only the permanent owner pair `(0, 0)`;
owners also always use incarnation zero. Callers must not use the shared engine's
`Relationship::storage_key()` to construct native keys. Defra's own persisted
relationship format is unchanged.

`PolicyRecord.relations` binds target and userset relation generations. Surviving
names keep their identities; removed and recreated names receive new identities.
The mandatory `RelationshipRecord.incarnation` must match its primary key. A
non-owner grant is current only when both relation identities and its target
object incarnation are current. Owners retain their stable zero key across
archive, unarchive and transfer.

[`object_state`](../crates/vera-modules/src/acp/object_state.rs) stores points at
`object_state/{policy_id}/{resource_hex}/{object_hex}`. A present value is a
positive eight-byte big-endian counter. Proven absence means initial zero; a
missing proof is an error. This point does not establish registration or ownership.
Archive advances the counter with checked arithmetic, invalidating outgoing grants
without moving the owner. Unarchive does not restore previous incarnations.
See [policy edits and archive](acp-policy-edits.md) for counts and cleanup.

Readers authenticate policy liveness, relation generations and needed object
points at the same finalized root as the relationships. Use verified permission
evaluation, `PolicyPrefixResponse::verify_object_owner`, or the policy-scoped
page APIs in [permission proofs](permission-proofs.md). Raw storage evidence can
contain obsolete grants and does not establish current access.

This format targets fresh state. Restoration rejects relationships outside
`relationship/v5/`, missing incarnation fields, mismatched keys and invalid state
or indexes. The optional JMT cardinality index uses format 4. There is no legacy
dual reader, automatic migration or index backfill. Validators and consumers need
matching keys and proof verification; updating key builders alone is insufficient.

Native genesis fingerprints remain `vera/native-genesis/v2` followed by one zero
byte and the serialized genesis configuration. This cutover does not change that
domain or receipt/finality formats. Genesis records and initialization intents
predating the v2 fingerprint remain incompatible.
