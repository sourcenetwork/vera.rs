# Delegated policy creation and editing

A policy actor can authorize a signing worker to create or edit policies. The
worker signs the native submission; the actor remains the policy owner. Each
worker has its own submission sequence.

Delegations are signed tokens with a worker DID in `sub`, deployment in `aud`,
and explicit validity times. The issuer is a `did:key`, and its key type fixes
the algorithm the token header must name:

| Issuer key | `did:key` multicodec | `alg` | Signature |
|---|---|---|---|
| secp256k1 | `0xe7` | `ES256K` | 64-byte `r \|\| s` over SHA-256, low `s` |
| Ed25519 | `0xed` | `EdDSA` | 64-byte signature over the signing input |
| P-256 | `0x1200` | `ES256` | 64-byte `r \|\| s` over SHA-256, low `s` |

A token naming another key type's algorithm is rejected. Token records and
revocation are keyed by the token hash, so each signature has one accepted
encoding: a high-`s` ECDSA signature and a non-strict Ed25519 signature are
rejected, as are small-order Ed25519 keys.

A secp256k1 issuer uses Base58BTC (`z`) or unpadded Base64URL (`u`), with a
compressed or uncompressed public key. Vera generates canonical Base58BTC
identifiers and compares the underlying key for issuer revocation; stored actor
identifiers are not rewritten. Older builds accepted additional multibase
encodings when decoding keys. Those encodings are not accepted by this version,
so replace them before upgrading.

Ed25519 and P-256 issuers have exactly one spelling: Base58BTC over the
multicodec and the 32-byte Ed25519 key or the 33-byte compressed P-256 point.
Policy ownership is compared as a DID string, so any other spelling of these
keys is rejected instead of becoming a second actor. `vera_crypto::actor`
derives the DID from a public key.

`UnsignedToken` in `vera-client` builds a delegation or operation token for a
key the library cannot hold, such as a hardware-backed key. The caller signs
`signing_input()` and completes the token with `finish` (raw signature) or
`finish_der` (ASN.1 DER ECDSA, as platform key stores return it). Either ECDSA
`s` is accepted and normalized, and a signature the issuer's key did not make
over that token is refused locally. The secp256k1 helpers below are unchanged.

The supported scopes are separate:

| Scope | Authorized operations |
|---|---|
| `acp:policy` | Existing object registration, archival and relationship commands |
| `acp:policy:create` | Create policies owned by the token issuer |
| `acp:policy:edit` | Edit policies already owned by the token issuer |
| `acp:access:record` | Record granted access for the requested target actor |

`create_bearer_token` retains the existing command scope.
`create_scoped_bearer_token` accepts `DelegationScope::CreatePolicy` or
`DelegationScope::EditPolicy` for lifecycle operations. A creation token cannot
edit policies, and an existing command token cannot create or edit them.

Creation, editing and validation compile YAML and JSON through the same policy builder and
check permission references before accepting a definition. Failed compilation
leaves the policy counter, stored records and evaluation cache unchanged.
Malformed or exhausted counter state rejects creation.

Policy definitions use strict YAML or JSON, bounded to 64 KiB. Unknown fields, duplicate
names, invalid identifiers and unresolved references are rejected. `description`,
resource descriptions, relation/permission `doc`, and `meta` entries are retained
in compiled policy records. User metadata is separate from the policy description.
Expressions are limited to 128 levels of nesting.

The optional `actor.relations` namespace contains roles on DID-addressed actor
records. Policy creators and declared managers control those roles. Actor records
cannot be registered as ordinary objects, so registration cannot grant control
of another identity's roles. Actor usersets participate in permission evaluation;
an actor object subject without a relation denotes that identity directly.

`spec: defra` requires `read` and `write` permissions on every resource and
makes write access grant read access. Specification names are case-insensitive;
unknown names are rejected. An omitted specification or `spec: none` selects
ordinary permission evaluation when creating a policy. Edits retain the stored
specification even when the replacement definition omits it or names another.
Records without a stored specification retain ordinary permission evaluation.

Edits preserve resource types, policy identity and original creation metadata.
Removing a relation prunes its stored relationships. Malformed relationship
records or records whose policy/key bindings differ abort the edit before any
pruning. Caller operation retries retain the original result after later edits;
see [operation-identities.md](operation-identities.md).

The shared ACP interface accepts:

```text
bearerCreatePolicy(bearerToken, policy, marshalType)
bearerEditPolicy(bearerToken, policyId, policy, marshalType)
```

`marshalType = 1` selects YAML; `marshalType = 2` selects JSON with the same policy fields. These calls can be
encoded as native submission payloads and sent through `vera_sendNativeTx`.
Every consensus member must run a version supporting the new calls and scopes
before operators enable their use.

Creation returns a policy record and emits `DelegatedPolicyCreated`, containing
the actual 32-byte policy ID and actor DID. The stored policy metadata records
the actor as owner, the authenticated worker as signer, the signed submission
ID, and the creation revision and timestamp. Editing preserves that creation
metadata and enforces the actor's ownership and existing policy-edit rules.

`vera_getReceiptProof` returns the finalized revision and its complete ordered
receipt commitment. `VeraClient::read_receipt` verifies the certificate against
configured trust, the receipt commitment and the locally computed signed
submission ID. This authenticates success or failure and emitted events. A
missing response means evidence is unavailable; it does not permit reusing the
submission sequence. The older `vera_getTransactionReceipt` response by itself
does not authenticate execution.

Use the policy ID from the verified creation event to obtain the current record
from `vera_getCurrentRecordProof` using `policy/objs/<policy-id>` in the ACP
namespace. Verify its certificate and record proof, then compare the policy ID,
owner, worker, signed submission ID, definition and creation revision with the
request. This lets concurrent creators identify their own policies without
scanning the policy list. A historical receipt proves execution at that
revision; current permission checks still require current evidence.

Execution checks the exact scope, caller, deployment, validity interval and
revocation before applying a change. Failed operations do not record delegation
usage. The actor or the bound worker can revoke a token through
`revokeDelegation`; revocation applies to that token, including after restart.

## Provider actors and authorized relays

Operators can authorize a relay to attest stable provider actors through
`AdministrativeCommand::SetRelay`. It requires the existing operator quorum,
exact genesis identity and next administrative sequence. A grant contains a
canonical compressed secp256k1 issuer DID, an ordered set of scopes and an
expiry. No relay is authorized by default. `RevokeRelay` removes the grant;
replacement installs a new generation identified by its administrative sequence.
Old assertions cannot become valid again after replacement or reauthorization.

A relay performs provider authentication before signing. The native service
verifies the relay's assertion against committed authority; it does not fetch
OIDC keys during execution. The relay is trusted to attest provider identities
within its granted scopes. Operators must provision this authority explicitly.

`create_relay_token` signs ES256K claims with type `vera-relay-v1+jwt`; relay
issuers are secp256k1 keys only. Standard
native delegation claims still bind the issuer, worker, deployment and scope.
An additional `relay` object contains:

| Field | Meaning |
|---|---|
| `actor` | Stable `did:opk:` actor followed by 64 lowercase hexadecimal digits |
| `genesis_id` | Exact 32-byte genesis identity, encoded as an integer array |
| `grant_sequence` | Administrative sequence that installed the active grant |
| `operation` | 32-byte operation commitment, encoded as an integer array |

Assertions must have `nbf == iat`, last at most 600 seconds and expire no later
than the grant. Expiry is exclusive. A relay assertion cannot use the direct
actor-token type, or grant authority to a `did:key` actor. Direct key delegations
remain separate. The worker and issuer may revoke individual assertions through
`revokeDelegation`; operators can revoke the relay's entire grant.

The operation commitment is SHA-256 of `vera/acp-operation/v1\0` followed by
compact UTF-8 JSON from `DelegatedOperation`. Its externally tagged variants are
`CreatePolicy: [definition, format]`, `EditPolicy: [policyId, definition, format]`
`PolicyCommand: [policyId, command]` and `CheckAccess: [policyId, request]`. The JSON has no whitespace outside
strings; strings use serde JSON escaping, fields retain declaration order, and
formats use their enum names such as `ShortYaml`. Graph commands use the typed
`PolicyCmd` representation. Access requests contain ordered `operations` followed
by `actor`; each operation contains `object` (`resource`, `id`) and `permission`. The service decodes and serializes these typed
arguments before checking the commitment. Equivalent transport whitespace does
not alter the operation; changing its semantic arguments does.

ACP records retain the provider actor as owner and the native worker as
submitter. Token lifecycle records retain the relay key as issuer, so revocation
continues to require a signing identity. Provider identity parsing validates its
representation and never supplies a public key or establishes authentication.
Clients reading these records must support provider actor identifiers.

`relay/v1/<canonical-issuer-did>` in the Vera namespace stores the Borsh-encoded
`RelayState`. Read it through the native current-record proof endpoint and
verify independent consensus trust and freshness before relying on the grant.
A relay assertion is operation-bound but is not a caller idempotency key;
separately signed submissions of the same operation may execute more than once.

Caller operation IDs add bounded cross-worker idempotency to these delegated
methods. The signed request claim binds the exact operation and genesis, and
retries return the original successful outcome. See
[operation-identities.md](operation-identities.md) for deadlines, resource
budgets, verification and recovery semantics.

`VeraClient::read_relay_grant` verifies an issuer's operator grant against independently
configured consensus trust and a caller-selected minimum revision. It returns
scopes, expiry and grant generation, or certified absence before authorization or
after revocation. Expired grants may remain stored; presence alone does not
authorize an assertion. Consumers still check its scope, generation and lifetime.

Operators can inspect the same certified grant from the CLI:

```sh
verad client --url "$VERA_URL" vera relay-grant "$RELAY_ISSUER" \
  --trusted-key "$VERA_TRUSTED_KEY" --minimum-revision "$MINIMUM_REVISION"
```

The trust key comes from authenticated deployment configuration. Output includes
`revision`, `timestamp`, and `grant` (null for certified absence). Select a minimum
revision appropriate to the operator's freshness requirements; the default is zero.
