# Caller operation identities

Delegated ACP creation, editing, graph commands and access-decision recording accept an optional signed
`request` claim. It binds a caller operation ID, exact semantic operation digest
and genesis identity. Direct key delegations and operator-authorized relay
assertions use the same execution path. All members must support this claim
before clients use it; older members reject unknown claims.

An operation ID contains 32 bytes: an eight-byte big-endian Unix expiry followed
by 24 bytes of caller-generated entropy. Expiry is exclusive and can be at most
600 seconds ahead of execution time. Empty entropy is rejected. The full ID,
including its expiry, must be persisted before submission and retained across
workers, gateway instances and retries. Identical arguments with different IDs
are independent operations.

The signed `request` object contains `id`, `digest` and `genesis_id`, each encoded
as a JSON array of exactly 32 byte values. `digest` uses the typed operation
encoding in [delegated-policies.md](delegated-policies.md). Token expiry cannot
exceed the ID's deadline. Normal caller, deployment, scope, relay grant and
revocation checks run before an existing outcome can be returned. The ID does
not bypass authorization.

The first successful execution stores its exact typed result, semantic digest,
actor, original worker, submission ID and creation revision atomically with its
effects and token usage. A later authorized request with the same actor, ID and
digest returns that original result without applying the effect again. Different
arguments under a completed ID are rejected. A result describes the completed
operation; it does not establish current ownership or permission after later
changes. Every accepted spelling of a secp256k1 actor's key shares one operation
namespace, and the outcome records the actor's canonical DID. Ed25519 and P-256
actors have a single spelling. The digest covers the arguments as the caller
wrote them: a retry may spell its issuer differently, but a DID inside the
arguments must be spelled as in the original request. See
[one actor per key](delegated-policies.md#one-actor-per-key).

Failed execution, result encoding, storage-budget checks and enclosing batch
reverts leave no completion record or partial effect. Only successful effects
claim an ID: failed requests can be corrected or retried within the deadline.
An expired ID always rejects execution, including after its record is removed.
Clients must never replace an expired or uncertain ID automatically to retry the
same intended operation.

Outcome records are at most 1 MiB. The total encoded outcome budget defaults to
64 MiB and is changed through the existing operator quorum with
`{"SetOperationBudget":268435456}` in an administrative request. A budget below
1 MiB or below currently retained usage is rejected without advancing the
administrative sequence. New outcomes exceeding the budget revert atomically;
existing outcomes remain available. Keys and index structures add memory and
storage overhead beyond this encoded-value budget.

End-of-block cleanup removes at most 128 expired records, in deadline order.
It verifies each index's immutable ID deadline and updates the byte counter with
the deletions. Cleanup may lag expiration under pressure; it never permits an
expired ID to execute again. This lifetime applies to operation outcomes, not
historical authorization-state retention.

`acp::operation::operation_key(actor, id)` derives the native ACP key:
`operation/v1/ || SHA256("vera/operation-actor/v1\0" || canonical_actor) || id`.
`vera_getCurrentRecordProof` serves its membership or absence with certified state.
The budget and encoded-byte counter use `operation-budget/v1` and
`operation-bytes/v1`, respectively, as eight-byte big-endian integers.

Clients verify the certificate, exact key, canonical actor, ID, digest, original
execution metadata and typed result. Lookup can recover an outcome without the original
worker's submission ID. A missing record after expiry is not proof that the
operation never ran. Receipt verification establishes the submitted attempt's
result; retries can have different submission IDs while referring to the same
original outcome. Neither a missing receipt nor a transport timeout establishes
rejection.

Decision recording requires `acp:access:record`; existing policy scopes do not
provide this authority. Its digest is the typed `CheckAccess(policy_id, request)`
operation. The caller namespaces recovery while the submitting worker remains
the decision creator. All requested permissions are evaluated during execution.
A successful retry returns the original decision even after grant removal or
decision expiry, provided the operation deadline and current relay authorization
still permit the retry. It never renews the decision. Fresh denied requests leave
no decision or outcome. Current reads expose issuance and expiry separately from
permission evaluation. All members must support the appended scope and call
before operators enable it.

Direct actors can use `create_operation_token` to sign an exact native request
without relay authority. Set `JwtClaims.request` to the caller's operation ID,
independently provisioned genesis identity and `DelegatedOperation::digest()` for
the intended command. The token binds the signing actor, worker, audience and
scope. The builder requires an operation claim, matching issuer, nonzero genesis,
valid ID deadline and a token lifetime within that deadline.

A different worker needs a newly actor-signed token naming that worker, while
retaining the same operation claim. Execution rejects substituted arguments and
returns the retained original outcome for an authorized retry. The operation ID
and expiry rules still apply after the outcome is pruned.

It uses the native JWT format and execution timestamps in seconds. Broad
scoped bearer tokens remain a separate delegation choice.
