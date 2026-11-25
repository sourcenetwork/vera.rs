# Caller operation identities

Delegated ACP creation, editing, graph commands, ordered graph-command lists and
access-decision recording accept an optional signed `request` claim; revocation
of a token by its issuer requires one. It binds a caller operation ID, exact semantic operation digest
and genesis identity. Direct key delegations and operator-authorized relay
assertions use the same execution path. All members must support this claim
before clients use it; older members reject unknown claims.

An operation ID contains 32 bytes: an eight-byte big-endian Unix expiry followed
by 24 bytes of caller-generated entropy. Expiry is exclusive and can be at most
600 seconds ahead of execution time, or the deployment's policy-command lead for
graph commands and command lists (see [long-lived policy commands](#long-lived-policy-commands)).
Empty entropy is rejected. The full ID,
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

Outcome records are at most 1 MiB. Outcomes count against one of two encoded
budgets, chosen when the identity is claimed: an identity with more than 600
seconds left before its deadline at execution is long-lived, any other is
short-lived. Each budget defaults to 64 MiB and is changed through the existing
operator quorum, with `{"SetOperationBudget":268435456}` for short-lived outcomes
and `{"SetLongOperationBudget":268435456}` for long-lived ones. A budget below
1 MiB or below its class's retained usage is rejected without advancing the
administrative sequence. A new outcome exceeding its class's budget reverts
atomically; existing outcomes remain available, and a full budget of one class
does not refuse outcomes of the other. Keys and index structures add memory and
storage overhead beyond this encoded-value budget.

## Long-lived policy commands

A change recorded now and submitted later, such as an access change a client owes
after its own transaction commits, needs an identity that outlives 600 seconds.
The deployment's policy-command lead is the longest an identity on an `acp:policy`
graph command or command list may lie ahead of execution time. It defaults to 600
seconds and is changed through the operator quorum with
`{"SetPolicyOperationLead":86400}` in an administrative request. A lead below 600
seconds or above 2,592,000 seconds (30 days) is rejected without advancing the
administrative sequence. Creation, editing, decision recording and Orbis
operations keep the 600-second lead whatever the deployment sets.

The lead is compared with an identity's remaining time at each execution, so an
identity issued under a longer lead is refused while its deadline lies further
ahead than the current lead, and becomes executable once it is within it. Lowering
the lead never makes a claimed or expired identity execute again: a claimed
identity returns its retained outcome, an expired one is refused, and records are
removed at their own deadlines as before. The token must remain valid until the
command executes, so an actor signs a direct operation token whose expiry reaches
the identity's deadline. A relay assertion still lasts at most 600 seconds, so a
relayed (`did:opk`) owed command needs a fresh relay assertion carrying the same
claim when it is submitted.

A long-lived outcome counts against the long-lived budget until its deadline, and
cleanup removes records of both classes in deadline order under the same bound,
releasing each from the counter it was charged to; lowering the lead does not
change a retained outcome's class. Separate budgets keep long-lived outcomes from
starving short-lived ones and the reverse, but an actor who can submit delegated
policy commands can still fill the long-lived budget, and new long-lived outcomes
then fail until those deadlines pass (at most the lead operators chose) or
operators raise that budget.

The ACP key `policy-operation-lead/v1` stores the lead as an eight-byte
big-endian count of seconds; absence means 600.
`VeraClient::read_policy_operation_lead` reads it with certified state.

## Command lists

`bearerPolicyCmds(bearerToken, commands)` applies an ordered list of one to 64
graph commands under one `acp:policy` authorization. `commands` is a JSON array
of `[policyId, cmd]` pairs, each policy ID 64 lowercase hexadecimal digits. Its
operation digest uses the typed `PolicyCommandList` operation in
[delegated-policies.md](delegated-policies.md#provider-actors-and-authorized-relays),
so a reordered, shortened, extended or altered list does not match a signed claim.
The commands execute in order as the token's actor; if any is refused the list
leaves no effect, token usage or outcome. A successful list stores one outcome
whose result is the ordered array of command results, and a retry returns it
whole. A list of one command and the single command are different operations.
Each command after the first pays the write base a separate call pays.

End-of-block cleanup removes at most 128 expired records, in deadline order.
It verifies each index's immutable ID deadline and updates the byte counter with
the deletions. Cleanup may lag expiration under pressure; it never permits an
expired ID to execute again. This lifetime applies to operation outcomes, not
historical authorization-state retention.

`acp::operation::operation_key(actor, id)` derives the native ACP key:
`operation/v1/ || SHA256("vera/operation-actor/v1\0" || canonical_actor) || id`.
`vera_getCurrentRecordProof` serves its membership or absence with certified state.
The short-lived budget and encoded-byte counter use `operation-budget/v1` and
`operation-bytes/v1`; the long-lived ones use `operation-long-budget/v1` and
`operation-long-bytes/v1`. All four are eight-byte big-endian integers. Each
expiry index entry holds the outcome key followed by one class byte, 0 for
short-lived and 1 for long-lived.

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
without relay authority. `create_operation_token_with_lead` and
`UnsignedToken::operation_with_lead` accept a deadline up to a lead the caller
names, beyond 600 seconds only for `acp:policy`; execution still applies the
deployment's lead. `PolicyOperation` builds the claims, digest and calldata of a
single graph command or a command list, with policy IDs spelled as the node
executes them. Set `JwtClaims.request` to the caller's operation ID,
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
