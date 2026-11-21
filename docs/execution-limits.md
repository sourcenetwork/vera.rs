# Execution limits

`VeraExecutor` enforces one cumulative execution budget for each revision, using
`Header::gas_limit`. Native requests execute first, followed by EVM requests;
both paths share the same remaining budget. Admission and block verification
accept only native requests, so a node's blocks carry no EVM requests.

## Admission and accounting

Before dispatch, a native request must fit its full 1,000,000-unit execution
allowance. An EVM request must fit its signed gas limit. Successful native
requests charge the module-reported cost; EVM requests charge the execution
result. Unused allowance remains available to subsequent requests.

During proposal construction, a request whose allowance does not fit is omitted
before changing its sequence, module state or account state. Its index is absent
from `ExecutionOutcome::executed_tx_indices`, so it is absent from the proposed
revision and does not become finalized through that proposal. Normal mempool
admission, revalidation and eviction rules still apply. Proposal verification
rejects a revision containing a request that cannot fit.

Admission rejects an EVM request whose signed gas limit exceeds the configured
revision limit, or whose gas cost plus value overflows, since no revision can
hold it. Blob (type 3) requests are refused at admission and execution. Revalidation after finalization replays each sender's retained EVM
requests in admission order, so a queued follow-up keeps its nonce and balance
reservation. Construction also lists in `ExecutionOutcome::rejected_tx_indices`
the EVM requests that do not decode or that fail transaction validation for a
reason other than a nonce ahead of the account, and the proposer removes them
from its pending pool. It then rebuilds the EVM reservations from the requests
that remain, so the sender of a removed request can resubmit at the same nonce
without waiting for the next finalized revision. A request omitted for the budget, or for a nonce that is
still ahead, stays pending.

A native request a module refuses is charged the gas the call reported, and at
least 5,000 units, the base charge of a module write. This covers a
module-reported revert, a reverted batch, an undecodable or unknown call and an
argument out of bounds. Methods with fixed charges report no usage when they
refuse, and budgeted methods report the work they completed, so a refusal costs
no less than the cheapest successful write and no more than the work it did. A
call that exhausts its allowance, and a module panic, are charged the full
1,000,000 units. The receipt names the refusal's kind, which tells an exhausted
allowance (`out_of_gas`) from a refusal of what the caller sent; see
[receipt commitments](receipt-commitments.md#refusals). Module and journal
changes roll back, while the accepted request consumes its signing sequence.
Invalid native authentication or sequence does not produce a failure receipt:
construction omits that request, and verification rejects it. Fatal execution
errors abort execution of the revision.

Admission still requires the full allowance to fit before dispatch, so a
refusal cannot overrun the revision budget. Charging a refusal what it used
lets more refused requests fit in one revision than the earlier full charge
did: a signer can now spend a revision's budget on refused requests at the
rate it could already spend it on successful ones. Native requests carry no
fee, so the budget, not a price, bounds this work in both cases.

Accounting uses checked arithmetic. A receipt cannot charge more than its
request allowance, and cumulative usage cannot exceed the revision limit.
Receipts retain both individual and cumulative usage. Their authenticated
encoding is described in [receipt commitments](receipt-commitments.md).

For example, with a 1,000,000-unit revision limit, a successful or refused
native request charged 5,000 leaves 995,000. Another native request cannot fit its full
allowance. In a deployment permitting EVM execution, a request declaring at
most 995,000 can still execute.

## ACP string-array decoding

Before owned ABI decoding, `checkAccess` and `verifyAccessRequest` accept at most
64 entries in each parallel string array; `generateCommitment` accepts at most
256. Parallel arrays must have equal lengths. The 64-entry ABI cap is new for
`verifyAccessRequest`, matching persisted decisions and default permission
proofs; commitment generation already has a 256-object limit.

Strings in these three calls share the existing decoded-byte budget with all
nested batch payloads. Every occurrence counts separately, including aliased arrays or tails,
the actor string, and UTF-8 replacement bytes produced by the permissive decoder.
Validation borrows the input and rejects invalid heads, offsets and lengths
before owned arrays or strings are allocated. Failures use the existing native
and EVM error and rollback paths.

## Native record bounds

Module changes must fit the native storage codecs: keys at most 64 KiB and
values at most 1 MiB. Limits apply to stored encodings, so an input that fits the
request-size limit can still produce an oversized key or value. For example,
relationship keys contain hexadecimal encodings of object identifiers.

Before accepting a successful native dispatch, execution checks changed records
against its pre-dispatch snapshot. Oversized records produce an ordinary failed
receipt naming `storage_bounds`: module and account-journal effects and logs
are discarded, the native sequence is consumed, and the request is charged what
the call reported using, since it ran to completion.
Subsequent requests can execute with the remaining revision budget. Optional EVM
module calls perform the same check before returning success; an oversized write
fails that call and follows its existing call-frame rollback semantics.

Validation borrows the persistent maps' changed entries, including changes across
nested batch snapshots. It does not copy record payloads or scan unchanged state.
The storage backend retains its own checks as a final invariant. These bounds do
not replace limits on decoding, temporary allocations or aggregate module work.

## Scope

These units enforce the dispatch accounting contract; they are not elapsed
time, allocated bytes or a throughput guarantee. Several module operations
still have fixed charges even when their work grows with stored data. Native
signature authentication precedes dispatch accounting, and revision maintenance
runs outside individual request allowances. Wire-size, operation-count, proof
and query limits provide separate bounds. See [ACP v1](acp-v1.md) for policy
lifecycle costs and remaining limitations.

Budget admission and failed-dispatch charging are consensus execution rules.
Every validator in a deployment must use matching rules and configuration;
mixing versions can produce different selected operations and receipts. The
native request wire format is unchanged.
