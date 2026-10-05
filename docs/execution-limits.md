# Execution limits

`VeraExecutor` enforces one cumulative execution budget for each revision, using
`Header::gas_limit`. Native requests execute first, followed by optional EVM
requests. Both paths share the same remaining budget. Pipelined deployments
accept only native requests.

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

Every failed native dispatch consumes the full 1,000,000 units, including a
module-reported revert and a reverted batch. Module and journal changes roll
back, while the accepted request consumes its signing sequence. Invalid native
authentication or sequence does not produce a failure receipt: construction
omits that request, and verification rejects it. Fatal execution errors abort
execution of the revision.

Accounting uses checked arithmetic. A receipt cannot charge more than its
request allowance, and cumulative usage cannot exceed the revision limit.
Receipts retain both individual and cumulative usage. Their authenticated
encoding is described in [receipt commitments](receipt-commitments.md).

For example, with a 1,000,000-unit revision limit, a successful native request
charged 5,000 leaves 995,000. Another native request cannot fit its full
allowance. In a deployment permitting EVM execution, a request declaring at
most 995,000 can still execute.

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
