# Certified read readiness

`verad probe` exits successfully only after observing two fresh, advancing,
cryptographically verified finalized revisions from one endpoint:

```sh
verad probe --url http://validator.internal:8545 \
  --genesis /etc/vera/genesis.json --minimum-height 12345 \
  --max-age-seconds 30 --timeout-seconds 10
```

Provision the genesis file independently from the endpoint being checked. The
probe takes its consensus key from that file's epoch-0 material. A key returned
by RPC cannot establish trust. The required checkpoint is an operator-supplied
positive revision; a node below it fails the probe. Both revisions must have
certified timestamps within the configured age, allowing at most five seconds
of future clock skew. Maintain a trustworthy local clock and advance the
checkpoint from authenticated observations as operational policy requires.

`VeraClient::verify_readiness` applies the existing bounded RPC transport and
finality verifier. Transport, proof, stale timestamp, regression and deadline
errors fail the check. Success must finish inside the overall deadline; bounded
synchronous proof verification is not preempted. No writes, worker keys or
membership changes are required. Success prints a single JSON report to stdout;
probe diagnostics use stderr. Validator and other command logging keeps its
existing stdout destination, including recovery and storage diagnostic events.

This qualifies serving fresh certified reads and observed consensus progress.
It does not prove that the particular endpoint participates in voting, holds its
current private share, or will remain available under quorum loss. Admission and
recovery qualification must still establish those properties separately.

The membership-under-load case checks positive readiness on all three surviving
replicas, rejects an independently different consensus key and zero bounds, and
invokes the actual CLI after membership changes. Timestamp boundary tests reject
stale, excessive future and extreme values. Qualification results must be tied
to the exact tested source before relying on the probe for deployment.
