# Terms and the active device

Every device of an account holds the deployment's validator key, so each of
them can finalize blocks that verify against the deployment's consensus key.
One device is active at a time. The term tells the blocks of one active device
apart from those of the device that replaced it.

## The term in a block

A block carries `term`, a 64-bit number, encoded after its timestamp. The
block identifier covers it, and so does the finalization certificate, which
signs that identifier. A deployment starts in term 0. `GossipHeader::term`
repeats the value for header subscribers.

A term never decreases along a chain: a block whose term is lower than its
parent's is invalid. `vera_domain::term_extends` is the rule.

- A proposer builds in the term it holds and builds nothing on a parent of a
  later term.
- A node refuses to vote for a candidate of a lower term than its parent.
- A finalized block is replayed without its parent, which may already be
  pruned or lie behind a snapshot. The node compares it with the finalized
  block it processed just before, when that is the block's parent. A certified
  block that fails the rule is not applied: Commonware's stateful actor panics
  on a finalized block its application refuses, which stops the node, exactly
  as for a certified block that does not reproduce its committed state.

Every block of a deployment that never switches its active device is in
term 0, and the rule never fails.

## The term certificate

A `TermCertificate` records a switch of the active device. It changes no key:
the blocks of the new term verify against the consensus key the deployment
already had. It is what tells a client, or another device, which chain to
follow when two devices finalized blocks at the same height.

```json
{
  "change": {
    "genesis_id": "0x<genesis block identifier>",
    "term": 1,
    "holder": "0x<transport key of the device active in the term>",
    "cut": {"height": 120, "block": "0x<identifier of the block the term builds on>"}
  },
  "approvals": [{"signer": 0, "signature": "0x<64 bytes>"}]
}
```

`cut` is the last block of the term before. Blocks above it in a lower term
are void, whoever certified them.

### Who signs

The deployment's operator policy approves a term change, as it approves an
administrative change. Each approval names an operator by its index in the
policy and carries that key's signature of `TermChange::signing_digest`:

```
SHA-256("vera/term/v1\0" || genesis_id || term || holder || cut.height || cut.block)
```

with both integers as 8 bytes, big-endian. The signature encoding is the one
[operator keys](consensus-membership.md#operator-keys) use for administrative
approvals: ECDSA keys sign the digest as the prehash with low `s`, and Ed25519
keys sign the 32 digest bytes as the message.

The certificate does not carry the policy. A certificate verifies when it
names the verifier's deployment, starts a term above 0, and lists at least the
policy's threshold of approvals, in ascending signer order, each of which
verifies; an approval that does not verify fails the certificate even when
enough others do. The same certificate therefore serves a policy of one key at
threshold 1 and a policy of an account key and a device key at threshold 2.
The node holds no operator key and signs no certificate: the host collects the
approvals. `approve_term`, `external_term_approval` and
`external_der_term_approval` in `vera-client` build them.

### Verifying one

- `TermCertificate::verify` in `vera-domain` checks the structure and calls
  back for each signature. It takes the policy's threshold and size.
- `vera_permission::verify_term_certificate` checks a certificate against an
  `OperatorPolicy`.
- `VeraClient::verify_term_certificate` reads the operator policy from
  certified state, as `read_administration` does, and checks the certificate
  against it. It returns the revision the policy was read at.
- The C verifier takes a `term_certificate` request; see
  [the native verifier](native-verifier.md).

The policy must come from state the verifier has authenticated. A verified
certificate says who may propose from its term on. It does not prove that its
cut is a finalized block; a verifier compares the cut with the blocks it has
accepted: `TermCertificate::keeps` says whether an accepted block survives the
switch, and `TermCertificate::admits` whether a block may carry a given term.
