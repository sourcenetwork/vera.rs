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

## Switching the active device

An embedded node switches when its configuration names the account's devices:

```rust
let mut config = EmbeddedConfig::adopt(data_dir, deployment, p2p_listen)?;
config.switching = Some(Switching::new(device_key, vec![Device { key, address }]));
```

`Switching::device_key` is this device's transport key (`DeviceKey`). It is
the device's name in term certificates, and its network key while it is a
backup. `Switching::devices` lists every other device with the address its
consensus listener has while that device is active. The active device admits
each listed device as a backup, in addition to `EmbeddedConfig::backups`.

A device that switches holds its key material in the host
([adopted](embedded-node.md#key-material-held-by-the-host)): a backup's
directory must not hold a validator key or share, so a node that keeps them in
files is refused with `TermRefusal::KeysInFiles`.

A switch changes a device's role, and a role is fixed for the life of a node,
so `take_over` and `follow` stop the node and start another in its place, in
the same directory. They take `&mut self`: `rpc()` afterwards returns the new
node's method table, and clones taken before end with `LocalRpcError::Stopped`.
`EmbeddedConfig::activated` and `EmbeddedConfig::following` build the same
configurations for a host that starts a device after it already switched.

### Announced handover

The active device hands over when it is about to quit or sleep and a backup is
connected and current.

```rust
let change = active.hand_over(&successor_key).await?;   // on the active device
let certificate = TermCertificate { change, approvals }; // approved by the operators
backup.take_over(keys, certificate.clone()).await?;      // on the successor
active.follow(certificate).await?;                       // on the device that handed over
```

`hand_over` holds back new proposals, waits up to two seconds for the blocks
already proposed to finalize, and asks the successor where it stands until it
reports that block as its newest, for up to `Switching::answer_timeout`
(3 seconds by default). That block is the change's cut, so the new term loses
nothing. A successor that is not connected or not current fails the call with
`TermRefusal::SuccessorNotCurrent` and the device goes on as before.

The announcement is stored in `term.json`. From then on the device proposes
nothing, also after a restart: a start as the active device fails with
`TermRefusal::HandedOver`. It follows the successor (`follow`, or a start with
`EmbeddedConfig::following`), or the host calls `resume` when no certificate
was issued. Only the host knows whether the successor received one; resuming
after it did forks the deployment. A proposal that was held back is not
answered when the hold is lifted, so the first block after `resume`, or after
a refused handover, can be late by the leader timeout.

The node signs nothing in a handover. With an operator policy of one key that
the host can use unattended, the host signs the change itself and the
handover needs no user. A policy that requires a key behind user presence
needs the user for a handover too.

### Confirmed takeover

Without a handover, a backup takes over only when the user confirms it on
that device.

```rust
let change = backup.takeover_change().await?;            // next term, this device, its newest block
let certificate = TermCertificate { change, approvals };
backup.take_over(keys, certificate).await?;
```

The cut is the backup's own newest block. Whatever the active device
finalized and this backup never received is above the cut and void in the new
term; the host shows the user how old the backup's newest block is before the
operators approve.

`take_over` checks the certificate against the operator policy in the
backup's own state, that it names this device, that its term is above every
term the device holds or has seen in a block, and that the device's newest
block is exactly the cut. For the final block of a handover it waits up to
`Switching::answer_timeout`. A refusal leaves the backup running.

The accepted certificate is stored before the node restarts. The device then
starts as the validator and checks once more that it holds no block above the
cut, in its history or in its consensus archive. One can arrive from an
active device that was still running while the cut was chosen. In that case
the takeover is abandoned with `TermRefusal::NotAtCut`, the certificate is
dropped, and the device starts as a backup again with
`EmbeddedConfig::following`; a new takeover names the later block.

### What a device stores

`term.json` in the data directory holds the newest certificate the device
verified, an announced handover, a takeover it accepted and has not started
under, and whether its consensus journal holds votes it cast as the
validator. None of it is secret.

- A start as the active device is refused with `TermRefusal::Superseded` when
  the stored certificate names another device, and with
  `TermRefusal::Behind` when the device's newest block is in a later term
  than it holds.
- A validator journals its own votes, and Commonware refuses to replay votes
  under a key the node no longer signs with. A device that validated drops
  the vote journal of its epochs when it next starts as a backup. Finalized
  blocks and state are kept.

### The epoch a device activates in

A backup watches each epoch's resharing ceremony as an observer: its journal
records the validator's dealer log and none of the dealing a player keeps. A
backup that becomes the validator after the epoch's midpoint therefore ends
that ceremony without a share, and Commonware registers the next epoch's
scheme for it as a member that cannot sign. The deployment used to stop at
the epoch's last block.

A lone validator's share is the same in every epoch, so the node now signs
with the share its host holds whenever the epoch's public sharing confirms
it. No dealing is copied between devices. This holds for one validator only,
like the [host-held share](embedded-node.md#the-share-after-the-first-epoch).

### What other devices and clients see

- `EmbeddedNode::term()` is the term the device holds, and
  `term_certificate()` the certificate of that term. `vera_getTermCertificate`
  returns the certificate over RPC, and `VeraClient::term_certificate`
  fetches it.
- Devices ask each other where they stand on p2p channel 17: a question, and
  an answer with the newest block and the newest certificate. The active
  device uses it to confirm a successor is current.
- A backup that holds a certificate refuses a finalized block above the cut
  in a lower term: such a block comes from a device that was replaced. The
  node stops with `TermRefusal::LowerTerm` before the block reaches
  execution. The block stays in its consensus archive.

A block that raises the term carries no certificate. A re-executing node
accepts any term at or above its parent's; it requires a certificate only to
change its own role and to refuse lower terms. A client that must not follow
a device holding the validator key without the operators' approval checks the
certificate itself, as [Verifying one](#verifying-one) describes.
