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
(3 seconds by default, and below the leader timeout). A proposal is counted
from the start of its build until its height is recorded, so the block the
handover names is the last one this device handed to consensus. That block
is the change's cut, so the new term loses nothing. A successor that is not
connected or not current fails the call with
`TermRefusal::SuccessorNotCurrent`, blocks that do not finalize in time with
`TermRefusal::Unsettled`, and the device goes on as it was before the call:
proposing if it was, held if it was.

A device that already announced a handover refuses another with
`TermRefusal::HandedOver`, and one that another device replaced with
`TermRefusal::Superseded`. Neither call changes whether it proposes.

The announcement is stored in `term.json`. From then on the device proposes
nothing, also after a restart: a start as the active device fails with
`TermRefusal::HandedOver`. It follows the successor (`follow`, or a start with
`EmbeddedConfig::following`), or the host calls `resume` when no certificate
was issued, or `EmbeddedNode::resume_stopped(&config)` when the node is not
running: the host quit before the operators approved. Only the host knows
whether the successor received a certificate; resuming after it did forks
the deployment. Both are refused with `TermRefusal::Superseded` on a device
that holds a certificate naming another device. A device that started to
follow the successor meanwhile may still resume; if the successor did take
over, the start as validator fails with `TermRefusal::Behind` on the later
term of its blocks. A takeover the device later
accepts under a certificate naming it replaces the announcement. A proposal that was held back is not
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

`takeover_change` waits, up to `Switching::answer_timeout`, until the backup
has executed every finalized block its consensus archive holds, and fails
with `TermRefusal::NotAtCut` while it is still behind; the host asks again. A
cut below such a block would void a block the device is about to apply.

Marshal stores a block and its finalization certificate separately, and a
backup stopped between the two keeps the certificate of the block above its
newest one without the block. `takeover_change` and `take_over` wait for
that block, up to `Switching::answer_timeout`: while the active device is
reachable the backup fetches it, and the cut moves up to it. When the device
that built it is away the block never comes. The cut then stays below it,
the term voids it, and the start under the certificate removes its
certificate; see [Consensus storage across a switch](#consensus-storage-across-a-switch).

`take_over` checks that the certificate names this device, that its term is
above every term the device holds or has seen in a block, and that the
device's newest block is exactly the cut; for the final block of a handover
it waits up to `Switching::answer_timeout`. It then checks the certificate
against the operator policy in the backup's state at the cut. A refusal
leaves the backup running.

A backup's directory opens as the validator only this way. A start as the
active device in a directory that last ran as a backup, without a
certificate naming the device, fails with `TermRefusal::NotCertified`.

The accepted certificate is stored before the node restarts. The device then
starts as the validator and checks once more that it holds no block above the
cut, in its history or in its consensus archive, and no certificate of one
that arrived after its archive was cleared. One can arrive from an active
device that was still running while the cut was chosen. In that case the
takeover is abandoned with `TermRefusal::NotAtCut`, the certificate is
dropped, and the device starts as a backup again with
`EmbeddedConfig::following`; a new takeover names the later block.

### What a device stores

`term.json` in the data directory holds the newest certificate the device
verified, an announced handover, a takeover it accepted and has not started
under, the role consensus last opened its storage in, consensus storage a
start decided to clear and has not finished clearing, whether the device last
ran as a backup, and whether its stores must be taken again.
None of it is secret. Every embedded node keeps it, with or without
`switching`.

- A start as the active device is refused with `TermRefusal::Superseded` when
  the stored certificate names another device, and with
  `TermRefusal::Behind` when the device's newest block is in a later term
  than it holds.

### Consensus storage across a switch

A device's state and finalized history are at its newest block whatever role
it ran in. Commonware's consensus storage is not: it is written in a role.

- Simplex journals an epoch's votes and certificates. A validator journals
  in `commonware/vera-orchestrator_consensus_<epoch>`, a backup in
  `commonware/vera-observer_consensus_<epoch>`. A validator's journal holds
  the votes its key cast: Commonware refuses to replay them under a key the
  node does not sign with, and a voter that lost them could cast a different
  vote in a view it already voted in. A backup's journal holds the
  certificates it observed, among them those of blocks a later term voided.
- Marshal caches the blocks and certificates of recent views in
  `commonware/vera-cache-*`, and archives finalized blocks and their
  certificates by height in `vera-blocks-*` and `vera-finalizations-*`. An
  archive keeps the first entry stored at a height and cannot drop one.

An embedded node therefore settles this storage at every start, before
marshal and Simplex open it. Nothing in `commonware/` that holds state, the
reshare ceremony or marshal's processed height is touched.

1. A start as a backup after a start as the validator removes the backup's
   journals, which predate the blocks the device built since. The
   validator's journal is kept while the device follows, so a device that
   validates again without a new term (`resume_stopped`) replays its own
   votes.
2. A start as the validator under a certificate the device has not started
   under removes both roles' journals and marshal's cache, and rebuilds the
   archive of certificates without those above the cut. The certificates up
   to the cut are first copied to `kept-finalizations` in the data directory;
   the archive is then destroyed and filled again from that file, and the
   file is removed last.
3. A backup that holds the certificate of a term does the same while its
   archive holds a certificate above the cut and no block above it: the
   certificate of a block of the replaced device that this backup never
   received either.
4. A block above the cut is never removed here. A validator's start refuses
   it (`TermRefusal::NotAtCut`), and a backup holds it because it is a block
   of the term.

The decision is stored in `term.json` before anything is removed, and a
start that finds it finishes the clearing first, in whichever role it runs.
An interruption after `kept-finalizations` is complete is repeated from that
file.

Simplex has no record of where an epoch stands other than its journal. A
voter that opens an empty one starts the epoch at view 1 on the last block
of the epoch before, execution refuses each proposal as stale, and nothing
finalizes. So at every start that does not synchronize by snapshot, the node
hands Simplex a floor: the finalization of its newest block, as
`simplex::Floor::Finalized`. The voter starts at the view after it with that
block as parent, and records the floor in its journal. A journal that
already reaches further is not rolled back by a lower floor.

- The floor is the finalization of the newest block in finalized history,
  or of a block above it that marshal archived with its certificate and
  delivers again before consensus proposes. It is read from marshal's
  archive, and from finalized history when the archive does not hold it.
- The node passes it to the orchestrator as Commonware's state-sync start
  for consensus (`vera-seat_dkg_state_sync`), with the epoch's public
  information from genesis or from the last block of the epoch before, read
  from finalized history. The reshare actor is not given it: it reads the
  epoch's ceremony from the blocks the device holds, as before.
- No floor is passed when the newest block is the genesis block or the last
  of its epoch. The next epoch starts from that block as Commonware starts
  any epoch. None is passed either when the certificate or the block that
  opened the epoch is not stored; consensus then starts as Commonware
  recovers it.

This is what lets a device validate again after it followed nobody, take a
term back after its successor built blocks, and take over after it
synchronized by snapshot and received no block since.

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

## The wake check

An active device that slept, or was stopped, cannot tell whether another
device took the deployment over meanwhile. Nothing expires in this design:
the active device never stops on its own. So before it proposes after a gap in
its own blocks longer than `Switching::freshness` (30 seconds by default, the
age a verifying client still accepts a state at), it asks every device in
`Switching::devices` where it stands.

- The gap is measured on the wall clock, from the timestamp of the device's
  newest block at start and from each block it proposes afterwards. The wall
  clock keeps running while a machine sleeps. A device with no block of its
  own, a newest block dated after the local clock, or a clock set back
  cannot show it is fresh, and asks.
- The device asks before it builds a block and again when the block is
  built, before consensus sees it: an idle proposer waits up to the heartbeat
  for a first request, and a machine can sleep inside that wait.
- Two devices that both run as the validator share one network key and cannot
  connect. The device therefore asks over a separate connection under its
  transport key, which the device that replaced it admits as a backup's. It
  dials each listed address and waits up to `Switching::answer_timeout` for
  an answer.
- Only a device that runs as the validator answers under the validator key,
  so any answer means another device is active, and the device does not
  propose.
- An answer that carries a certificate of a later term, held by another
  device and valid under the operator policy in this device's own state,
  demotes the device: it stores the certificate, proposes nothing more, and
  `EmbeddedNode::demoted` resolves with the certificate. The host then calls
  `follow`. `resume` and `hand_over` are refused with
  `TermRefusal::Superseded`.
- Any other answer is a contest: no certificate, one the device cannot
  verify (the operators were rotated in blocks it does not have), one of a
  term it already holds, or one it could not store. Nothing is stored and
  nothing is demoted on unverified data. The proposal is dropped,
  `EmbeddedNode::contested` resolves with the `Contest` (the device that
  answered, its newest block and its unverified certificate), and the device
  asks again at its next turn. It proposes again once nobody answers. This
  covers two devices certified for the same term number and a device opened
  as validator without a certificate. The answer does not carry the chain of
  certificates since the asker's term: holding is enough to stop the fork,
  and the host resolves it with a certificate the device can verify.
- With no answer the device proposes. An idle deployment's heartbeat keeps
  its newest block inside the window, so a device that stays awake asks only
  once after it starts or wakes.

```rust
let mut node = EmbeddedNode::start(active_config).await?;
tokio::select! {
    certificate = node.demoted() => node.follow(certificate).await?,
    // ... the host's other work
}
```

This bounds a fork; it does not prevent one. A device that wakes while no
other device is reachable goes on as the active device, and so does one that
restarts inside the window. A device that stays awake and is cut off from
the others never asks. If another device took over meanwhile, both
finalize blocks until the woken one next asks, or the host gives it the
certificate with `follow`. Preventing that takes a lease and an always-on
voter, which this version does not have.

## Rewinding above the cut

A device that finalized blocks above the cut of a later term holds blocks
that no other device has and that the term voided. This is the device that
was replaced by a confirmed takeover while it was down or unreachable. When it
starts as a backup, by `follow` or with `EmbeddedConfig::following`, it brings
its directory back to the cut before the node opens it:

1. It compares its finalized history with the cut. Records above the cut are
   void when the first of them is in a lower term than the certificate's; a
   term never decreases along a chain, so the rest are too. Records above
   the cut that are already in the term were received from its holder and
   stay.
2. It adds every submission those records finalized to
   `discarded-submissions.json`, then drops the records and their query
   mappings from history.
3. It removes `commonware/`: the consensus archives and the state journals.
   Commonware's archives cannot be cut back, and a finalized block stays in
   them once stored. The node then starts like a backup on an empty
   directory. It takes the state at a block of the new term from the device
   it follows and imports the history between the cut and that block. The
   history up to the cut is kept, so the import does not grow with the
   deployment's age.

Each step is durable before the next begins, and an interrupted rewind is
completed by the next start as a backup. A start never prepares a directory
another node runs on.

A device whose block at the cut's height is another block than the cut left
the deployment's history below the cut. It cannot follow, and the start fails
with `TermRefusal::Diverged`; the device joins again as a backup in an empty
directory. This needs two switches that each lost blocks, with this device
absent for both. A device whose newest block is below the cut cannot be
judged from the certificate. It is found out when it connects: the holder's
next block does not extend its newest block, or the history it imports does
not connect to the records it kept. The node stops with
`TermRefusal::Diverged` before the block reaches execution, on every start,
until the directory is replaced.

A rewind also drops an import of history that was interrupted above the cut.

### Discarded submissions

`follow` returns the submissions the rewind voided, and
`EmbeddedNode::discarded` returns them again until the host calls
`acknowledge_discarded`; the report is a file, so it survives a restart.

```rust
for discarded in node.follow(certificate).await? {
    // discarded.submission, .height, .success, .request
}
```

Each entry carries the signed request as it was submitted. The submission
was finalized, its receipt was served, and a client may have acted on it; it
is not part of the deployment's history any more, and the device no longer
serves its receipt. The host decides what to do with each: a request whose
sequence is still the signer's next one on the new chain can be submitted
again unchanged to the active device and keeps its identifier, and anything
else is signed again from the intent. Requests that were only pending in the
device's pool are not reported: they were never finalized, and they are lost
with the process as on any restart.

### A refused block

A backup that stops with `TermRefusal::LowerTerm` keeps the refused block in
its consensus archive. The node marks the directory, and the next start as a
backup removes `commonware/` as in step 3, so the device can follow the
holder of the term once it is given the right address. A snapshot is not
executed block by block, so the node also checks the term of the block a
snapshot is taken at and refuses the same way.

## Limits

These follow from sticky active without a lease and from one shared key:

- An active device that stays awake and is cut off from the others never
  asks, and an unanswered check permits proposing.
- Nothing binds a certificate to a version of the operator policy. A
  verifier reads the policy at its own newest state, so a certificate
  approved before a rotation may not verify after it, and the reverse.
- Two certificates for one term number, naming different devices or cuts,
  are an operator error. A device does not detect it from the certificates;
  the two devices contest each other when one asks.
- A re-executing node accepts any term at or above its parent's without a
  certificate.
- `LightBlock` JSON and the C verifier's results do not expose a block's
  term. A client reads it from the block it decodes or from
  `GossipHeader::term`.
- A device that was rewound serves no certificate below the cut from its
  consensus archive, only from the finalized history it kept.
- A device that resumes a handover without a certificate
  (`resume_stopped`) clears no certificate: no term voids anything. If it
  holds the certificate of a block above its newest one without the block,
  the successor did take over, and the device should follow it.
- A certificate above the cut whose block arrives after `takeover_change`
  stopped waiting for it is voided with the block. The host shows the user
  the age of the cut before the operators approve.

Also:

- One validator key shared by every device. A device that holds it can
  finalize blocks in any term; the term and its certificate tell honest
  devices and clients which chain to follow, and they do not take the key
  away from a stolen device. That needs key rotation, which is not built.
- Sticky active without a lease. A fork is bounded by the wake check and by
  clients that require certificates; it is not prevented. A confirmed
  takeover loses whatever the replaced device finalized after the cut.
- Catch-up after a rewind transfers the whole state. Its cost was not
  measured, and neither was a handover or a takeover on a deployment of
  realistic age and size.
- A rewind removes the consensus archives, so a device that was rewound
  serves no certificate for a block below the cut from its archive; it
  serves them from the finalized history it kept.
- `Switching::devices` is configuration. Nothing in state records the
  account's devices, and a change takes a restart.
- A backup dials one address. After a switch its host restarts it with the
  new holder's address (`follow`, `EmbeddedConfig::following`).
- Announced handover and takeover were exercised between two nodes in one
  process on loopback, and a takeover past an unreceived certificate between
  three. Devices on separate hosts were not.
- The certificate of a block stored without the block is produced in tests
  by a fault-injection build that writes it into the archive at start. A
  stop between marshal's two writes was not reproduced.
- An interrupted clearing is tested at one point: after `kept-finalizations`
  is complete and before the archive is destroyed. A stop while Commonware
  destroys the archive, or while it is filled again, is repeated from the
  same file, provided Commonware opens the partly removed archive at the
  next start; that was not exercised.
- A start under a certificate removes the validator's journal. Votes it held
  above the cut are void in the new term, like the blocks above the cut.
