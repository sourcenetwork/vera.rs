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
