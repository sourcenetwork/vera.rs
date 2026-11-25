//! Solidity ABI interface for the anchor precompile at `0x0814`.

use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the anchor precompile at `0x0814`.
    interface IAnchor {
        /// A deployment's latest anchor moved to a new revision.
        event RevisionAnchored(
            bytes32 indexed deployment,
            uint64 sequence,
            uint64 height,
            bytes32 blockHash
        );

        /// A finalized block of a deployment that does not descend from its latest anchor.
        event ForkReported(
            bytes32 indexed deployment,
            uint64 sequence,
            bytes32 anchoredBlock,
            uint64 height,
            bytes32 blockHash
        );

        /// A deployment's operators certified a term, which continues its
        /// chain of anchors from the cut.
        event TermChanged(
            bytes32 indexed deployment,
            uint64 term,
            uint64 cutHeight,
            bytes32 cutBlock,
            uint64 sequence
        );

        /// Record a term of a registered deployment. `certificate` is the
        /// JSON `TermCertificate`, approved under the deployment's registered
        /// operator policy. Returns the term record as JSON.
        function changeTerm(
            bytes32 deployment,
            bytes certificate
        ) external returns (bytes record);

        /// Record a finalized revision of a registered deployment, submitted by
        /// a signer with a grant for it. `ancestryProof` shows that the deployment's latest anchor is an
        /// ancestor of the revision; it is empty for the first anchor.
        /// Returns the deployment's latest anchor record as JSON.
        function anchorRevision(
            bytes32 deployment,
            bytes block,
            bytes[] descendants,
            bytes finalization,
            bytes epochMaterial,
            bytes ancestryProof
        ) external returns (bytes record);

        /// Record a finalized revision of a registered deployment that
        /// conflicts with its latest anchor: another block at the anchored height, or a block
        /// above it whose ancestor at the anchored height is `ancestor`, as
        /// `ancestryProof` shows. Returns the fork record as JSON.
        function reportFork(
            bytes32 deployment,
            bytes block,
            bytes[] descendants,
            bytes finalization,
            bytes epochMaterial,
            bytes32 ancestor,
            bytes ancestryProof
        ) external returns (bytes record);
    }
}
