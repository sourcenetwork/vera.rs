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

        /// Record a finalized revision of the deployment with this consensus key.
        /// Returns the deployment's latest anchor record as JSON.
        function anchorRevision(
            bytes consensusKey,
            bytes block,
            bytes[] descendants,
            bytes finalization,
            bytes epochMaterial
        ) external returns (bytes record);
    }
}
