//! Solidity ABI of the validator registry at module address `0x0813`.

use alloy_sol_types::sol;

sol! {
    /// Calls and events of the validator registry.
    interface IValidatorRegistry {
        // ── Events ──────────────────────────────────────────────────────

        event ValidatorAdded(address indexed validator, bytes32 consensusPubkey);
        event ValidatorRemoved(address indexed validator);
        event ValidatorStatusChanged(address indexed validator, bool active);
        event ValidatorUpdated(address indexed validator);

        // ── Write methods (ACP-gated) ───────────────────────────────────

        function addValidator(
            address validator,
            bytes32 consensusPubkey,
            string calldata p2pAddr
        ) external;

        function removeValidator(address validator) external;

        function setValidatorStatus(address validator, bool active) external;

        // ── Address update (signed by the validator's consensus key) ────

        function updateP2PAddress(
            address validator,
            string calldata p2pAddr,
            uint64 sequence,
            bytes calldata signature
        ) external;

        // ── Query methods ───────────────────────────────────────────────

        function getValidators() external view returns (bytes);

        function getValidator(address validator) external view returns (bytes);

        function getActiveValidatorCount() external view returns (uint256);
    }
}
