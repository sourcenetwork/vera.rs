//! Solidity ABI interface for the Vera precompile at `0x0812`.

use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the Vera precompile at `0x0812`.
    interface IVera {
        // ── Events ──────────────────────────────────────────────────────

        event JWSTokenInvalidated(string indexed tokenHash, string issuerDid);

        // ── Write methods ───────────────────────────────────────────────

        function invalidateJWS(string tokenHash) external;

        function revokeDelegation(string token) external;

        function updateParams(bytes params) external;

        function applyAdministration(bytes request) external;

        function applyNodeRequest(bytes request) external returns (bytes);

        function storeThresholdObject(bytes request, string bearerToken) external returns (bytes);

        function applyRingCommand(bytes request, string bearerToken) external returns (bytes);

        function applyRingParticipantRequest(bytes request) external returns (bytes);
        /// Finalize an announced committee change with the existing ring key.
        function finalizeRingReshare(bytes request) external returns (bytes);
        /// Apply a threshold-authorized fault report.
        function submitRingReport(bytes request) external returns (bytes);

        function getAdministration() external view returns (bytes);

        // ── Read methods ────────────────────────────────────────────────

        function getJWSToken(
            string tokenHash
        ) external view returns (bool found, bytes record);

        function getJWSTokensByDid(
            string did
        ) external view returns (bytes);

        function getJWSTokensByAccount(
            address account
        ) external view returns (bytes);

        function getDelegationsBySubmitter(
            string submitter
        ) external view returns (bytes);

        function getChainConfig() external view returns (bytes);

        function getParams() external view returns (bytes);
    }
}
