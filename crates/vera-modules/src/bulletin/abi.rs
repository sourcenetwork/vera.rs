//! Solidity ABI interface for the Bulletin precompile at `0x0811`.

use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the Bulletin precompile at `0x0811`.
    interface IBulletin {
        // ── Events ──────────────────────────────────────────────────────

        event NamespaceCreated(string indexed namespace, string owner);
        event CollaboratorAdded(string indexed namespace, string collaborator);
        event CollaboratorRemoved(string indexed namespace, string collaborator);
        event PostCreated(string indexed namespace, bytes32 postId, string artifact);

        // ── Write methods ───────────────────────────────────────────────

        function registerNamespace(string namespace) external returns (bytes);

        function createPost(
            string namespace,
            bytes payload,
            bytes proof,
            string artifact
        ) external returns (bytes32 postId);

        function addCollaborator(
            string namespace,
            string collaboratorDid
        ) external returns (string storedDid);

        function removeCollaborator(
            string namespace,
            string collaboratorDid
        ) external returns (string storedDid);

        // ── Read methods ────────────────────────────────────────────────

        function getPost(
            string namespace,
            string postId
        ) external view returns (bytes);

        function getNamespace(
            string namespace
        ) external view returns (bytes);

        function getNamespaces() external view returns (bytes);

        function getNamespaceCollaborators(
            string namespace
        ) external view returns (bytes);

        function getNamespacePosts(
            string namespace
        ) external view returns (bytes);

        function getPosts() external view returns (bytes);

        function iterateGlob(
            string namespace,
            string glob
        ) external view returns (bytes);
    }
}
