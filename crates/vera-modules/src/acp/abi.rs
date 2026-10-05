use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the ACP precompile at `0x0810`.
    interface IAcp {
        // ── Events ──────────────────────────────────────────────────────

        event RegistrationsCommitted(uint64 indexed commitmentId, bytes32 indexed policyId, bytes32 commitment);

        event PolicyCreated(string indexed policyId, string creator);
        event DelegatedPolicyCreated(bytes32 indexed policyId, string creator);
        event PolicyEdited(string indexed policyId, string creator, uint256 relationshipsRemoved);
        event RelationshipSet(string indexed policyId, string resource, string objectId, string relation, string actor);
        event RelationshipDeleted(string indexed policyId, string resource, string objectId, string relation, string actor);
        event RelationshipSubjectSet(string indexed policyId, string resource, string objectId, string relation, uint8 subjectKind, string subjectResource, string subjectObjectId, string subjectRelation);
        event RelationshipSubjectDeleted(string indexed policyId, string resource, string objectId, string relation, uint8 subjectKind, string subjectResource, string subjectObjectId, string subjectRelation);
        event ObjectRegistered(string indexed policyId, string resource, string objectId, string owner);
        event ObjectUnregistered(string indexed policyId, string resource, string objectId);

        // ── Write methods (map to Cosmos Msgs) ──────────────────────────

        event ObjectTransferred(bytes32 indexed policyId, string resource, string objectId, string newOwner);
        event PolicyDeleted(bytes32 indexed policyId);
        event PolicyMetadataEdited(bytes32 indexed policyId);

        event PolicyCommandExecuted(bytes32 indexed policyId, string actor);
        function executePolicyCommand(bytes32 policyId, bytes request) external returns (bytes);
        function createPolicyWithOptions(bytes request) external returns (bytes);
        function transferObject(bytes32 policyId, string resource, string objectId, string newOwner) external returns (bytes);
        function deletePolicy(bytes32 policyId) external returns (bool);
        function editPolicyMetadata(bytes32 policyId, bytes metadata) external returns (bytes);
        function evaluateTheorem(bytes32 policyId, string source) external view returns (bytes);
        function getPolicyCatalogue(bytes32 policyId) external view returns (bytes);
        function getPoliciesPage(bytes cursor) external view returns (bytes);
        function getRelationshipsPage(bytes32 policyId, bytes request) external view returns (bytes);
        function getPolicies() external view returns (bytes);
        function getObjectRegistration(bytes32 policyId, string resource, string objectId) external view returns (bytes);
        function checkManagementAuthority(bytes32 policyId, string resource, string objectId, string relation, string actor) external view returns (bool);

        function batchCalls(bytes[] calldata calls) external returns (bytes[] results);
        function createPolicy(bytes calldata policy, uint8 marshalType) external returns (bytes);
        function editPolicy(bytes32 policyId, bytes calldata policy, uint8 marshalType) external returns (uint64 relationshipsRemoved, bytes record);
        function bearerCreatePolicy(string bearerToken, bytes calldata policy, uint8 marshalType) external returns (bytes);
        function bearerEditPolicy(string bearerToken, bytes32 policyId, bytes calldata policy, uint8 marshalType) external returns (uint64 relationshipsRemoved, bytes record);

        function setRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external returns (bool recordExisted, bytes record);

        function deleteRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external returns (bool recordFound);

        function setRelationshipSubject(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            uint8 subjectKind,
            string subjectResource,
            string subjectObjectId,
            string subjectRelation
        ) external returns (bool recordExisted, bytes record);

        function deleteRelationshipSubject(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            uint8 subjectKind,
            string subjectResource,
            string subjectObjectId,
            string subjectRelation
        ) external returns (bool recordFound);

        function registerObject(
            bytes32 policyId,
            string objectId,
            string resource
        ) external returns (bytes record);

        function archiveObject(
            bytes32 policyId,
            string objectId,
            string resource
        ) external returns (bool found, uint64 relationshipsRemoved);

        function unarchiveObject(
            bytes32 policyId,
            string objectId,
            string resource
        ) external returns (bytes record, bool relationshipModified);

        function commitRegistrations(
            bytes32 policyId,
            bytes commitment
        ) external returns (uint64 commitmentId);

        function revealRegistration(
            uint64 commitmentId,
            bytes proof
        ) external returns (bytes);

        function flagHijackAttempt(uint64 eventId) external returns (bytes event);

        function bearerCheckAccess(string bearerToken, bytes32 policyId, bytes request) external returns (bytes);

        function checkAccess(
            bytes32 policyId,
            string[] resources,
            string[] objectIds,
            string[] permissions,
            string actor
        ) external returns (bytes);

        function verifyAccessRequest(
            bytes32 policyId,
            string[] resources,
            string[] objectIds,
            string[] permissions,
            string actor
        ) external view returns (bool);

        function bearerPolicyCmd(string bearerToken, bytes32 policyId, bytes cmd) external returns (bytes);
        function updateParams(bytes params) external;

        // ── Read methods (map to Cosmos Queries) ────────────────────────

        function hasRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external view returns (bool);

        function getPolicy(bytes32 policyId) external view returns (bytes);

        function getObjectOwner(
            bytes32 policyId,
            string resource,
            string objectId
        ) external view returns (bool registered, bytes record);

        function getPolicyIds() external view returns (string[]);

        function filterRelationships(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external view returns (bytes);

        function validatePolicy(bytes calldata policy, uint8 marshalType) external view returns (bool valid, string reason);

        function getAccessDecision(string decisionId) external view returns (bytes);

        function getRegistrationsCommitment(uint64 commitmentId) external view returns (bytes);

        function getRegistrationsCommitmentByValue(
            bytes commitment
        ) external view returns (bytes);

        function getHijackAttempts(bytes32 policyId) external view returns (bytes);

        function generateCommitment(
            bytes32 policyId,
            string[] resources,
            string[] objectIds,
            string actor
        ) external view returns (bytes);

        function getParams() external view returns (bytes);
    }
}
