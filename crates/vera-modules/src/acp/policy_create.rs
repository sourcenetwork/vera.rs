//! Create policies under ids bound to their creator and the creator's nonce.

use super::*;
use serde::{Deserialize, Serialize};

/// The DID that owns policies seeded by [`AcpModule::initialize_policies`]
/// at a daemon's genesis.
pub const GENESIS_POLICY_CREATOR: &str = "did:key:zVeraGenesisSeed";

/// One genesis-seeded policy owned by the genesis creator.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySeed {
    /// The policy's source text, in `marshal_type`'s format.
    pub definition: String,
    /// Which format `definition` is written in.
    pub marshal_type: PolicyMarshalingType,
    /// The creator's nonce, part of the policy id.
    pub nonce: PolicyNonce,
}

/// One genesis-seeded policy whose owner and nonce the deployment chooses.
///
/// The id is derived from the definition, the owner and the nonce alone
/// ([`AcpModule::predict_policy_id`]), so a host knows it before the
/// deployment exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacedPolicy {
    /// The policy's source text, in `marshal_type`'s format.
    pub definition: String,
    /// Which format `definition` is written in.
    pub marshal_type: PolicyMarshalingType,
    /// The owner's nonce, part of the policy id.
    pub nonce: PolicyNonce,
    /// DID recorded as the policy's owner and creator.
    pub owner: String,
}

impl AcpModule {
    /// Parse, validate, and store a new access control policy.
    pub fn create_policy(
        &mut self,
        creator: &Did,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        nonce: PolicyNonce,
    ) -> Result<PolicyRecord> {
        self.create_policy_with_budget(
            creator,
            policy,
            marshal_type,
            nonce,
            &PolicyCreateBudget::new(u64::MAX),
        )
    }

    /// Create within a caller-owned allowance, preserving state on failure.
    pub fn create_policy_with_budget(
        &mut self,
        creator: &Did,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        nonce: PolicyNonce,
        budget: &PolicyCreateBudget,
    ) -> Result<PolicyRecord> {
        budget.input(creator.as_str().len())?;
        let result = self.create_policy_with_options_and_budget(
            policy,
            marshal_type,
            nonce,
            RecordMetadata {
                creation_ts: Timestamp::default(),
                tx_hash: Vec::new(),
                tx_signer: String::new(),
                owner_did: creator.to_string(),
            },
            None,
            &SuppliedMetadata::default(),
            budget,
        );
        budget.finish(result)
    }

    /// Creates the policy under the id of its hash, `metadata.owner_did`
    /// (canonicalized) and `nonce`. An id that is stored, or retired and not
    /// yet cleaned up, is refused and keeps what it names.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn create_policy_with_options_and_budget(
        &mut self,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        nonce: PolicyNonce,
        mut metadata: RecordMetadata,
        specification: Option<PolicySpecification>,
        supplied: &SuppliedMetadata,
        budget: &PolicyCreateBudget,
    ) -> Result<PolicyRecord> {
        crate::actor::canonicalize(&mut metadata.owner_did);
        if policy.len() > MAX_POLICY_DEFINITION_BYTES {
            return Err(AcpError::InvalidPolicy {
                reason: "policy definition exceeds 64 KiB".into(),
            });
        }
        budget.input(policy.len())?;
        budget.metadata(supplied)?;
        let record = Self::new_policy_record(
            policy,
            marshal_type,
            nonce,
            metadata,
            specification,
            supplied.clone(),
        )?;
        let policy_id = record.policy.id.clone();
        let key = keys::policy_key(&policy_id);
        budget.records.read(&key, self.store.get_ref(&key))?;
        let retired_key = retirement::retired_key(&policy_id);
        budget
            .records
            .read(&retired_key, self.store.get_ref(&retired_key))?;
        self.refuse_taken_id(&policy_id)?;
        let bytes = budget.records.encode(&key, &record)?;
        self.store.put(&key, bytes);
        self.zanzibar_policies
            .insert(policy_id, Arc::new(record.policy.clone()));
        Ok(record)
    }

    /// Seed policies owned by `creator`, each under its own nonce. Only at
    /// genesis: refused once any policy exists.
    pub fn initialize_policies(
        &mut self,
        creator: &Did,
        policies: &[PolicySeed],
    ) -> Result<Vec<PolicyRecord>> {
        let placed: Vec<_> = policies
            .iter()
            .map(|seed| PlacedPolicy {
                definition: seed.definition.clone(),
                marshal_type: seed.marshal_type.clone(),
                nonce: seed.nonce,
                owner: creator.to_string(),
            })
            .collect();
        self.initialize_placed_policies(&placed)
    }

    /// Seed policies under the owners and nonces the caller chose. Only at
    /// genesis: refused once any policy exists. Two seeds with one id are
    /// refused.
    pub fn initialize_placed_policies(
        &mut self,
        policies: &[PlacedPolicy],
    ) -> Result<Vec<PolicyRecord>> {
        if self.store.prefix_iter(keys::POLICY_PREFIX).next().is_some() {
            return Err(AcpError::State("policies are already initialized".into()));
        }
        let mut records = Vec::with_capacity(policies.len());
        for placed in policies {
            let owner = Did::new(placed.owner.as_str())
                .map_err(|error| AcpError::State(format!("seeded policy owner: {error}")))?;
            let record = Self::new_policy_record(
                &placed.definition,
                placed.marshal_type.clone(),
                placed.nonce,
                RecordMetadata {
                    creation_ts: Timestamp::default(),
                    tx_hash: Vec::new(),
                    tx_signer: String::new(),
                    owner_did: crate::actor::canonical(&owner).to_string(),
                },
                None,
                SuppliedMetadata::default(),
            )?;
            let policy_id = record.policy.id.clone();
            self.refuse_taken_id(&policy_id)?;
            let bytes = serde_json::to_vec(&record)
                .map_err(|error| AcpError::State(format!("encode seeded policy: {error}")))?;
            self.store.put(&keys::policy_key(&policy_id), bytes);
            self.zanzibar_policies
                .insert(policy_id, Arc::new(record.policy.clone()));
            records.push(record);
        }
        Ok(records)
    }

    /// The id `creator` gets for `policy` created with `nonce`, without
    /// reading or changing state: a host can name a seeded policy before
    /// its deployment exists.
    pub fn predict_policy_id(
        policy: &str,
        marshal_type: &PolicyMarshalingType,
        nonce: &PolicyNonce,
        creator: &str,
    ) -> Result<String> {
        let (_, hash) = Self::compile_policy(policy, marshal_type, None)?;
        Ok(policy_yaml::policy_id(
            &hash,
            nonce,
            &crate::actor::canonical_str(creator),
        ))
    }

    /// A record for a new policy owned by the already canonical
    /// `metadata.owner_did`.
    fn new_policy_record(
        policy: &str,
        marshal_type: PolicyMarshalingType,
        nonce: PolicyNonce,
        metadata: RecordMetadata,
        specification: Option<PolicySpecification>,
        supplied_metadata: SuppliedMetadata,
    ) -> Result<PolicyRecord> {
        let (mut compiled, policy_hash) =
            Self::compile_policy(policy, &marshal_type, specification)?;
        compiled.id = policy_yaml::policy_id(&policy_hash, &nonce, &metadata.owner_did);
        Ok(PolicyRecord {
            relations: RelationGenerations::new(&compiled).map_err(relation_state_error)?,
            supplied_metadata,
            last_modified: None,
            policy: compiled,
            raw_policy: policy.to_string(),
            marshal_type,
            metadata,
            nonce,
            policy_hash,
        })
    }

    fn refuse_taken_id(&self, policy_id: &str) -> Result<()> {
        if self.store.has(&keys::policy_key(policy_id)) || self.retired_policy(policy_id)?.is_some()
        {
            return Err(AcpError::PolicyAlreadyExists {
                id: policy_id.to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "policy_create_budget_tests.rs"]
mod tests;
