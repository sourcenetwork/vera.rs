//! Membership commands, authorized by the deployment's membership policy.

use alloy_primitives::Address;
use vera_identity::Did;

use super::{MemberRecord, MembershipLimits, error::ValidatorRegistryError, validate_p2p_address};
use crate::acp::AcpModule;
use crate::acp::types::{AccessRequest, Actor, Object, Operation};
use crate::vera::VeraModule;

type Result<T> = std::result::Result<T, ValidatorRegistryError>;

fn valid_consensus_key(key: &[u8; 32]) -> bool {
    *key != [0; 32] && vera_crypto::actor::ed25519_did(key).is_ok()
}

impl VeraModule {
    fn check_manage_access(&self, acp: &AcpModule, caller: &Did) -> Result<()> {
        let policy = self
            .administration()
            .map_err(|error| ValidatorRegistryError::Corrupt(error.to_string()))?
            .and_then(|state| state.membership_policy)
            .ok_or_else(|| {
                ValidatorRegistryError::Unauthorized("no ACP policy configured".into())
            })?;
        let request = AccessRequest {
            operations: vec![Operation {
                object: Object {
                    resource: "registry".into(),
                    id: "registry".into(),
                },
                permission: "manage".into(),
            }],
            actor: Actor(caller.clone()),
        };
        match acp.query_verify_access_request(&hex::encode(policy), &request) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ValidatorRegistryError::Unauthorized(
                "ACP denied manage permission".into(),
            )),
            Err(error) => Err(ValidatorRegistryError::State(format!(
                "ACP check failed: {error}"
            ))),
        }
    }

    fn active_members(&self) -> Result<usize> {
        Ok(self
            .registry_members()?
            .iter()
            .filter(|(_, member)| member.active)
            .count())
    }

    /// Register an active member.
    pub fn add_validator(
        &mut self,
        acp: &AcpModule,
        caller: &Did,
        limits: MembershipLimits,
        address: Address,
        consensus_key: [u8; 32],
        p2p_address: &str,
    ) -> Result<()> {
        self.check_manage_access(acp, caller)?;
        if address == Address::ZERO {
            return Err(ValidatorRegistryError::InvalidAddress(
                "zero address".into(),
            ));
        }
        if !valid_consensus_key(&consensus_key) {
            return Err(ValidatorRegistryError::InvalidPublicKey);
        }
        validate_p2p_address(p2p_address)?;
        let members = self.registry_members()?;
        if members.iter().any(|(member, _)| *member == address) {
            return Err(ValidatorRegistryError::ValidatorAlreadyExists(format!(
                "{address:?}"
            )));
        }
        if members.len() >= limits.members as usize {
            return Err(ValidatorRegistryError::MembershipLimit(limits.members));
        }
        if members.iter().filter(|(_, member)| member.active).count() >= limits.active as usize {
            return Err(ValidatorRegistryError::EpochCapacity(limits.active));
        }
        if members
            .iter()
            .any(|(_, member)| member.consensus_key == consensus_key)
        {
            return Err(ValidatorRegistryError::DuplicateConsensusKey);
        }
        let admission = self.next_admission()?;
        self.put_member(
            address,
            &MemberRecord {
                consensus_key,
                p2p_address: p2p_address.to_owned(),
                active: true,
                admission,
                address_sequence: 0,
            },
        );
        Ok(())
    }

    /// Remove a member, unless it is the last active one.
    pub fn remove_validator(
        &mut self,
        acp: &AcpModule,
        caller: &Did,
        address: Address,
    ) -> Result<()> {
        self.check_manage_access(acp, caller)?;
        let member = self
            .registry_member(address)?
            .ok_or_else(|| ValidatorRegistryError::ValidatorNotFound(format!("{address:?}")))?;
        if member.active && self.active_members()? <= 1 {
            return Err(ValidatorRegistryError::EmptyCommittee);
        }
        self.delete_member(address);
        Ok(())
    }

    /// Activate or deactivate a member within the committee's bounds.
    pub fn set_validator_status(
        &mut self,
        acp: &AcpModule,
        caller: &Did,
        limits: MembershipLimits,
        address: Address,
        active: bool,
    ) -> Result<()> {
        self.check_manage_access(acp, caller)?;
        let mut member = self
            .registry_member(address)?
            .ok_or_else(|| ValidatorRegistryError::ValidatorNotFound(format!("{address:?}")))?;
        let active_members = self.active_members()?;
        if !active && member.active && active_members <= 1 {
            return Err(ValidatorRegistryError::EmptyCommittee);
        }
        if active && !member.active && active_members >= limits.active as usize {
            return Err(ValidatorRegistryError::EpochCapacity(limits.active));
        }
        member.active = active;
        self.put_member(address, &member);
        Ok(())
    }

    /// Consensus keys of the active members, sorted.
    pub fn active_consensus_keys(&self) -> Result<Vec<[u8; 32]>> {
        let mut keys: Vec<_> = self
            .registry_members()?
            .into_iter()
            .filter(|(_, member)| member.active)
            .map(|(_, member)| member.consensus_key)
            .collect();
        keys.sort_unstable();
        if keys.is_empty()
            || keys.windows(2).any(|pair| pair[0] == pair[1])
            || !keys.iter().all(valid_consensus_key)
        {
            return Err(ValidatorRegistryError::Corrupt(
                "empty, duplicate or invalid consensus roster".into(),
            ));
        }
        Ok(keys)
    }

    /// Install the genesis members, all active. The registry must be empty.
    pub fn seed_validators(
        &mut self,
        members: impl IntoIterator<Item = (Address, [u8; 32], String)>,
    ) -> Result<()> {
        if !self.registry_members()?.is_empty() {
            return Err(ValidatorRegistryError::State(
                "registry already holds members".into(),
            ));
        }
        let mut keys = std::collections::BTreeSet::new();
        for (address, consensus_key, p2p_address) in members {
            if address == Address::ZERO {
                return Err(ValidatorRegistryError::InvalidAddress(
                    "zero address".into(),
                ));
            }
            if !valid_consensus_key(&consensus_key) {
                return Err(ValidatorRegistryError::InvalidPublicKey);
            }
            validate_p2p_address(&p2p_address)?;
            if self.registry_member(address)?.is_some() {
                return Err(ValidatorRegistryError::ValidatorAlreadyExists(format!(
                    "{address:?}"
                )));
            }
            if !keys.insert(consensus_key) {
                return Err(ValidatorRegistryError::DuplicateConsensusKey);
            }
            let admission = self.next_admission()?;
            self.put_member(
                address,
                &MemberRecord {
                    consensus_key,
                    p2p_address,
                    active: true,
                    admission,
                    address_sequence: 0,
                },
            );
        }
        Ok(())
    }
}
