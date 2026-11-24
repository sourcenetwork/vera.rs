use std::collections::{HashMap, HashSet};

use super::{ParsedPolicy, PolicyRelation};
use crate::error::{Error, Result};

fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidPolicy(reason.into())
}

fn identifier(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    if name.len() > 128
        || !bytes
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        || !bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err(invalid(format!("invalid policy identifier '{name}'")));
    }
    Ok(())
}

pub(super) fn validate(policy: &ParsedPolicy) -> Result<()> {
    if policy.name.trim().is_empty() || policy.name.len() > 256 {
        return Err(invalid("policy name must contain 1–256 bytes"));
    }
    let mut names = HashMap::new();
    for resource in &policy.resources {
        identifier(&resource.name)?;
        if resource.name == "actor" || names.contains_key(resource.name.as_str()) {
            return Err(invalid(format!(
                "duplicate or reserved resource '{}'",
                resource.name
            )));
        }
        let mut relations = relation_names(&resource.relations, true)?;
        for permission in &resource.permissions {
            identifier(&permission.name)?;
            if !relations.insert(permission.name.as_str()) {
                return Err(invalid(format!(
                    "duplicate or reserved relation '{}'",
                    permission.name
                )));
            }
        }
        names.insert(resource.name.as_str(), relations);
    }
    names.insert("actor", relation_names(&policy.actor.relations, false)?);
    for resource in &policy.resources {
        validate_references(&resource.relations, &names)?;
    }
    validate_references(&policy.actor.relations, &names)?;
    validate_create_rules(policy, &names)
}

fn validate_create_rules(
    policy: &ParsedPolicy,
    names: &HashMap<&str, HashSet<&str>>,
) -> Result<()> {
    let mut parents = HashMap::new();
    for resource in &policy.resources {
        let Some(rule) = &resource.create else {
            continue;
        };
        let relation = resource
            .relations
            .iter()
            .find(|relation| relation.name == rule.parent)
            .ok_or_else(|| {
                invalid(format!(
                    "unknown parent relation '{}.{}'",
                    resource.name, rule.parent
                ))
            })?;
        let [parent] = relation.types.as_slice() else {
            return Err(invalid(
                "a create rule requires exactly one parent object type",
            ));
        };
        let parent = parent.trim();
        if parent == "actor" || !names.contains_key(parent) {
            return Err(invalid(format!("invalid parent object type '{parent}'")));
        }
        if !names[parent].contains(rule.requires.as_str()) {
            return Err(invalid(format!(
                "unknown parent permission '{parent}.{}'",
                rule.requires
            )));
        }
        parents.insert(resource.name.as_str(), parent);
    }
    let mut complete = HashSet::new();
    for resource in &policy.resources {
        let mut path = HashSet::new();
        let mut current = resource.name.as_str();
        while let Some(&parent) = parents.get(current) {
            if complete.contains(current) {
                break;
            }
            if !path.insert(current) {
                return Err(invalid(format!("cycle in create rules at '{current}'")));
            }
            current = parent;
        }
        complete.extend(path);
    }
    Ok(())
}

fn relation_names(relations: &[PolicyRelation], with_owner: bool) -> Result<HashSet<&str>> {
    let mut names = HashSet::new();
    for relation in relations {
        identifier(&relation.name)?;
        if !names.insert(relation.name.as_str()) {
            return Err(invalid(format!("duplicate relation '{}'", relation.name)));
        }
        if relation.name == "owner"
            && (!with_owner || !relation.types.is_empty() || !relation.manages.is_empty())
        {
            return Err(invalid("the owner relation cannot be customized"));
        }
    }
    if with_owner {
        names.insert("owner");
    }
    Ok(names)
}

fn validate_references(
    relations: &[PolicyRelation],
    resources: &HashMap<&str, HashSet<&str>>,
) -> Result<()> {
    for relation in relations {
        for managed in &relation.manages {
            if managed != "owner" && !relations.iter().any(|r| r.name == *managed) {
                return Err(invalid(format!("invalid managed relation '{managed}'")));
            }
        }
        for subject_type in &relation.types {
            let subject_type = subject_type.trim();
            if subject_type == "actor:individual" {
                continue;
            }
            let (resource, relation) = subject_type.split_once("->").unwrap_or((subject_type, ""));
            let valid = resources
                .get(resource)
                .is_some_and(|names| relation.is_empty() || names.contains(relation));
            if !valid {
                return Err(invalid(format!("unknown subject type '{subject_type}'")));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_yaml::parse_policy_yaml;

    fn validate_rule(parent_type: &str, requires: &str) -> Result<()> {
        let yaml = format!(
            "name: p\nresources:\n- name: node\n  permissions: [{{name: enroll}}]\n- name: job\n  relations: [{{name: parent, types: [{parent_type}]}}]\n  create: {{parent: parent, requires: {requires}}}\n"
        );
        validate(&parse_policy_yaml(&yaml).unwrap())
    }

    #[test]
    fn a_create_rule_uses_one_parent_object_and_a_known_permission() {
        assert!(validate_rule("node", "owner").is_ok());
        assert!(validate_rule("node", "enroll").is_ok());
        for (parent, requires) in [
            ("node", "missing"),
            ("actor", "owner"),
            ("node->enroll", "owner"),
            ("node, job", "owner"),
            ("job", "owner"),
        ] {
            assert!(
                validate_rule(parent, requires).is_err(),
                "{parent} {requires}"
            );
        }
    }

    #[test]
    fn individual_actor_changes_the_policy_hash() {
        let yaml = "name: p\nresources:\n- name: node\n  relations: [{name: publisher, types: [actor:individual]}]\n";
        let restricted = parse_policy_yaml(yaml).unwrap();
        let legacy = parse_policy_yaml(&yaml.replace("actor:individual", "actor")).unwrap();
        assert!(validate(&restricted).is_ok());
        assert_ne!(
            crate::policy_yaml::policy_hash(&restricted).unwrap(),
            crate::policy_yaml::policy_hash(&legacy).unwrap()
        );
    }
}
