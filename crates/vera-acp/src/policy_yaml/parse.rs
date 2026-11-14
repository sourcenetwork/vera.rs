use serde::{Deserialize, Deserializer};
use vera_zanzibar::PolicySpecification;

use super::ParsedPolicy;

pub fn parse_policy_yaml(yaml: &str) -> Result<ParsedPolicy, String> {
    if yaml.len() > 64 * 1024 {
        return Err("policy definition exceeds 64 KiB".into());
    }
    let value: serde_yaml::Value =
        super::bounded_yaml::parse(yaml).map_err(|e| format!("invalid policy YAML: {e}"))?;
    serde_yaml::from_value(value).map_err(|e| format!("invalid policy YAML: {e}"))
}

pub(super) fn deserialize_specification<'de, D>(
    deserializer: D,
) -> Result<PolicySpecification, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    match value.to_ascii_lowercase().as_str() {
        "" | "none" => Ok(PolicySpecification::None),
        "defra" => Ok(PolicySpecification::Defra),
        _ => Err(serde::de::Error::custom(format!(
            "unknown policy specification '{value}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_POLICY: &str = r#"
name: test
description: a test policy
resources:
  - name: users
    permissions:
      - name: read
        expr: owner + reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
    relations:
      - name: owner
        types:
          - actor
      - name: reader
        types:
          - actor
"#;

    #[test]
    fn test_parse_valid_policy() {
        let policy = parse_policy_yaml(TEST_POLICY).unwrap();
        assert_eq!(policy.name, "test");
        assert_eq!(policy.description, "a test policy");
        assert_eq!(policy.resources.len(), 1);
        let resource = policy.find_resource("users").unwrap();
        assert!(resource.has_permission("read"));
        assert!(resource.has_permission("update"));
        assert!(resource.has_permission("delete"));
        assert!(!resource.has_permission("nonexistent"));
        assert!(resource.has_relation("owner"));
        assert!(resource.has_relation("reader"));
        assert!(!resource.has_relation("nonexistent"));
    }

    #[test]
    fn test_find_missing_resource() {
        let policy = parse_policy_yaml(TEST_POLICY).unwrap();
        assert!(policy.find_resource("nonexistent").is_none());
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let result = parse_policy_yaml("{{invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_policy_name() {
        let policy = parse_policy_yaml(TEST_POLICY).unwrap();
        assert_eq!(policy.name, "test");
    }

    #[test]
    fn test_parse_permission_expr() {
        let policy = parse_policy_yaml(TEST_POLICY).unwrap();
        let resource = policy.find_resource("users").unwrap();
        let read_perm = resource
            .permissions
            .iter()
            .find(|p| p.name == "read")
            .unwrap();
        assert_eq!(read_perm.expr, "owner + reader");
    }
}

#[cfg(test)]
mod expansion_tests {
    use super::parse_policy_yaml;

    #[test]
    fn policy_alias_expansion_is_bounded_before_schema_conversion() {
        let yaml = format!(
            "name: aliases\nresources:\n  - &item\n    name: file\n    description: {}\n{}",
            "x".repeat(16 * 1024),
            "  - *item\n".repeat(128),
        );
        assert!(yaml.len() < 64 * 1024);
        let error = parse_policy_yaml(&yaml)
            .err()
            .expect("expanded policy must fail");
        assert!(error.contains("expansion exceeds byte limit"), "{error}");
    }

    #[test]
    fn ordinary_aliases_remain_supported() {
        let parsed = parse_policy_yaml("name: aliases\ndescription: &text shared\nresources:\n  - name: file\n    description: *text\n").unwrap();
        assert_eq!(parsed.description, "shared");
        assert_eq!(parsed.resources[0].description, "shared");
    }

    #[test]
    fn expanded_collections_are_bounded_even_without_large_strings() {
        let yaml = format!(
            "name: aliases\nunknown: &row [{}]\nother: [{}]\n",
            "0,".repeat(100),
            "*row,".repeat(1000)
        );
        assert!(yaml.len() < 64 * 1024);
        let error = parse_policy_yaml(&yaml)
            .err()
            .expect("expanded collection must fail");
        assert!(error.contains("expansion exceeds node limit"), "{error}");
    }
}
