// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashSet;
use std::path::Path;

use jsonschema::output::BasicOutput;
use jsonschema::Draft;
use jsonschema::JSONSchema;
use serde_json::Value;
use thiserror::Error;

/// Errors returned while loading a JSON schema file.
#[derive(Debug, Error)]
pub enum LoadSchemaError {
    #[error("failed to read schema file: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse schema json: {0}")]
    Parse(#[from] serde_json::Error),
}

/// One schema validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{path}: {message}")]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

/// Load a JSON schema file from disk.
pub fn load_schema_file(path: &Path) -> Result<Value, LoadSchemaError> {
    let input = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&input)?)
}

/// Validate one JSON document against a JSON Schema using the `jsonschema`
/// crate.
///
/// Returns all validation issues. If the schema itself is invalid, one
/// root-level issue is returned with details.
pub fn validate_json_schema(instance: &Value, schema: &Value) -> Vec<ValidationError> {
    let compiled = match JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
    {
        Ok(compiled) => compiled,
        Err(err) => {
            return vec![ValidationError {
                path: "/".into(),
                message: format!("invalid schema: {err}"),
            }];
        }
    };

    let mut issues = match compiled.apply(instance).basic() {
        BasicOutput::Valid(_) => Vec::new(),
        BasicOutput::Invalid(errors) => errors
            .into_iter()
            .map(|error| DetailedValidationIssue {
                path: json_pointer_or_root(error.instance_location().to_string()),
                schema_path: json_pointer_or_root(error.keyword_location().to_string()),
                message: error.error_description().to_string(),
            })
            .collect(),
    };

    issues = dedupe_issues(issues);
    issues.sort_by(|lhs, rhs| {
        pointer_depth(&rhs.path)
            .cmp(&pointer_depth(&lhs.path))
            .then_with(|| lhs.path.cmp(&rhs.path))
            .then_with(|| lhs.message.cmp(&rhs.message))
    });

    issues
        .into_iter()
        .map(|issue| ValidationError {
            path: issue.path,
            message: issue.message,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DetailedValidationIssue {
    path: String,
    schema_path: String,
    message: String,
}

fn dedupe_issues(issues: Vec<DetailedValidationIssue>) -> Vec<DetailedValidationIssue> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut unique = Vec::new();

    for issue in issues {
        let key = (issue.path.clone(), issue.message.clone());
        if seen.insert(key) {
            unique.push(issue);
        }
    }

    unique
}

fn pointer_depth(path: &str) -> usize {
    if path == "/" {
        return 0;
    }

    path.split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

fn json_pointer_or_root(pointer: String) -> String {
    if pointer.is_empty() {
        "/".into()
    } else {
        pointer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("suricata-config-{name}-{unique}.json"))
    }

    #[test]
    fn test_load_schema_file_ok() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("suricata-yaml.schema.json");

        let schema = load_schema_file(&path).expect("schema file should load");

        assert_eq!(
            schema["$schema"],
            json!("https://json-schema.org/draft/2020-12/schema")
        );
    }

    #[test]
    fn test_load_schema_file_parse_err() {
        let path = temp_path("invalid-schema");
        std::fs::write(&path, "{not-json}").expect("invalid schema file should be written");

        let err = load_schema_file(&path).expect_err("invalid json should fail");
        let _ = std::fs::remove_file(&path);

        assert!(matches!(err, LoadSchemaError::Parse(_)));
    }

    #[test]
    fn test_load_schema_file_read_err() {
        let path = temp_path("missing-schema");

        let err = load_schema_file(&path).expect_err("missing file should fail");

        assert!(matches!(err, LoadSchemaError::Read(_)));
    }

    #[test]
    fn test_pointer_depth() {
        assert_eq!(pointer_depth("/"), 0);
        assert_eq!(pointer_depth("/value"), 1);
        assert_eq!(pointer_depth("/one/two/three"), 3);
    }

    #[test]
    fn test_dedupe_issues() {
        let issues = vec![
            DetailedValidationIssue {
                path: "/value".into(),
                schema_path: "/properties/value/type".into(),
                message: "must be integer".into(),
            },
            DetailedValidationIssue {
                path: "/value".into(),
                schema_path: "/properties/value/anyOf/0/type".into(),
                message: "must be integer".into(),
            },
            DetailedValidationIssue {
                path: "/value".into(),
                schema_path: "/properties/value/minimum".into(),
                message: "must be greater than or equal to 1".into(),
            },
        ];

        let deduped = dedupe_issues(issues);

        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].schema_path, "/properties/value/type");
        assert_eq!(deduped[1].message, "must be greater than or equal to 1");
    }

    #[test]
    fn test_validate_json_schema_sorts() {
        let errors = validate_json_schema(
            &json!({
                "outer": {}
            }),
            &json!({
                "type": "object",
                "required": ["top"],
                "properties": {
                    "outer": {
                        "type": "object",
                        "required": ["inner"]
                    }
                }
            }),
        );

        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].path, "/outer");
        assert_eq!(errors[1].path, "/");
    }

    #[test]
    fn test_validate_json_schema_ok() {
        let errors = validate_json_schema(
            &json!({
                "enabled": true,
                "threshold": 10
            }),
            &json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "threshold": { "type": "integer" }
                },
                "required": ["enabled", "threshold"]
            }),
        );

        assert!(errors.is_empty());
    }
}
