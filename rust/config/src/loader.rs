// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::path::PathBuf;

use saphyr::MappingOwned;
use saphyr::ScalarOwned;
use saphyr::Tag;
use saphyr::YamlOwned;

use crate::Config;
use crate::ParseError;
use thiserror::Error;

const INCLUDE_RECURSION_LIMIT: usize = 128;

/// Errors returned while loading a configuration file.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("invalid include directive: {0}")]
    InvalidInclude(String),
    #[error("maximum include recursion level reached ({0})")]
    IncludeRecursionLimit(usize),
}

/// Parse a configuration file and apply transformations (includes, etc).
pub fn load_file(path: &Path) -> Result<Config, LoadError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let config = load_yaml_file(path)?;

    finalize_config(config, dir)
}

/// Parse a configuration string and apply transformations (includes, etc).
pub fn load_string(input: &str) -> Result<Config, LoadError> {
    let config = crate::parse_yaml(input)?;
    finalize_config(config, Path::new("."))
}

// Apply all post-parse loader transformations to a parsed config tree.
fn finalize_config(mut config: Config, dir: &Path) -> Result<Config, LoadError> {
    resolve_includes(&mut config, dir, 0)?;
    config = unwrap_tagged_values(config);
    apply_dotted_overrides(&mut config);

    Ok(config)
}

// Read and parse one YAML file without applying loader transformations.
fn load_yaml_file(path: &Path) -> Result<Config, LoadError> {
    let input = std::fs::read_to_string(path)?;
    crate::parse_yaml(&input).map_err(LoadError::from)
}

// Recursively resolve include directives and !include tags in a YAML node.
fn resolve_includes(node: &mut Config, dir: &Path, depth: usize) -> Result<(), LoadError> {
    if depth > INCLUDE_RECURSION_LIMIT {
        return Err(LoadError::IncludeRecursionLimit(INCLUDE_RECURSION_LIMIT));
    }

    if let Some(path) = include_path_from_tag(node)? {
        let (mut include, include_path) = load_include(dir, path)?;
        resolve_includes(&mut include, &include_path, depth + 1)?;
        *node = include;
        return Ok(());
    }

    match node {
        YamlOwned::Mapping(mapping) => resolve_mapping_includes(mapping, dir, depth),
        YamlOwned::Sequence(sequence) => {
            for value in sequence {
                resolve_includes(value, dir, depth)?;
            }
            Ok(())
        }
        YamlOwned::Tagged(_, value) => resolve_includes(value, dir, depth),
        _ => Ok(()),
    }
}

/// Resolve includes within a mapping.
///
/// Example:
///
/// `main.yaml`:
/// ```yaml
/// include:
///   - one.yaml
///   - two.yaml
/// ```
fn resolve_mapping_includes(
    mapping: &mut MappingOwned, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    let original_entries = mapping.clone();
    mapping.clear();

    for (key, mut value) in original_entries {
        if key.as_str() == Some("include") {
            inline_include_value(mapping, &value, include_dir, depth + 1)?;
            continue;
        }

        match include_path_from_tag(&value)? {
            Some(include_name) => {
                let (mut include, include_dir) = load_include(include_dir, include_name)?;
                resolve_includes(&mut include, &include_dir, depth + 1)?;
                value = include;
            }
            None => resolve_includes(&mut value, include_dir, depth)?,
        }

        upsert_mapping_entry(mapping, key, value);
    }

    Ok(())
}

// Extract the include filename from a !include tag if present.
fn include_path_from_tag(node: &YamlOwned) -> Result<Option<&str>, LoadError> {
    if let YamlOwned::Tagged(tag, value) = node {
        if is_include_tag(tag) {
            let Some(include_name) = value.as_str() else {
                return Err(LoadError::InvalidInclude(
                    "!include value must be a string".into(),
                ));
            };
            return Ok(Some(include_name));
        }
    }

    Ok(None)
}

// Inline one include value which can be a filename or a list of filenames.
fn inline_include_value(
    mapping: &mut MappingOwned, include_value: &YamlOwned, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    if include_value.is_null() {
        return Ok(());
    }

    if let Some(include_name) = include_value.as_str() {
        return inline_include_file(mapping, include_name, include_dir, depth);
    }

    let Some(sequence) = include_value.as_sequence() else {
        return Err(LoadError::InvalidInclude(
            "\"include\" expects a filename or a sequence of filenames".into(),
        ));
    };

    for entry in sequence {
        if entry.is_null() {
            continue;
        }

        let Some(include_name) = entry.as_str() else {
            return Err(LoadError::InvalidInclude(
                "\"include\" sequence entries must be strings".into(),
            ));
        };

        inline_include_file(mapping, include_name, include_dir, depth)?;
    }

    Ok(())
}

// Load one include file and merge its root mapping into the target mapping.
fn inline_include_file(
    mapping: &mut MappingOwned, name: &str, path: &Path, depth: usize,
) -> Result<(), LoadError> {
    let (mut include, include_dir) = load_include(path, name)?;
    resolve_includes(&mut include, &include_dir, depth)?;

    let YamlOwned::Mapping(include_mapping) = include else {
        return Err(LoadError::InvalidInclude(format!(
            "included file {name:?} must contain a mapping at the document root"
        )));
    };

    for (key, value) in include_mapping {
        upsert_mapping_entry(mapping, key, value);
    }

    Ok(())
}

// Insert a key/value pair or overwrite the existing value for that key.
fn upsert_mapping_entry(mapping: &mut MappingOwned, key: YamlOwned, value: YamlOwned) {
    if let Some(existing) = mapping.get_mut(&key) {
        *existing = value;
    } else {
        mapping.insert(key, value);
    }
}

// Remove all YAML tag wrappers from a parsed config tree.
fn unwrap_tagged_values(node: YamlOwned) -> YamlOwned {
    match node {
        YamlOwned::Tagged(_, value) => unwrap_tagged_values(*value),
        YamlOwned::Mapping(mapping) => {
            let mut unwrapped = MappingOwned::new();
            for (key, value) in mapping {
                unwrapped.insert(unwrap_tagged_values(key), unwrap_tagged_values(value));
            }
            YamlOwned::Mapping(unwrapped)
        }
        YamlOwned::Sequence(sequence) => {
            YamlOwned::Sequence(sequence.into_iter().map(unwrap_tagged_values).collect())
        }
        other => other,
    }
}

// Apply dotted-key overrides throughout the config tree.
fn apply_dotted_overrides(node: &mut Config) {
    match node {
        YamlOwned::Mapping(mapping) => apply_dotted_overrides_mapping(mapping),
        YamlOwned::Sequence(sequence) => {
            for value in sequence {
                apply_dotted_overrides(value);
            }
        }
        YamlOwned::Tagged(_, value) => apply_dotted_overrides(value),
        _ => {}
    }
}

// Expand dotted keys in a mapping into nested mapping paths.
fn apply_dotted_overrides_mapping(mapping: &mut MappingOwned) {
    let entries = mapping.clone();
    mapping.clear();

    for (key, mut value) in entries {
        apply_dotted_overrides(&mut value);

        if let Some(segments) = dotted_key_segments(&key) {
            apply_dotted_override(mapping, &segments, value);
        } else {
            upsert_mapping_entry(mapping, key, value);
        }
    }
}

// Split a dotted mapping key into path segments when applicable.
fn dotted_key_segments(key: &YamlOwned) -> Option<Vec<&str>> {
    let key = key.as_str()?;
    if !key.contains('.') {
        return None;
    }

    let segments: Vec<&str> = key.split('.').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }

    Some(segments)
}

// Apply one dotted key override into the target mapping.
fn apply_dotted_override(mapping: &mut MappingOwned, segments: &[&str], value: YamlOwned) {
    let Some((leaf, parents)) = segments.split_last() else {
        return;
    };

    let mut current = mapping;

    for segment in parents {
        let key = YamlOwned::Value(ScalarOwned::String(segment.to_string()));
        if !current.contains_key(&key) {
            current.insert(key.clone(), YamlOwned::Mapping(MappingOwned::new()));
        }

        let Some(child) = current.get_mut(&key) else {
            return;
        };

        if mapping_node_mut(child).is_none() {
            *child = YamlOwned::Mapping(MappingOwned::new());
        }

        let Some(next) = mapping_node_mut(child) else {
            return;
        };
        current = next;
    }

    let key = YamlOwned::Value(ScalarOwned::String(leaf.to_string()));
    upsert_mapping_entry(current, key, value);
}

// Return a mutable mapping view for plain or tagged mapping nodes.
fn mapping_node_mut(node: &mut YamlOwned) -> Option<&mut MappingOwned> {
    match node {
        YamlOwned::Mapping(mapping) => Some(mapping),
        YamlOwned::Tagged(_, value) => mapping_node_mut(value),
        _ => None,
    }
}

// Load an include returning the parsed include and its path.
fn load_include(dir: &Path, name: &str) -> Result<(Config, PathBuf), LoadError> {
    let path = if Path::new(name).is_absolute() {
        PathBuf::from(name)
    } else {
        dir.join(name)
    };

    let include_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let include = load_yaml_file(&path)?;

    Ok((include, include_dir))
}

// Check whether a YAML tag is !include.
fn is_include_tag(tag: &Tag) -> bool {
    tag.handle == "!" && tag.suffix == "include"
}
