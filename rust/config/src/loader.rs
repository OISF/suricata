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
    let include_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let config = load_yaml_file(path)?;

    finalize_config(config, include_dir)
}

/// Parse a configuration string and apply transformations (includes, etc).
pub fn load_string(input: &str) -> Result<Config, LoadError> {
    let config = crate::parse_yaml(input)?;
    finalize_config(config, Path::new("."))
}

// Apply all post-parse loader transformations to a parsed config tree.
fn finalize_config(mut config: Config, include_dir: &Path) -> Result<Config, LoadError> {
    resolve_includes(&mut config, include_dir, 0)?;
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
fn resolve_includes(node: &mut Config, include_dir: &Path, depth: usize) -> Result<(), LoadError> {
    if depth > INCLUDE_RECURSION_LIMIT {
        return Err(LoadError::IncludeRecursionLimit(INCLUDE_RECURSION_LIMIT));
    }

    match node {
        YamlOwned::Mapping(mapping) => resolve_mapping_includes(mapping, include_dir, depth),
        YamlOwned::Sequence(sequence) => {
            for value in sequence {
                resolve_includes(value, include_dir, depth)?;
            }
            Ok(())
        }
        YamlOwned::Tagged(_, value) => resolve_includes(value, include_dir, depth),
        _ => Ok(()),
    }
}

/// Resolve includes within a mapping.
///
/// Entries are processed in document order with last-writer-wins
/// semantics. When an `include:` key is encountered, the included
/// file(s) are inlined into the mapping. Keys that appear later in
/// the parent file, or in later entries of an include sequence,
/// override earlier ones.
fn resolve_mapping_includes(
    mapping: &mut MappingOwned, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    let entries = std::mem::take(mapping).into_iter().collect::<Vec<_>>();

    for (key, mut value) in entries {
        if key.as_str() == Some("include") {
            inline_include_value(mapping, &value, include_dir, depth + 1)?;
            continue;
        }

        match include_path_from_tag(&value)? {
            Some(include_name) => {
                let (mut included, included_dir) = load_include(include_dir, include_name)?;
                resolve_includes(&mut included, &included_dir, depth + 1)?;
                value = included;
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
    mapping: &mut MappingOwned, include_name: &str, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    let (mut included, included_dir) = load_include(include_dir, include_name)?;
    resolve_includes(&mut included, &included_dir, depth)?;

    let YamlOwned::Mapping(included_mapping) = included else {
        return Err(LoadError::InvalidInclude(format!(
            "included file {include_name:?} must contain a mapping at the document root"
        )));
    };

    for (key, value) in included_mapping {
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
    let entries = std::mem::take(mapping).into_iter().collect::<Vec<_>>();

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

    let segments = key.split('.').collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }

    Some(segments)
}

// Apply one dotted key override into the target mapping.
fn apply_dotted_override(mapping: &mut MappingOwned, segments: &[&str], value: YamlOwned) {
    if segments.is_empty() {
        return;
    }

    let mut current = mapping;

    for segment in &segments[..segments.len() - 1] {
        let segment_key = dotted_segment_key(segment);
        if !current.contains_key(&segment_key) {
            current.insert(segment_key.clone(), YamlOwned::Mapping(MappingOwned::new()));
        }

        let Some(child) = current.get_mut(&segment_key) else {
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

    let leaf_key = dotted_segment_key(segments[segments.len() - 1]);
    upsert_mapping_entry(current, leaf_key, value);
}

// Return a mutable mapping view for plain or tagged mapping nodes.
fn mapping_node_mut(node: &mut YamlOwned) -> Option<&mut MappingOwned> {
    match node {
        YamlOwned::Mapping(mapping) => Some(mapping),
        YamlOwned::Tagged(_, value) => mapping_node_mut(value),
        _ => None,
    }
}

// Build a YAML string key node for a dotted-path segment.
fn dotted_segment_key(segment: &str) -> YamlOwned {
    YamlOwned::Value(ScalarOwned::String(segment.into()))
}

// Resolve and load one include file and return it with its base directory.
fn load_include(include_dir: &Path, include_name: &str) -> Result<(Config, PathBuf), LoadError> {
    let include_path = if Path::new(include_name).is_absolute() {
        PathBuf::from(include_name)
    } else {
        include_dir.join(include_name)
    };

    let included_dir = include_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let included = load_yaml_file(&include_path)?;

    Ok((included, included_dir))
}

// Check whether a YAML tag corresponds to !include.
fn is_include_tag(tag: &Tag) -> bool {
    tag.handle == "!" && tag.suffix == "include"
}
