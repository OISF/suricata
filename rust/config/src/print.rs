// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! Printing of configurations.
//!
//! Unlike loading, printing recurses. A loaded configuration is nested at
//! most [`MAX_NESTING_DEPTH`](crate::MAX_NESTING_DEPTH) levels deep.

use std::borrow::Cow;

use saphyr::Scalar;
use saphyr::Yaml;
use saphyr::YamlEmitter;

use crate::node::Node;

/// Print a configuration in the format of `suricata --dump-config`.
///
/// Each node is printed as `path = value`, with `(null)` for a node
/// without a value. Like the C configuration tree, a mapping in a
/// sequence has the first key of the mapping as its value.
pub fn print_flat_config(config: &Node) -> String {
    let mut output = String::new();
    print_children("", config, &mut output);
    output
}

// Print the children of a node, with `prefix` as the path of the node.
fn print_children(prefix: &str, node: &Node, output: &mut String) {
    let path = |name: &str| {
        if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        }
    };

    match node {
        Node::Mapping(mapping) => {
            for (key, child) in mapping {
                print_node(&path(key), child, None, output);
            }
        }
        Node::Sequence(items) => {
            for (index, child) in items.iter().enumerate() {
                // A mapping in a sequence has its first key as value.
                let label = child
                    .as_mapping()
                    .and_then(|mapping| mapping.keys().next())
                    .map(String::as_str);
                print_node(&path(&index.to_string()), child, label, output);
            }
        }
        Node::Null | Node::Scalar(_) => {}
    }
}

// Print a node and its children. `label` is the value of a mapping or
// sequence, if it has one.
fn print_node(path: &str, node: &Node, label: Option<&str>, output: &mut String) {
    let value = match node {
        Node::Scalar(value) => value,
        _ => label.unwrap_or("(null)"),
    };
    output.push_str(&format!("{path} = {value}\n"));
    print_children(path, node, output);
}

/// Print a configuration as YAML.
pub fn print_yaml(config: &Node) -> Result<String, saphyr::EmitError> {
    let mut output = String::new();
    YamlEmitter::new(&mut output).dump(&to_yaml(config))?;
    // The emitter leaves the last line unterminated.
    output.push('\n');
    Ok(output)
}

// Convert a configuration to a saphyr document.
fn to_yaml(node: &Node) -> Yaml<'_> {
    fn string(value: &str) -> Yaml<'_> {
        Yaml::Value(Scalar::String(Cow::Borrowed(value)))
    }

    match node {
        Node::Null => Yaml::Value(Scalar::Null),
        Node::Scalar(value) => string(value),
        Node::Sequence(items) => Yaml::Sequence(items.iter().map(to_yaml).collect()),
        Node::Mapping(mapping) => Yaml::Mapping(
            mapping
                .iter()
                .map(|(key, value)| (string(key), to_yaml(value)))
                .collect(),
        ),
    }
}
