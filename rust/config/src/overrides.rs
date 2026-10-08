// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! Command line overrides, like `--set stream.midstream=true`.
//!
//! Overrides are collected as a list of [`Override`]s in the order they
//! were given, and applied to a configuration after it is loaded with
//! [`apply_overrides`]. The C loader instead set them before the load
//! and protected them with final flags while loading; the result is the
//! same, the command line wins, but without final flags and the prune
//! and merge rules around them. The visible differences are the position
//! of the overridden nodes (a key that exists in the file keeps its
//! position, a new key is appended) and that a node that was overridden
//! does not keep children or a value from the file.

use crate::node::path_node_mut;
use crate::node::PathError;
use crate::Config;
use crate::Mapping;
use crate::Node;
use crate::MAX_NESTING_DEPTH;

/// A command line override: the value for the node at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    /// The components of the path, like `["stream", "midstream"]`.
    pub path: Vec<String>,
    /// The value, as given. Like a scalar in a configuration file it is
    /// kept as text, so `--set x=` is the empty string, not null.
    pub value: String,
}

impl Override {
    /// An override of the node at a dotted path, like
    /// `stream.midstream`, with a value. Both are used as given; see
    /// [`parse_set`] for the trimming of a `--set` argument.
    pub fn new(path: &str, value: &str) -> Result<Override, OverrideError> {
        let segments: Vec<String> = path.split('.').map(String::from).collect();
        if segments.iter().any(String::is_empty) {
            return Err(OverrideError::InvalidPath(path.to_string()));
        }
        Ok(Override {
            path: segments,
            value: value.to_string(),
        })
    }
}

/// An error in a command line override.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverrideError {
    /// A `--set` argument without `=`.
    #[error("invalid argument for --set {0:?}: expected path=value")]
    MissingEquals(String),
    /// An empty path, or a path with an empty component like `a..b`.
    #[error("invalid argument for --set: invalid path {0:?}")]
    InvalidPath(String),
    /// A component of the path names a child of a sequence, which only
    /// has indexes, like `pcap.buffer-size` where `pcap` is a sequence.
    #[error("cannot apply --set {path}: {source}")]
    NotAnIndex { path: String, source: PathError },
    /// An override could not be applied to the configuration, like an
    /// index past the end of a sequence.
    #[error("cannot apply --set {path}: {reason}")]
    Apply { path: String, reason: String },
}

/// Parse a `--set` argument of the form `path=value`.
///
/// Like Suricata, whitespace is trimmed from the end of the path and the
/// start of the value, so `--set 'a = b'` sets `a` to `b`. The value may
/// contain `=`, and may be empty.
pub fn parse_set(arg: &str) -> Result<Override, OverrideError> {
    let Some((path, value)) = arg.split_once('=') else {
        return Err(OverrideError::MissingEquals(arg.to_string()));
    };
    Override::new(path.trim_end(), value.trim_start())
}

/// Apply one command line override to a loaded configuration, and
/// return its path as resolved, with the indexes of sequences in their
/// canonical form (`00` is `0`). See [`apply_overrides`] for the rules.
///
/// On error the configuration is left unchanged.
pub fn apply_override(
    config: &mut Config, override_: &Override,
) -> Result<Vec<String>, OverrideError> {
    let Override { path, value } = override_;

    // The root mapping is level 1 and the value is not a level, so the
    // deepest mapping of a path is at the depth of its component count,
    // whatever already exists along the path.
    if path.len() > MAX_NESTING_DEPTH {
        return Err(OverrideError::Apply {
            path: path.join("."),
            reason: format!("maximum nesting depth of {MAX_NESTING_DEPTH} exceeded"),
        });
    }

    let mut empty = Mapping::new();
    let root = match config {
        Node::Null => &mut empty,
        Node::Mapping(root) => root,
        _ => {
            return Err(OverrideError::Apply {
                path: path.join("."),
                reason: "the configuration is not a mapping".into(),
            })
        }
    };

    // An error of the walk is at a sequence, which exists already, as
    // do all the nodes before it, so the walk has not changed anything
    // when it fails.
    let (node, resolved) = path_node_mut(root, path).map_err(|source| match source {
        PathError::NotAnIndex { .. } => OverrideError::NotAnIndex {
            path: path.join("."),
            source,
        },
        _ => OverrideError::Apply {
            path: path.join("."),
            reason: source.to_string(),
        },
    })?;
    *node = Node::Scalar(value.clone());
    if config.is_null() {
        *config = Node::Mapping(empty);
    }
    Ok(resolved)
}

/// Apply command line overrides to a loaded configuration, in order, so
/// a later override of the same path wins.
///
/// Each override replaces the node at its path with its value, whatever
/// the node was: a mapping or sequence at the path is replaced, not
/// given a value next to its children. Mappings are created along the
/// path as needed, and a scalar along the path is replaced with a
/// mapping. A number selects an item of a sequence, the length of the
/// sequence appends an item, anything beyond is an error. The indexes
/// refer to the configuration as loaded, after includes and dotted keys
/// have been applied. Like a dotted key, each component of the path is
/// a level of nesting, limited to [`MAX_NESTING_DEPTH`].
///
/// On error the configuration is left unchanged.
pub fn apply_overrides(config: &mut Config, overrides: &[Override]) -> Result<(), OverrideError> {
    if overrides.is_empty() {
        return Ok(());
    }
    let mut applied = config.clone();
    for override_ in overrides {
        apply_override(&mut applied, override_)?;
    }
    *config = applied;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(arg: &str) -> (String, String) {
        let o = parse_set(arg).unwrap();
        (o.path.join("."), o.value)
    }

    #[test]
    fn test_parse_set() {
        assert_eq!(
            parse_set("stream.midstream=true").unwrap(),
            Override {
                path: vec!["stream".into(), "midstream".into()],
                value: "true".into(),
            }
        );
        assert_eq!(
            set("outputs.1.eve-log.enabled=no"),
            ("outputs.1.eve-log.enabled".into(), "no".into())
        );
        // Whitespace is trimmed from the end of the path and the start
        // of the value only, like Suricata.
        assert_eq!(set(" a = value "), (" a".into(), "value ".into()));
        // The value may contain '=', and may be empty.
        assert_eq!(set("eq=a=b"), ("eq".into(), "a=b".into()));
        assert_eq!(set("empty="), ("empty".into(), "".into()));
        // Values are kept as text, so this is the string "~".
        assert_eq!(set("tilde=~"), ("tilde".into(), "~".into()));
        // Unlike the C loader there is no limit on the length of a name.
        let name = "b".repeat(2048);
        assert_eq!(parse_set(&format!("a.{name}=ok")).unwrap().path[1], name);
    }

    #[test]
    fn test_parse_set_errors() {
        assert_eq!(
            parse_set("foo"),
            Err(OverrideError::MissingEquals("foo".into()))
        );
        // An empty path, or a path with an empty component.
        for arg in ["=x", "  =x", "foo..x=1", "foo.y.=2", ".z=3"] {
            assert!(
                matches!(parse_set(arg), Err(OverrideError::InvalidPath(_))),
                "{arg}"
            );
        }
    }

    #[test]
    fn test_apply_to_empty_config() {
        let mut config = Node::Null;
        apply_overrides(&mut config, &[parse_set("a.b=1").unwrap()]).unwrap();
        assert_eq!(config["a"]["b"].as_str(), Some("1"));

        // Nothing to apply leaves a null configuration alone.
        let mut config = Node::Null;
        apply_overrides(&mut config, &[]).unwrap();
        assert!(config.is_null());
    }

    #[test]
    fn test_apply_override_resolved_path() {
        let mut config = crate::load_string("list: [a, b]\nmap: {k: v}\n").unwrap();
        let set = |arg| parse_set(arg).unwrap();
        assert_eq!(
            apply_override(&mut config, &set("list.00=x")).unwrap(),
            ["list", "0"]
        );
        assert_eq!(
            apply_override(&mut config, &set("list.+2=y")).unwrap(),
            ["list", "2"]
        );
        assert_eq!(
            apply_override(&mut config, &set("map.k=w")).unwrap(),
            ["map", "k"]
        );
        assert_eq!(config["list"][0].as_str(), Some("x"));
        assert_eq!(config["list"][2].as_str(), Some("y"));

        // A name into a sequence is its own error, the C side handles it.
        let before = config.clone();
        let err = apply_override(&mut config, &set("list.name=z")).unwrap_err();
        assert!(matches!(err, OverrideError::NotAnIndex { .. }), "{err}");
        assert_eq!(
            err.to_string(),
            "cannot apply --set list.name: \"name\" is not a valid index for a sequence of length 3"
        );
        let err = apply_override(&mut config, &set("list.5=z")).unwrap_err();
        assert!(matches!(err, OverrideError::Apply { .. }), "{err}");
        assert_eq!(config, before);
    }

    #[test]
    fn test_apply_to_non_mapping() {
        let mut config = Node::Scalar("x".into());
        let err = apply_overrides(&mut config, &[parse_set("a=1").unwrap()]).unwrap_err();
        assert!(matches!(err, OverrideError::Apply { .. }), "{err}");
        assert_eq!(config, Node::Scalar("x".into()));
    }

    #[test]
    fn test_apply_nesting_limit() {
        let set = |n: usize| parse_set(&format!("{}=1", vec!["a"; n].join("."))).unwrap();
        let mut config = Node::Null;
        apply_overrides(&mut config, &[set(128)]).unwrap();
        // The result can be printed, which recurses.
        assert_eq!(crate::print_flat_config(&config).lines().count(), 128);

        let before = config.clone();
        let err = apply_overrides(&mut config, &[set(129)]).unwrap_err();
        assert!(
            err.to_string()
                .ends_with("maximum nesting depth of 128 exceeded"),
            "{err}"
        );
        assert_eq!(config, before);
    }

    #[test]
    fn test_apply_error_leaves_config_unchanged() {
        let mut config = Node::Mapping(Mapping::from([(
            "list".to_string(),
            Node::Sequence(vec![Node::Scalar("a".into())]),
        )]));
        let before = config.clone();
        let overrides = [parse_set("new=1").unwrap(), parse_set("list.5=q").unwrap()];
        let err = apply_overrides(&mut config, &overrides).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot apply --set list.5: \"5\" is not a valid index for a sequence of length 1"
        );
        assert_eq!(config, before);
    }
}
