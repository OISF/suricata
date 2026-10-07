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

/// An error in a command line override.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverrideError {
    /// A `--set` argument without `=`.
    #[error("invalid argument for --set {0:?}: expected path=value")]
    MissingEquals(String),
    /// An empty path, or a path with an empty component like `a..b`.
    #[error("invalid argument for --set: invalid path {0:?}")]
    InvalidPath(String),
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
    let path = path.trim_end();
    let segments: Vec<String> = path.split('.').map(String::from).collect();
    if segments.iter().any(String::is_empty) {
        return Err(OverrideError::InvalidPath(path.to_string()));
    }
    Ok(Override {
        path: segments,
        value: value.trim_start().to_string(),
    })
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

    // The root mapping is level 1 and the value is not a level, so the
    // deepest mapping of a path is at the depth of its component count,
    // whatever already exists along the path.
    for Override { path, .. } in overrides {
        if path.len() > MAX_NESTING_DEPTH {
            return Err(OverrideError::Apply {
                path: path.join("."),
                reason: format!("maximum nesting depth of {MAX_NESTING_DEPTH} exceeded"),
            });
        }
    }

    let mut root = match config {
        Node::Null => Mapping::new(),
        Node::Mapping(mapping) => mapping.clone(),
        _ => {
            return Err(OverrideError::Apply {
                path: overrides[0].path.join("."),
                reason: "the configuration is not a mapping".into(),
            })
        }
    };

    for Override { path, value } in overrides {
        let node = path_node_mut(&mut root, path).map_err(|reason| OverrideError::Apply {
            path: path.join("."),
            reason,
        })?;
        *node = Node::Scalar(value.clone());
    }

    *config = Node::Mapping(root);
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
