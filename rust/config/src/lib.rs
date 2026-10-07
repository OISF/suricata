// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! Suricata configuration loading.
//!
//! A configuration is loaded from YAML into a tree of [`Node`]s. See
//! [`loader`] for how includes and dotted keys are applied.
//!
//! Values given on the command line, like `--set stream.midstream=true`,
//! are collected as a list of [`Override`]s in the order they were
//! given, to be applied to a configuration after it is loaded, and again
//! after each reload, rather than being set before the load and
//! protected while loading as the C loader did. Applying the overrides
//! is not implemented yet.

pub mod loader;
pub mod node;
mod print;

pub use loader::load_file;
pub use loader::load_file_with_include_dir;
pub use loader::load_string;
pub use loader::load_string_with_include_dir;
pub use loader::merge_file;
pub use loader::LoadError;
pub use loader::Location;
pub use node::Mapping;
pub use node::Node;
pub use print::print_flat_config;
pub use print::print_yaml;

/// A loaded configuration, the root mapping.
pub type Config = Node;

/// Maximum nesting depth of a configuration, counting the root mapping.
/// This is the same limit as the C loader had, but applies to the whole
/// configuration, including included files and the parts of dotted
/// keys.
pub const MAX_NESTING_DEPTH: usize = 128;

/// Maximum depth of included files including other files.
pub const MAX_INCLUDE_DEPTH: usize = 128;

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
}
