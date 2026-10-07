// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! Suricata configuration loading.
//!
//! A configuration is loaded from YAML into a tree of [`Node`]s. See
//! [`loader`] for how includes and dotted keys are applied.
//!
//! Values given on the command line, like `--set stream.midstream=true`,
//! are collected as a list of [`Override`]s in the order they were
//! given, and applied to a configuration after it is loaded with
//! [`apply_overrides`]. See [`overrides`].

pub mod loader;
pub mod node;
pub mod overrides;
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
pub use overrides::apply_overrides;
pub use overrides::parse_set;
pub use overrides::Override;
pub use overrides::OverrideError;
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
