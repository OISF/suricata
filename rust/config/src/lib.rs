// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! Suricata configuration loading.
//!
//! A configuration is loaded from YAML into a tree of [`Node`]s with
//! [`load_file`] or [`load_string`], which apply includes and dotted
//! keys; see `loader.rs` for the rules.

mod loader;
mod node;
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
