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
use crate::MAX_NESTING_DEPTH;
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
    #[error("invalid dotted key {key:?}: {reason}")]
    InvalidDottedKey { key: String, reason: String },
    #[error("maximum nesting depth exceeded ({0})")]
    NestingLimit(usize),
}

/// Parse a configuration file and apply transformations (includes, etc).
///
/// Relative include paths, including those in included files, are
/// resolved from the directory of this file.
pub fn load_file(path: &Path) -> Result<Config, LoadError> {
    let include_dir = path.parent().unwrap_or_else(|| Path::new("."));
    load_file_with_include_dir(path, include_dir)
}

/// Parse a configuration file and apply transformations (includes, etc).
///
/// Relative include paths, including those in included files, are
/// resolved from `include_dir`. This matches the C loader, which resolves
/// all includes from the directory of the top-level configuration file.
pub fn load_file_with_include_dir(path: &Path, include_dir: &Path) -> Result<Config, LoadError> {
    load_file_for_merge(path, include_dir).map(unwrap_tagged_values)
}

/// Parse a configuration string and apply transformations (includes, etc).
pub fn load_string(input: &str) -> Result<Config, LoadError> {
    load_string_for_merge(input).map(unwrap_tagged_values)
}

/// Like [`load_file_with_include_dir`], for merging the configuration into
/// an existing one. Mappings that only exist through dotted keys are
/// marked, see [`take_merge_mark`].
pub(crate) fn load_file_for_merge(path: &Path, include_dir: &Path) -> Result<Config, LoadError> {
    let config = load_yaml_file(path)?;

    finalize_config(config, include_dir)
}

/// Like [`load_string`], for merging the configuration into an existing
/// one. Mappings that only exist through dotted keys are marked, see
/// [`take_merge_mark`].
pub(crate) fn load_string_for_merge(input: &str) -> Result<Config, LoadError> {
    let config = crate::parse_yaml(input)?;
    finalize_config(config, Path::new("."))
}

/// Remove the mark from a mapping that only exists through dotted keys,
/// and return whether it was marked.
///
/// A dotted key, like `vars.address-groups.HOME_NET`, sets a value without
/// replacing the existing nodes along the path, while any other key
/// replaces the existing node. The loader resolves this within a
/// configuration, but when the configuration is merged into an existing
/// one, like a file loaded with --include, the marked mappings must be
/// merged into the existing nodes of the same name instead of replacing
/// them.
pub(crate) fn take_merge_mark(node: YamlOwned) -> (YamlOwned, bool) {
    match node {
        YamlOwned::Tagged(tag, node) if is_merge_tag(&tag) => (*node, true),
        node => (node, false),
    }
}

// Apply all post-parse loader transformations to a parsed config tree.
fn finalize_config(config: Config, include_dir: &Path) -> Result<Config, LoadError> {
    Resolver::new(include_dir).resolve(config)
}

// Read and parse one YAML file without applying loader transformations.
fn load_yaml_file(path: &Path) -> Result<Config, LoadError> {
    let input = std::fs::read_to_string(path)?;
    crate::parse_yaml(&input).map_err(LoadError::from)
}

// Where a resolved value goes when it is complete.
enum Dest {
    // The resolved configuration.
    Root,
    // Insert or replace the entry for a key in the parent mapping.
    Key(YamlOwned),
    // Replace the node at a dotted key path in the parent mapping. If
    // `merge` is set, a mapping is marked as only existing through dotted
    // keys.
    Path { segments: Vec<String>, merge: bool },
    // Append to the parent sequence.
    Push,
}

// Mapping entries still to be applied, from a document or an included
// file, with the include depth they were loaded at.
struct Entries {
    entries: std::vec::IntoIter<(YamlOwned, YamlOwned)>,
    include_depth: usize,
}

impl Entries {
    fn new(mapping: MappingOwned, include_depth: usize) -> Self {
        Self {
            entries: mapping.into_iter().collect::<Vec<_>>().into_iter(),
            include_depth,
        }
    }
}

// A mapping or sequence being resolved. `depth` is its nesting depth,
// counting the root.
enum Frame {
    Mapping {
        target: MappingOwned,
        // Runs of entries to apply, the last one first. An inlined
        // include pushes a new run, so its entries are applied before
        // the entries after the include.
        pending: Vec<Entries>,
        dest: Dest,
        depth: usize,
    },
    Sequence {
        items: Vec<YamlOwned>,
        pending: std::vec::IntoIter<YamlOwned>,
        include_depth: usize,
        dest: Dest,
        depth: usize,
    },
}

// The next step of resolving the frame on top of the stack.
enum Step {
    Entry {
        key: YamlOwned,
        value: YamlOwned,
        depth: usize,
        include_depth: usize,
    },
    Item {
        value: YamlOwned,
        depth: usize,
        include_depth: usize,
    },
    Finish,
}

/// Resolves includes and dotted keys in a parsed config, and removes YAML
/// tags.
///
/// Entries are applied in document order with last-writer-wins
/// semantics, matching the C loader:
///
/// - An `include:` key inlines the entries of the included file(s) at
///   this point, so later entries override them.
/// - A dotted key walks the path below the target, creating mappings as
///   needed, and merges the value into the node found there. Numeric
///   path segments index into sequences.
/// - Any other key replaces an existing value.
///
/// Mappings created by dotted keys are marked as merged, see
/// [`take_merge_mark`], until a plain key replaces them.
///
/// This is not recursive. The mappings and sequences being resolved are
/// kept on a stack, and the nesting depth of the result, including
/// included files and dotted keys, is limited to [`MAX_NESTING_DEPTH`].
struct Resolver<'a> {
    include_dir: &'a Path,
    stack: Vec<Frame>,
    result: Option<YamlOwned>,
}

impl<'a> Resolver<'a> {
    fn new(include_dir: &'a Path) -> Self {
        Self {
            include_dir,
            stack: Vec::new(),
            result: None,
        }
    }

    fn resolve(mut self, config: Config) -> Result<Config, LoadError> {
        self.start_value(config, Dest::Root, 0, 0)?;

        while let Some(step) = self.next_step() {
            match step {
                Step::Entry {
                    key,
                    value,
                    depth,
                    include_depth,
                } => self.apply_entry(key, value, depth, include_depth)?,
                Step::Item {
                    value,
                    depth,
                    include_depth,
                } => self.start_value(value, Dest::Push, depth, include_depth)?,
                Step::Finish => self.finish_frame()?,
            }
        }

        Ok(self
            .result
            .unwrap_or_else(|| YamlOwned::Mapping(MappingOwned::new())))
    }

    // Take the next entry or item from the frame on top of the stack.
    fn next_step(&mut self) -> Option<Step> {
        match self.stack.last_mut()? {
            Frame::Mapping { pending, depth, .. } => {
                while let Some(run) = pending.last_mut() {
                    if let Some((key, value)) = run.entries.next() {
                        return Some(Step::Entry {
                            key,
                            value,
                            depth: *depth,
                            include_depth: run.include_depth,
                        });
                    }
                    pending.pop();
                }
                Some(Step::Finish)
            }
            Frame::Sequence {
                pending,
                include_depth,
                depth,
                ..
            } => Some(match pending.next() {
                Some(value) => Step::Item {
                    value,
                    depth: *depth,
                    include_depth: *include_depth,
                },
                None => Step::Finish,
            }),
        }
    }

    // Start resolving a value below a parent at `parent_depth`. Scalars
    // are complete right away, mappings and sequences get a frame.
    fn start_value(
        &mut self, value: YamlOwned, dest: Dest, parent_depth: usize, include_depth: usize,
    ) -> Result<(), LoadError> {
        match strip_tags(value) {
            YamlOwned::Mapping(entries) => self.push_mapping(
                MappingOwned::new(),
                entries,
                dest,
                parent_depth + 1,
                include_depth,
            ),
            YamlOwned::Sequence(sequence) => {
                let depth = check_depth(parent_depth + 1)?;
                self.stack.push(Frame::Sequence {
                    items: Vec::with_capacity(sequence.len()),
                    pending: sequence.into_iter(),
                    include_depth,
                    dest,
                    depth,
                });
                Ok(())
            }
            scalar => self.deliver(dest, scalar),
        }
    }

    // Push a frame applying `entries` to the `target` mapping.
    fn push_mapping(
        &mut self, target: MappingOwned, entries: MappingOwned, dest: Dest, depth: usize,
        include_depth: usize,
    ) -> Result<(), LoadError> {
        let depth = check_depth(depth)?;
        self.stack.push(Frame::Mapping {
            target,
            pending: vec![Entries::new(entries, include_depth)],
            dest,
            depth,
        });
        Ok(())
    }

    // Pop the completed frame on top of the stack and deliver its value.
    fn finish_frame(&mut self) -> Result<(), LoadError> {
        let (value, dest) = match self.stack.pop() {
            Some(Frame::Mapping { target, dest, .. }) => (YamlOwned::Mapping(target), dest),
            Some(Frame::Sequence { items, dest, .. }) => (YamlOwned::Sequence(items), dest),
            None => return Ok(()),
        };
        self.deliver(dest, value)
    }

    // Put a resolved value in its place in the frame on top of the stack.
    fn deliver(&mut self, dest: Dest, value: YamlOwned) -> Result<(), LoadError> {
        match (dest, self.stack.last_mut()) {
            (Dest::Root, None) => self.result = Some(value),
            (Dest::Key(key), Some(Frame::Mapping { target, .. })) => {
                upsert_mapping_entry(target, key, value);
            }
            (Dest::Path { segments, merge }, Some(Frame::Mapping { target, .. })) => {
                let (node, _) = dotted_path_node(target, &segments)
                    .map_err(|err| invalid_dotted_key(&segments, err))?;
                *node = match value {
                    YamlOwned::Mapping(mapping) if merge => merge_mark(mapping),
                    value => value,
                };
            }
            (Dest::Push, Some(Frame::Sequence { items, .. })) => items.push(value),
            _ => unreachable!("resolved value does not match its parent"),
        }
        Ok(())
    }

    // The mapping on top of the stack, where entries are applied, and
    // its pending entries.
    fn target_mapping(&mut self) -> (&mut MappingOwned, &mut Vec<Entries>) {
        match self.stack.last_mut() {
            Some(Frame::Mapping {
                target, pending, ..
            }) => (target, pending),
            _ => unreachable!("mapping entry outside of a mapping"),
        }
    }

    // Apply one mapping entry to the mapping on top of the stack, which
    // is at `depth`.
    fn apply_entry(
        &mut self, key: YamlOwned, value: YamlOwned, depth: usize, include_depth: usize,
    ) -> Result<(), LoadError> {
        let key = unwrap_tagged_values(key);

        if key.as_str() == Some("include") {
            return self.inline_include_value(&value, include_depth + 1);
        }

        match include_path_from_tag(&value)? {
            Some(include_name) => {
                let included = load_include(self.include_dir, include_name, include_depth + 1)?;
                self.set_entry(key, included, depth, include_depth + 1)
            }
            None => self.set_entry(key, value, depth, include_depth),
        }
    }

    // Set the value for a plain or dotted key in the mapping on top of
    // the stack, which is at `depth`.
    fn set_entry(
        &mut self, key: YamlOwned, value: YamlOwned, depth: usize, include_depth: usize,
    ) -> Result<(), LoadError> {
        let Some(segments) = dotted_key_segments(&key) else {
            return self.start_value(value, Dest::Key(key), depth, include_depth);
        };
        let segments = segments.into_iter().map(String::from).collect::<Vec<_>>();

        // Each part of a dotted key is a level of nesting, the value
        // replaces or merges into the node for the last part.
        let parent_depth = depth + segments.len() - 1;
        check_depth(parent_depth)?;

        let value = strip_tags(value);
        let (target, _) = self.target_mapping();
        let (node, created) = dotted_path_node(target, &segments)
            .map_err(|err| invalid_dotted_key(&segments, err))?;

        // A mapping merged into a mapping is applied entry by entry, and
        // stays marked if it was. Anything else replaces the node, and a
        // mapping for a new node is marked.
        match (mapping_mut(node), value) {
            (Some((existing, merge)), YamlOwned::Mapping(entries)) => {
                let existing = std::mem::take(existing);
                self.push_mapping(
                    existing,
                    entries,
                    Dest::Path { segments, merge },
                    parent_depth + 1,
                    include_depth,
                )
            }
            (_, value) => {
                let merge = created && value.is_mapping();
                self.start_value(
                    value,
                    Dest::Path { segments, merge },
                    parent_depth,
                    include_depth,
                )
            }
        }
    }

    // Inline one include value, which can be a filename or a list of
    // filenames, into the mapping on top of the stack.
    fn inline_include_value(
        &mut self, include_value: &YamlOwned, include_depth: usize,
    ) -> Result<(), LoadError> {
        let include_names = if include_value.is_null() {
            Vec::new()
        } else if let Some(include_name) = include_value.as_str() {
            vec![include_name]
        } else if let Some(sequence) = include_value.as_sequence() {
            let mut include_names = Vec::new();
            for entry in sequence.iter().filter(|entry| !entry.is_null()) {
                let Some(include_name) = entry.as_str() else {
                    return Err(LoadError::InvalidInclude(
                        "\"include\" sequence entries must be strings".into(),
                    ));
                };
                include_names.push(include_name);
            }
            include_names
        } else {
            return Err(LoadError::InvalidInclude(
                "\"include\" expects a filename or a sequence of filenames".into(),
            ));
        };

        let mut runs = Vec::with_capacity(include_names.len());
        for include_name in include_names {
            let included = load_include(self.include_dir, include_name, include_depth)?;
            let YamlOwned::Mapping(entries) = strip_tags(included) else {
                return Err(LoadError::InvalidInclude(format!(
                    "included file {include_name:?} must contain a mapping at the document root"
                )));
            };
            runs.push(Entries::new(entries, include_depth));
        }

        // The last run is applied first, so push the first file last.
        let (_, pending) = self.target_mapping();
        pending.extend(runs.into_iter().rev());

        Ok(())
    }
}

// Return the depth if it is within the nesting limit.
fn check_depth(depth: usize) -> Result<usize, LoadError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(LoadError::NestingLimit(MAX_NESTING_DEPTH));
    }
    Ok(depth)
}

fn invalid_dotted_key(segments: &[String], reason: String) -> LoadError {
    LoadError::InvalidDottedKey {
        key: segments.join("."),
        reason,
    }
}

// The tag marking a mapping that only exists through dotted keys. Tags
// in a document are removed while resolving it, so they can't be confused
// with this one.
const MERGE_TAG_SUFFIX: &str = "suricata-merge";

fn is_merge_tag(tag: &Tag) -> bool {
    tag.handle.is_empty() && tag.suffix == MERGE_TAG_SUFFIX
}

// Mark a mapping as only existing through dotted keys.
fn merge_mark(mapping: MappingOwned) -> YamlOwned {
    let tag = Tag {
        handle: String::new(),
        suffix: MERGE_TAG_SUFFIX.into(),
    };
    YamlOwned::Tagged(tag, Box::new(YamlOwned::Mapping(mapping)))
}

// The mapping of a node, marked or not, and whether it is marked.
fn mapping_mut(node: &mut YamlOwned) -> Option<(&mut MappingOwned, bool)> {
    match node {
        YamlOwned::Mapping(mapping) => Some((mapping, false)),
        YamlOwned::Tagged(tag, node) if is_merge_tag(tag) => match node.as_mut() {
            YamlOwned::Mapping(mapping) => Some((mapping, true)),
            _ => None,
        },
        _ => None,
    }
}

// Remove the outer YAML tags from a node.
fn strip_tags(mut node: YamlOwned) -> YamlOwned {
    while let YamlOwned::Tagged(_, value) = node {
        node = *value;
    }
    node
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

// Insert a key/value pair or overwrite the existing value for that key.
fn upsert_mapping_entry(mapping: &mut MappingOwned, key: YamlOwned, value: YamlOwned) {
    if let Some(existing) = mapping.get_mut(&key) {
        *existing = value;
    } else {
        mapping.insert(key, value);
    }
}

// Remove all YAML tag wrappers from a node, without recursion.
fn unwrap_tagged_values(node: YamlOwned) -> YamlOwned {
    enum Frame {
        Mapping {
            target: MappingOwned,
            pending: std::vec::IntoIter<(YamlOwned, YamlOwned)>,
            // The unwrapped key, while its value is unwrapped.
            key: Option<YamlOwned>,
            // The value of the key being unwrapped.
            value: Option<YamlOwned>,
        },
        Sequence {
            items: Vec<YamlOwned>,
            pending: std::vec::IntoIter<YamlOwned>,
        },
    }

    let mut stack: Vec<Frame> = Vec::new();
    let mut next = Some(node);

    loop {
        // Unwrap the next node, or complete the frame on top of the stack.
        let unwrapped = match next.take().map(strip_tags) {
            Some(YamlOwned::Mapping(mapping)) => {
                stack.push(Frame::Mapping {
                    target: MappingOwned::new(),
                    pending: mapping.into_iter().collect::<Vec<_>>().into_iter(),
                    key: None,
                    value: None,
                });
                None
            }
            Some(YamlOwned::Sequence(sequence)) => {
                stack.push(Frame::Sequence {
                    items: Vec::with_capacity(sequence.len()),
                    pending: sequence.into_iter(),
                });
                None
            }
            Some(scalar) => Some(scalar),
            None => match stack.last_mut() {
                Some(Frame::Mapping {
                    pending,
                    key,
                    value,
                    ..
                }) => {
                    if key.is_some() {
                        next = value.take();
                    } else if let Some((entry_key, entry_value)) = pending.next() {
                        *value = Some(entry_value);
                        next = Some(entry_key);
                    }
                    if next.is_some() {
                        continue;
                    }
                    match stack.pop() {
                        Some(Frame::Mapping { target, .. }) => Some(YamlOwned::Mapping(target)),
                        _ => unreachable!(),
                    }
                }
                Some(Frame::Sequence { pending, .. }) => {
                    next = pending.next();
                    if next.is_some() {
                        continue;
                    }
                    match stack.pop() {
                        Some(Frame::Sequence { items, .. }) => Some(YamlOwned::Sequence(items)),
                        _ => unreachable!(),
                    }
                }
                None => unreachable!(),
            },
        };

        // Put a completely unwrapped node in its place.
        if let Some(unwrapped) = unwrapped {
            match stack.last_mut() {
                None => return unwrapped,
                Some(Frame::Mapping { target, key, .. }) => match key.take() {
                    None => *key = Some(unwrapped),
                    Some(key) => {
                        target.insert(key, unwrapped);
                    }
                },
                Some(Frame::Sequence { items, .. }) => items.push(unwrapped),
            }
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

// Walk a dotted key path below a mapping and return the node at the end
// of the path, and whether it was created. Missing nodes are created along
// the way. Errors are returned as a reason string.
//
// Like the C configuration tree, a numeric segment selects a sequence
// entry. An index one past the end appends a new entry. A mapping created
// along the path is marked as only existing through dotted keys. A node
// that is neither a mapping nor a sequence is replaced with a mapping.
fn dotted_path_node<'a, S: AsRef<str>>(
    mapping: &'a mut MappingOwned, segments: &[S],
) -> Result<(&'a mut YamlOwned, bool), String> {
    let Some((first, rest)) = segments.split_first() else {
        return Err("empty key".into());
    };

    let (mut node, mut created) = dotted_mapping_child(mapping, first.as_ref())?;
    for segment in rest {
        let segment = segment.as_ref();

        if created {
            *node = merge_mark(MappingOwned::new());
        } else if !node.is_sequence() && mapping_mut(node).is_none() {
            *node = YamlOwned::Mapping(MappingOwned::new());
        }

        (node, created) = if let YamlOwned::Sequence(sequence) = node {
            let Some(index) = segment
                .parse::<usize>()
                .ok()
                .filter(|index| *index <= sequence.len())
            else {
                return Err(format!(
                    "{segment:?} is not a valid index for a sequence of length {}",
                    sequence.len()
                ));
            };
            let created = index == sequence.len();
            if created {
                sequence.push(YamlOwned::Value(ScalarOwned::Null));
            }
            (&mut sequence[index], created)
        } else if let Some((mapping, _)) = mapping_mut(node) {
            dotted_mapping_child(mapping, segment)?
        } else {
            return Err(format!("cannot descend into {segment:?}"));
        };
    }

    Ok((node, created))
}

// Return the child of a mapping for a dotted-path segment, and whether it
// was created. A missing child is inserted as null. Existing entries keep
// their position.
fn dotted_mapping_child<'a>(
    mapping: &'a mut MappingOwned, segment: &str,
) -> Result<(&'a mut YamlOwned, bool), String> {
    let key = dotted_segment_key(segment);
    let created = !mapping.contains_key(&key);
    if created {
        mapping.insert(key.clone(), YamlOwned::Value(ScalarOwned::Null));
    }
    let node = mapping
        .get_mut(&key)
        .ok_or_else(|| format!("failed to insert {segment:?}"))?;
    Ok((node, created))
}

// Build a YAML string key node for a dotted-path segment.
fn dotted_segment_key(segment: &str) -> YamlOwned {
    YamlOwned::Value(ScalarOwned::String(segment.into()))
}

// Resolve and load one include file. Relative paths are resolved from
// the top-level include directory, also for includes in included files.
fn load_include(include_dir: &Path, include_name: &str, depth: usize) -> Result<Config, LoadError> {
    if depth > INCLUDE_RECURSION_LIMIT {
        return Err(LoadError::IncludeRecursionLimit(INCLUDE_RECURSION_LIMIT));
    }

    let include_path = if Path::new(include_name).is_absolute() {
        PathBuf::from(include_name)
    } else {
        include_dir.join(include_name)
    };

    load_yaml_file(&include_path)
}

// Check whether a YAML tag corresponds to !include.
fn is_include_tag(tag: &Tag) -> bool {
    tag.handle == "!" && tag.suffix == "include"
}
