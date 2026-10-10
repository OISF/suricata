// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! YAML configuration loader.
//!
//! The loader builds the configuration directly from the parser events,
//! without recursion: the mappings and sequences being built are kept on
//! a stack of frames, and the files being read (the configuration and
//! the files it includes) on a stack of inputs.
//!
//! Entries are applied in document order, the last one wins:
//!
//! - A plain key sets the value for the key, replacing an existing
//!   value. A replaced key keeps its position.
//! - A dotted key, like `vars.address-groups.HOME_NET`, sets the value
//!   at the path below the mapping, creating mappings along the path as
//!   needed. A number selects an item of an existing sequence, the
//!   length of the sequence appends an item. The value is merged into
//!   the existing node: a mapping is merged entry by entry, a null value
//!   leaves the existing node as is, anything else replaces it.
//! - An `include` key, with a file name or a sequence of file names,
//!   applies the entries of the root mapping of each file to the
//!   mapping at this point, so later entries override them. It may be
//!   used more than once in a mapping.
//! - A scalar value tagged `!include` is replaced by the root node of
//!   the file.
//!
//! Relative include file names are resolved from the include directory,
//! the directory of the configuration file, also for the files included
//! by included files.
//!
//! Underscores in mapping keys are replaced with dashes (`host_os_policy`
//! is `host-os-policy`), except for the keys directly below an
//! `address-groups` or `port-groups` key.
//!
//! The nesting depth of the configuration, including included files and
//! the parts of dotted keys, is limited to [`MAX_NESTING_DEPTH`].
//!
//! YAML anchors are ignored, and aliases are not supported.

use std::collections::VecDeque;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;

use saphyr_parser::BufferedInput;
use saphyr_parser::Event;
use saphyr_parser::Parser;
use saphyr_parser::ScalarStyle;
use saphyr_parser::ScanError;
use saphyr_parser::Tag;

use crate::node::path_node_mut;
use crate::node::Mapping;
use crate::node::Node;
use crate::node::PathError;
use crate::Config;
use crate::MAX_INCLUDE_DEPTH;
use crate::MAX_NESTING_DEPTH;

/// A location in a configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    /// The file, if the configuration was loaded from a file.
    pub path: Option<PathBuf>,
    /// The line, starting at 1.
    pub line: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}:{}", path.display(), self.line),
            None => write!(f, "line {}", self.line),
        }
    }
}

/// Errors returned while loading a configuration.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// A file could not be read. `include` is where it was included,
    /// if it was.
    #[error("failed to read {}{}: {source}", path.display(), included_at(include))]
    Io {
        path: PathBuf,
        include: Option<Location>,
        #[source]
        source: std::io::Error,
    },
    /// The input is not valid YAML.
    #[error("failed to parse{}: {source}", file(path))]
    Parse {
        path: Option<PathBuf>,
        #[source]
        source: ScanError,
    },
    /// The configuration is nested deeper than [`MAX_NESTING_DEPTH`].
    #[error("maximum nesting depth of {MAX_NESTING_DEPTH} exceeded at {0}")]
    NestingLimit(Location),
    /// Includes are nested deeper than [`MAX_INCLUDE_DEPTH`].
    #[error("maximum include depth of {MAX_INCLUDE_DEPTH} exceeded at {0}")]
    IncludeLimit(Location),
    /// A file includes itself, directly or through other files.
    #[error("{} included at {location} includes itself", path.display())]
    IncludeCycle { path: PathBuf, location: Location },
    /// Valid YAML that is not a valid configuration.
    #[error("{message} at {location}")]
    Invalid { location: Location, message: String },
}

/// " included at {location}" if the file was included, for messages.
fn included_at(include: &Option<Location>) -> String {
    include
        .as_ref()
        .map(|location| format!(" included at {location}"))
        .unwrap_or_default()
}

/// " {path}" if there is one, for messages.
fn file(path: &Option<PathBuf>) -> String {
    path.as_ref()
        .map(|path| format!(" {}", path.display()))
        .unwrap_or_default()
}

/// Load a configuration file.
///
/// Relative include paths, also in included files, are resolved from the
/// directory of the file.
pub fn load_file(path: &Path) -> Result<Config, LoadError> {
    load_file_with_include_dir(path, &default_include_dir(path))
}

/// Load a configuration file, resolving relative include paths from
/// `include_dir`.
pub fn load_file_with_include_dir(path: &Path, include_dir: &Path) -> Result<Config, LoadError> {
    let mut loader = Loader::new(Mapping::new(), include_dir);
    loader.push_file(path, None, Mode::Splice)?;
    loader.run().map(Node::Mapping)
}

/// Load a configuration from a string. Relative include paths are
/// resolved from the current directory.
pub fn load_string(input: &str) -> Result<Config, LoadError> {
    load_string_with_include_dir(input, Path::new("."))
}

/// Load a configuration from a string, resolving relative include paths
/// from `include_dir`.
pub fn load_string_with_include_dir(input: &str, include_dir: &Path) -> Result<Config, LoadError> {
    let mut loader = Loader::new(Mapping::new(), include_dir);
    loader.push_source(input.to_string(), None, None, Mode::Splice);
    loader.run().map(Node::Mapping)
}

/// Load a configuration file into an existing configuration, as if it
/// was included at the end of the configuration (like `suricata
/// --include`).
///
/// Like an include, a relative `path`, and the relative include paths in
/// the file, are resolved from `include_dir`, which should be the include
/// directory of the existing configuration. On error the existing
/// configuration is not changed.
pub fn merge_file(config: &mut Config, path: &Path, include_dir: &Path) -> Result<(), LoadError> {
    let root = match config {
        Node::Null => Mapping::new(),
        Node::Mapping(mapping) => mapping.clone(),
        _ => {
            return Err(LoadError::Invalid {
                location: Location {
                    path: Some(path.to_path_buf()),
                    line: 0,
                },
                message: "cannot merge into a configuration that is not a mapping".into(),
            })
        }
    };
    let mut loader = Loader::new(root, include_dir);
    let path = loader.include_path(path);
    loader.push_file(&path, None, Mode::Splice)?;
    *config = Node::Mapping(loader.run()?);
    Ok(())
}

// The directory of a configuration file.
fn default_include_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

// The parser input, owning the text so that parsers for included files
// can be kept on a stack.
struct OwnedChars {
    text: String,
    pos: usize,
}

impl Iterator for OwnedChars {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        let c = self.text[self.pos..].chars().next()?;
        self.pos += c.len_utf8();
        Some(c)
    }
}

type YamlParser = Parser<'static, BufferedInput<OwnedChars>>;

// How the root node of a file is used.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    // The entries of the root mapping are applied to the current mapping,
    // like the configuration file itself or an `include` key.
    Splice,
    // The root node is the value at the current position, like a value
    // tagged `!include`.
    Value,
}

// The identity of an open file, to detect include cycles: the device
// and inode on Unix, so that a file read from a pipe, like -c /dev/stdin
// or a shell process substitution, which has no canonical path, still
// has one.
#[cfg(unix)]
#[derive(PartialEq, Eq)]
struct FileId(u64, u64);

#[cfg(unix)]
fn file_id(file: &std::fs::File, _path: &Path) -> std::io::Result<Option<FileId>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(Some(FileId(metadata.dev(), metadata.ino())))
}

// The canonical path elsewhere, if there is one.
#[cfg(not(unix))]
#[derive(PartialEq, Eq)]
struct FileId(PathBuf);

#[cfg(not(unix))]
fn file_id(_file: &std::fs::File, path: &Path) -> std::io::Result<Option<FileId>> {
    Ok(std::fs::canonicalize(path).ok().map(FileId))
}

// A file, or string, being parsed.
struct Source {
    parser: YamlParser,
    path: Option<PathBuf>,
    // The identity of the file, to detect include cycles.
    id: Option<FileId>,
    mode: Mode,
    // The number of mappings and sequences open in this source.
    open: usize,
    // Whether a root node was seen.
    root_seen: bool,
    documents: usize,
}

enum Input {
    Source(Box<Source>),
    // Files still to be included by an `include` key at `location`.
    Includes {
        names: VecDeque<String>,
        location: Location,
    },
}

// A pending mapping key.
enum Key {
    Plain(String),
    Dotted(Vec<String>),
    Include,
}

// Where a completed mapping or sequence goes in its parent.
enum Dest {
    // The root of the configuration. Never completed by an event.
    Root,
    Key(String),
    Path(Vec<String>),
    Push,
}

// A mapping or sequence being built.
enum Frame {
    Mapping {
        map: Mapping,
        // The key waiting for its value.
        key: Option<Key>,
        dest: Dest,
        // The nesting depth, counting the root mapping as 1.
        depth: usize,
    },
    Sequence {
        items: Vec<Node>,
        dest: Dest,
        depth: usize,
    },
    // The file names of an `include` key with a sequence value.
    Includes {
        names: Vec<String>,
        location: Location,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Mapping,
    Sequence,
}

// The next step of the loader.
enum Step {
    Event(Event<'static>, usize),
    EndSource,
    Include(String, Location),
    EndIncludes,
}

struct Loader {
    include_dir: PathBuf,
    inputs: Vec<Input>,
    frames: Vec<Frame>,
    // The line of the current event.
    line: usize,
}

impl Loader {
    fn new(root: Mapping, include_dir: &Path) -> Self {
        Self {
            include_dir: include_dir.to_path_buf(),
            inputs: Vec::new(),
            frames: vec![Frame::Mapping {
                map: root,
                key: None,
                dest: Dest::Root,
                depth: 1,
            }],
            line: 0,
        }
    }

    fn run(mut self) -> Result<Mapping, LoadError> {
        loop {
            let step = match self.inputs.last_mut() {
                None => break,
                Some(Input::Includes { names, location }) => match names.pop_front() {
                    Some(name) => Step::Include(name, location.clone()),
                    None => Step::EndIncludes,
                },
                Some(Input::Source(source)) => match source.parser.next_event() {
                    None => Step::EndSource,
                    Some(Ok((event, span))) => Step::Event(event, span.start.line()),
                    Some(Err(err)) => {
                        return Err(LoadError::Parse {
                            path: source.path.clone(),
                            source: err,
                        })
                    }
                },
            };

            match step {
                Step::Event(event, line) => {
                    self.line = line;
                    self.event(event)?;
                }
                Step::EndSource => self.end_source()?,
                Step::Include(name, location) => {
                    let path = self.include_path(&name);
                    self.push_file(&path, Some(location), Mode::Splice)?;
                }
                Step::EndIncludes => {
                    self.inputs.pop();
                }
            }
        }

        match (self.frames.pop(), self.frames.is_empty()) {
            (Some(Frame::Mapping { map, .. }), true) => Ok(map),
            _ => unreachable!("unbalanced frames at end of input"),
        }
    }

    // The location of the current event.
    fn location(&self) -> Location {
        Location {
            path: self.source_ref().and_then(|source| source.path.clone()),
            line: self.line,
        }
    }

    fn invalid(&self, message: impl Into<String>) -> LoadError {
        LoadError::Invalid {
            location: self.location(),
            message: message.into(),
        }
    }

    fn source_ref(&self) -> Option<&Source> {
        self.inputs.iter().rev().find_map(|input| match input {
            Input::Source(source) => Some(source.as_ref()),
            Input::Includes { .. } => None,
        })
    }

    // The source of the current event.
    fn source(&mut self) -> &mut Source {
        match self.inputs.last_mut() {
            Some(Input::Source(source)) => source,
            _ => unreachable!("event without a source"),
        }
    }

    // The path of an included file.
    fn include_path(&self, name: impl AsRef<Path>) -> PathBuf {
        let name = name.as_ref();
        if name.is_absolute() {
            name.to_path_buf()
        } else {
            self.include_dir.join(name)
        }
    }

    // Read a file and push it as the current source. `include` is where
    // it was included, if it was.
    fn push_file(
        &mut self, path: &Path, include: Option<Location>, mode: Mode,
    ) -> Result<(), LoadError> {
        let io_error = |source| LoadError::Io {
            path: path.to_path_buf(),
            include: include.clone(),
            source,
        };

        if let Some(location) = &include {
            let depth = self
                .inputs
                .iter()
                .filter(|input| matches!(input, Input::Source(_)))
                .count();
            if depth > MAX_INCLUDE_DEPTH {
                return Err(LoadError::IncludeLimit(location.clone()));
            }
        }

        let mut file = std::fs::File::open(path).map_err(io_error)?;
        let id = file_id(&file, path).map_err(io_error)?;
        if let (Some(location), Some(id)) = (&include, &id) {
            let cycle = self.inputs.iter().any(|input| {
                matches!(input, Input::Source(source)
                    if source.id.as_ref() == Some(id))
            });
            if cycle {
                return Err(LoadError::IncludeCycle {
                    path: path.to_path_buf(),
                    location: location.clone(),
                });
            }
        }

        let mut text = String::new();
        std::io::Read::read_to_string(&mut file, &mut text).map_err(io_error)?;
        self.push_source(text, Some(path.to_path_buf()), id, mode);
        Ok(())
    }

    fn push_source(
        &mut self, mut text: String, path: Option<PathBuf>, id: Option<FileId>, mode: Mode,
    ) {
        if text.starts_with('\u{feff}') {
            text.remove(0);
        }
        self.inputs.push(Input::Source(Box::new(Source {
            parser: Parser::new_from_iter(OwnedChars { text, pos: 0 }),
            path,
            id,
            mode,
            open: 0,
            root_seen: false,
            documents: 0,
        })));
    }

    fn end_source(&mut self) -> Result<(), LoadError> {
        let Some(Input::Source(source)) = self.inputs.pop() else {
            unreachable!("end of a source that is not current");
        };
        // An empty file included as a value is null.
        if source.mode == Mode::Value && !source.root_seen {
            self.value(Node::Null)?;
        }
        Ok(())
    }

    fn event(&mut self, event: Event<'static>) -> Result<(), LoadError> {
        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => Ok(()),
            Event::DocumentStart(_) => {
                let source = self.source();
                source.documents += 1;
                // Documents of a spliced file are applied one after the
                // other, but a value can only be one document.
                if source.mode == Mode::Value && source.documents > 1 {
                    return Err(self.invalid("a file included as a value must be one document"));
                }
                Ok(())
            }
            // Anchors are ignored, and aliases are not supported.
            Event::Alias(_) => Err(self.invalid("aliases are not supported")),
            Event::Scalar(text, style, _, tag) => {
                if self.enter_root() {
                    let node = resolve_scalar(text.into_owned(), style, tag.as_deref());
                    if node.is_null() {
                        // An empty document.
                        return Ok(());
                    }
                    return Err(self.invalid("expected a mapping at the root of the document"));
                }
                self.scalar(text.into_owned(), style, tag.as_deref())
            }
            Event::MappingStart(..) => {
                if self.enter_root() {
                    self.source().open += 1;
                    return Ok(());
                }
                self.source().open += 1;
                self.start(Kind::Mapping)
            }
            Event::SequenceStart(..) => {
                if self.enter_root() {
                    return Err(self.invalid("expected a mapping at the root of the document"));
                }
                self.source().open += 1;
                self.start(Kind::Sequence)
            }
            Event::MappingEnd | Event::SequenceEnd => {
                let source = self.source();
                source.open -= 1;
                if source.open == 0 && source.mode == Mode::Splice {
                    // The end of a spliced root mapping.
                    return Ok(());
                }
                self.end()
            }
        }
    }

    // Note the start of a node, and return whether it is the root node of
    // a spliced source, which has no frame of its own.
    fn enter_root(&mut self) -> bool {
        let source = self.source();
        if source.open > 0 {
            return false;
        }
        source.root_seen = true;
        source.mode == Mode::Splice
    }

    fn scalar(
        &mut self, text: String, style: ScalarStyle, tag: Option<&Tag>,
    ) -> Result<(), LoadError> {
        // Whether an `!include` tag includes a file. The tag is ignored on
        // sequence items, like the C loader.
        let can_include = match self.frames.last() {
            // Keys are used as written, also null-like keys.
            Some(Frame::Mapping { key: None, .. }) => return self.key(text),
            Some(Frame::Mapping { key: Some(key), .. }) => !matches!(key, Key::Include),
            Some(Frame::Sequence { .. } | Frame::Includes { .. }) => false,
            None => unreachable!("scalar without a frame"),
        };

        let node = resolve_scalar(text, style, tag);
        if can_include && tag.is_some_and(is_include_tag) {
            if let Node::Scalar(name) = &node {
                // The value comes from the included file.
                let path = self.include_path(name);
                return self.push_file(&path, Some(self.location()), Mode::Value);
            }
        }
        self.value(node)
    }

    fn check_depth(&self, depth: usize) -> Result<(), LoadError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(LoadError::NestingLimit(self.location()));
        }
        Ok(())
    }

    // Set the pending key of the mapping on top of the stack.
    fn key(&mut self, mut text: String) -> Result<(), LoadError> {
        let key = if text == "include" {
            Key::Include
        } else {
            match dotted_key_segments(&text) {
                Some(mut segments) => {
                    let mut parent = self.mapping_name();
                    for segment in &mut segments {
                        mangle(segment, parent);
                        parent = Some(segment.as_str());
                    }
                    Key::Dotted(segments)
                }
                None => {
                    mangle(&mut text, self.mapping_name());
                    Key::Plain(text)
                }
            }
        };

        // Each part of a dotted key is a level of nesting.
        if let Key::Dotted(segments) = &key {
            if let Some(Frame::Mapping { depth, .. }) = self.frames.last() {
                self.check_depth(depth + segments.len() - 1)?;
            }
        }

        match self.frames.last_mut() {
            Some(Frame::Mapping { key: pending, .. }) => *pending = Some(key),
            _ => unreachable!("key outside of a mapping"),
        }
        Ok(())
    }

    // The name of the mapping on top of the stack, for key mangling.
    fn mapping_name(&self) -> Option<&str> {
        match self.frames.last() {
            Some(Frame::Mapping {
                dest: Dest::Key(key),
                ..
            }) => Some(key.as_str()),
            Some(Frame::Mapping {
                dest: Dest::Path(segments),
                ..
            }) => segments.last().map(String::as_str),
            _ => None,
        }
    }

    // Put a scalar or null value at the current position. Mappings and
    // sequences are put in place by `end`.
    fn value(&mut self, node: Node) -> Result<(), LoadError> {
        let location = self.location();
        match self.frames.last_mut() {
            Some(Frame::Mapping { map, key, .. }) => match key.take() {
                Some(Key::Plain(key)) => {
                    map.insert(key, node);
                }
                Some(Key::Dotted(segments)) => {
                    let (slot, _) = path_node_mut(map, &segments)
                        .map_err(|reason| invalid_dotted_key(location, &segments, reason))?;
                    // A null value leaves an existing node as is.
                    if !node.is_null() {
                        *slot = node;
                    }
                }
                Some(Key::Include) => {
                    // A null include is ignored.
                    if let Node::Scalar(name) = node {
                        self.push_includes(vec![name], location);
                    }
                }
                None => unreachable!("value without a key"),
            },
            Some(Frame::Sequence { items, .. }) => items.push(node),
            Some(Frame::Includes { names, .. }) => {
                // Null entries are ignored.
                if let Node::Scalar(name) = node {
                    names.push(name);
                }
            }
            None => unreachable!("value without a frame"),
        }
        Ok(())
    }

    fn push_includes(&mut self, names: Vec<String>, location: Location) {
        if !names.is_empty() {
            self.inputs.push(Input::Includes {
                names: names.into(),
                location,
            });
        }
    }

    // Start a mapping or sequence at the current position.
    fn start(&mut self, kind: Kind) -> Result<(), LoadError> {
        let location = self.location();
        let (dest, depth, map) = match self.frames.last_mut() {
            Some(Frame::Mapping { key: None, .. }) => {
                return Err(self.invalid("mapping keys must be scalars"));
            }
            Some(Frame::Mapping {
                key: Some(Key::Include),
                ..
            }) => {
                if kind == Kind::Mapping {
                    return Err(self.invalid("include fields cannot be a mapping"));
                }
                if let Some(Frame::Mapping { key, .. }) = self.frames.last_mut() {
                    *key = None;
                }
                self.frames.push(Frame::Includes {
                    names: Vec::new(),
                    location,
                });
                return Ok(());
            }
            Some(Frame::Mapping {
                key: key @ Some(Key::Plain(_)),
                depth,
                ..
            }) => {
                let Some(Key::Plain(key)) = key.take() else {
                    unreachable!();
                };
                (Dest::Key(key), *depth + 1, Mapping::new())
            }
            Some(Frame::Mapping {
                map,
                key: key @ Some(Key::Dotted(_)),
                depth,
                ..
            }) => {
                let Some(Key::Dotted(segments)) = key.take() else {
                    unreachable!();
                };
                let depth = *depth + segments.len();
                if depth > MAX_NESTING_DEPTH {
                    return Err(LoadError::NestingLimit(location));
                }
                // A mapping is merged into an existing mapping, which is
                // taken out and put back when complete.
                let map = if kind == Kind::Mapping {
                    let (slot, _) = path_node_mut(map, &segments)
                        .map_err(|reason| invalid_dotted_key(location, &segments, reason))?;
                    match slot {
                        Node::Mapping(existing) => std::mem::take(existing),
                        _ => Mapping::new(),
                    }
                } else {
                    Mapping::new()
                };
                (Dest::Path(segments), depth, map)
            }
            Some(Frame::Sequence { depth, .. }) => (Dest::Push, *depth + 1, Mapping::new()),
            Some(Frame::Includes { .. }) => {
                return Err(self.invalid("include list entries must be file names"));
            }
            None => unreachable!("start without a frame"),
        };

        self.check_depth(depth)?;
        self.frames.push(match kind {
            Kind::Mapping => Frame::Mapping {
                map,
                key: None,
                dest,
                depth,
            },
            Kind::Sequence => Frame::Sequence {
                items: Vec::new(),
                dest,
                depth,
            },
        });
        Ok(())
    }

    // Complete the mapping or sequence on top of the stack.
    fn end(&mut self) -> Result<(), LoadError> {
        let (node, dest) = match self.frames.pop() {
            Some(Frame::Mapping { map, dest, .. }) => (Node::Mapping(map), dest),
            Some(Frame::Sequence { items, dest, .. }) => (Node::Sequence(items), dest),
            Some(Frame::Includes { names, location }) => {
                self.push_includes(names, location);
                return Ok(());
            }
            None => unreachable!("end without a frame"),
        };

        let location = self.location();
        match (dest, self.frames.last_mut()) {
            (Dest::Key(key), Some(Frame::Mapping { map, .. })) => {
                map.insert(key, node);
            }
            (Dest::Path(segments), Some(Frame::Mapping { map, .. })) => {
                let (slot, _) = path_node_mut(map, &segments)
                    .map_err(|reason| invalid_dotted_key(location, &segments, reason))?;
                *slot = node;
            }
            (Dest::Push, Some(Frame::Sequence { items, .. })) => items.push(node),
            _ => unreachable!("completed node does not match its parent"),
        }
        Ok(())
    }
}

// Resolve a scalar value. Like the C loader, scalars are kept as text,
// and the plain null forms of the YAML core schema are null. The core
// schema `!!str` and `!!null` tags are respected.
fn resolve_scalar(text: String, style: ScalarStyle, tag: Option<&Tag>) -> Node {
    if let Some(tag) = tag.filter(|tag| tag.is_yaml_core_schema()) {
        match tag.suffix.as_str() {
            "str" => return Node::Scalar(text),
            "null" => return Node::Null,
            _ => {}
        }
    }
    if style == ScalarStyle::Plain && matches!(text.as_str(), "" | "~" | "null" | "Null" | "NULL") {
        return Node::Null;
    }
    Node::Scalar(text)
}

fn is_include_tag(tag: &Tag) -> bool {
    tag.handle == "!" && tag.suffix == "include"
}

// Replace underscores in a key with dashes, except for group names.
fn mangle(key: &mut String, parent: Option<&str>) {
    if !matches!(parent, Some("address-groups" | "port-groups")) && key.contains('_') {
        *key = key.replace('_', "-");
    }
}

// Split a mapping key with dots into its parts. A key with an empty part
// is not a dotted key.
fn dotted_key_segments(key: &str) -> Option<Vec<String>> {
    if !key.contains('.') {
        return None;
    }
    let segments: Vec<String> = key.split('.').map(String::from).collect();
    if segments.iter().any(String::is_empty) {
        return None;
    }
    Some(segments)
}

fn invalid_dotted_key(location: Location, segments: &[String], reason: PathError) -> LoadError {
    LoadError::Invalid {
        location,
        message: format!("invalid dotted key {:?}: {reason}", segments.join(".")),
    }
}
