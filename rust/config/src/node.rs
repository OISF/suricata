// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! The configuration tree.

use std::ops::Index;

use indexmap::IndexMap;

/// A mapping of a configuration, in document order.
pub type Mapping = IndexMap<String, Node>;

/// A node of a configuration tree.
///
/// Scalars are kept as the text from the document, without resolving
/// them to booleans or numbers, which is left to the user of a value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Node {
    #[default]
    Null,
    Scalar(String),
    Sequence(Vec<Node>),
    Mapping(Mapping),
}

// Returned when indexing a node that does not exist.
static NULL: Node = Node::Null;

impl Node {
    pub fn is_null(&self) -> bool {
        matches!(self, Node::Null)
    }

    pub fn is_mapping(&self) -> bool {
        matches!(self, Node::Mapping(_))
    }

    pub fn is_sequence(&self) -> bool {
        matches!(self, Node::Sequence(_))
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Node::Scalar(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_mapping(&self) -> Option<&Mapping> {
        match self {
            Node::Mapping(mapping) => Some(mapping),
            _ => None,
        }
    }

    pub fn as_mapping_mut(&mut self) -> Option<&mut Mapping> {
        match self {
            Node::Mapping(mapping) => Some(mapping),
            _ => None,
        }
    }

    pub fn as_sequence(&self) -> Option<&[Node]> {
        match self {
            Node::Sequence(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_sequence_mut(&mut self) -> Option<&mut Vec<Node>> {
        match self {
            Node::Sequence(items) => Some(items),
            _ => None,
        }
    }

    /// The child of a mapping by key, or of a sequence by index if the
    /// key is a number.
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Mapping(mapping) => mapping.get(key),
            Node::Sequence(items) => items.get(key.parse::<usize>().ok()?),
            _ => None,
        }
    }

    /// The node at a dotted path, like `outputs.1.eve-log.enabled`.
    pub fn get_path(&self, path: &str) -> Option<&Node> {
        path.split('.').try_fold(self, |node, key| node.get(key))
    }
}

/// Why a path could not be walked, see [`path_node_mut`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The path is empty.
    #[error("empty key")]
    Empty,
    /// A component of the path names a child of a sequence, which only
    /// has indexes.
    #[error("{segment:?} is not a valid index for a sequence of length {len}")]
    NotAnIndex { segment: String, len: usize },
    /// An index past the end of a sequence, where only the next index
    /// can be used to append an item.
    #[error("{segment:?} is not a valid index for a sequence of length {len}")]
    PastEnd { segment: String, len: usize },
}

/// Walk a path below a mapping and return the node at the end of the
/// path, for setting it, with the path as resolved: an index of a
/// sequence is in its canonical form, so `00` is `0`. Used for dotted
/// keys and command line overrides.
///
/// Missing nodes are created as null, and a node along the path that is
/// neither a mapping nor a sequence is replaced with a mapping. A number
/// selects an item of a sequence, the length of the sequence appends an
/// item, anything beyond is an error.
pub(crate) fn path_node_mut<'a>(
    mapping: &'a mut Mapping, segments: &[String],
) -> Result<(&'a mut Node, Vec<String>), PathError> {
    let Some((first, rest)) = segments.split_first() else {
        return Err(PathError::Empty);
    };

    let mut resolved = Vec::with_capacity(segments.len());
    resolved.push(first.clone());
    let mut node = mapping.entry(first.clone()).or_default();
    for segment in rest {
        if !node.is_mapping() && !node.is_sequence() {
            *node = Node::Mapping(Mapping::new());
        }
        node = match node {
            Node::Mapping(mapping) => {
                resolved.push(segment.clone());
                mapping.entry(segment.clone()).or_default()
            }
            Node::Sequence(items) => {
                let len = items.len();
                let Ok(index) = segment.parse::<usize>() else {
                    return Err(PathError::NotAnIndex {
                        segment: segment.clone(),
                        len,
                    });
                };
                if index > len {
                    return Err(PathError::PastEnd {
                        segment: segment.clone(),
                        len,
                    });
                }
                if index == len {
                    items.push(Node::Null);
                }
                resolved.push(index.to_string());
                &mut items[index]
            }
            Node::Null | Node::Scalar(_) => unreachable!(),
        };
    }

    Ok((node, resolved))
}

impl Index<&str> for Node {
    type Output = Node;

    /// The child for a key, see [`Node::get`], or null if there is none.
    fn index(&self, key: &str) -> &Node {
        self.get(key).unwrap_or(&NULL)
    }
}

impl Index<usize> for Node {
    type Output = Node;

    /// The item of a sequence, or null if there is none.
    fn index(&self, index: usize) -> &Node {
        match self {
            Node::Sequence(items) => items.get(index).unwrap_or(&NULL),
            _ => &NULL,
        }
    }
}
