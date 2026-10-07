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

/// Walk a path below a mapping and return the node at the end of the
/// path, for setting it. Used for dotted keys and command line
/// overrides.
///
/// Missing nodes are created as null, and a node along the path that is
/// neither a mapping nor a sequence is replaced with a mapping. A number
/// selects an item of a sequence, the length of the sequence appends an
/// item, anything beyond is an error.
pub(crate) fn path_node_mut<'a>(
    mapping: &'a mut Mapping, segments: &[String],
) -> Result<&'a mut Node, String> {
    let Some((first, rest)) = segments.split_first() else {
        return Err("empty key".into());
    };

    let mut node = mapping.entry(first.clone()).or_default();
    for segment in rest {
        if !node.is_mapping() && !node.is_sequence() {
            *node = Node::Mapping(Mapping::new());
        }
        node = match node {
            Node::Mapping(mapping) => mapping.entry(segment.clone()).or_default(),
            Node::Sequence(items) => {
                let len = items.len();
                match segment.parse::<usize>() {
                    Ok(index) if index < len => &mut items[index],
                    Ok(index) if index == len => {
                        items.push(Node::Null);
                        &mut items[index]
                    }
                    _ => {
                        return Err(format!(
                            "{segment:?} is not a valid index for a sequence of length {len}"
                        ))
                    }
                }
            }
            Node::Null | Node::Scalar(_) => unreachable!(),
        };
    }

    Ok(node)
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
