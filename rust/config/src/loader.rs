// Copyright (C) 2022 Open Information Security Foundation
//
// You can copy, redistribute or modify this Program under the terms of
// the GNU General Public License version 2 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// version 2 along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.

use crate::file::FileCharIterator;
use linked_hash_map::LinkedHashMap;
use std::collections::BTreeMap;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;
use yaml_rust::parser::MarkedEventReceiver;
use yaml_rust::scanner::TScalarStyle;
use yaml_rust::scanner::TokenType;
use yaml_rust::Event;
use yaml_rust::Yaml;

pub type Hash = LinkedHashMap<Yaml, Yaml>;

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("failed to open {filename:?}: {source:?}")]
    FileOpen {
        filename: String,
        source: std::io::Error,
    },
    #[error("yaml parse")]
    YamlScanError {
        filename: Option<String>,
        source: yaml_rust::ScanError,
    },
    #[error("not a file: {0}")]
    NotAFile(String),
    #[error("invalid include content: {0}")]
    InvalidInclude(&'static str),
}

// copied from yaml-rust
//
// parse f64 as Core schema
// See: https://github.com/chyh1990/yaml-rust/issues/51
fn parse_f64(v: &str) -> Option<f64> {
    match v {
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => Some(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => Some(f64::NEG_INFINITY),
        ".nan" | "NaN" | ".NAN" => Some(f64::NAN),
        _ => v.parse::<f64>().ok(),
    }
}

/// A custom YAML loader.
///
/// We can't use the one from yaml-loader as there is no way to construct it as a user from the
/// library, and we need access to some of the internal state for include handling.
struct SuricataYamlLoader {
    docs: Vec<Yaml>,
    doc_stack: Vec<(Yaml, usize)>,
    key_stack: Vec<Yaml>,
    anchor_map: BTreeMap<usize, Yaml>,

    // The current filename being parsed.
    filename: Option<PathBuf>,

    // Set to true if the next event should be an include filename.
    include: bool,

    error: Option<LoaderError>,
}

impl SuricataYamlLoader {
    fn new() -> Self {
        Self {
            docs: Vec::new(),
            doc_stack: Vec::new(),
            key_stack: Vec::new(),
            anchor_map: BTreeMap::new(),
            filename: None,
            include: false,
            error: None,
        }
    }

    /// Set the filename that is being loaded. This is used for resolving the path to any includes.
    pub fn set_filename<P: AsRef<Path>>(&mut self, path: P) {
        let mut filename = PathBuf::new();
        filename.push(path.as_ref());
        self.filename = Some(filename);
    }

    /// Copied from yaml-rust.
    fn insert_new_node(&mut self, node: (Yaml, usize)) {
        // valid anchor id starts from 1
        if node.1 > 0 {
            self.anchor_map.insert(node.1, node.0.clone());
        }
        if self.doc_stack.is_empty() {
            self.doc_stack.push(node);
        } else {
            let parent = self.doc_stack.last_mut().unwrap();
            match *parent {
                (Yaml::Array(ref mut v), _) => v.push(node.0),
                (Yaml::Hash(ref mut h), _) => {
                    let cur_key = self.key_stack.last_mut().unwrap();
                    // current node is a key
                    if cur_key.is_badvalue() {
                        *cur_key = node.0;
                    // current node is a value
                    } else {
                        let mut newkey = Yaml::BadValue;
                        mem::swap(&mut newkey, cur_key);
                        h.insert(newkey, node.0);
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    fn is_key(&self) -> bool {
        if self.doc_stack.is_empty() {
            return false;
        }
        let parent = self.doc_stack.last().unwrap();
        if let (Yaml::Hash(_), _) = *parent {
            let cur_key = self.key_stack.last().unwrap();
            if cur_key.is_badvalue() {
                return true;
            }
        }
        false
    }

    fn load_include(&mut self, filename: &str, merge: bool) {
        let filename = self.resolve_include_filename(filename);
        match load_from_file(filename) {
            Err(err) => self.error = Some(err),
            Ok(docs) => {
                for doc in docs {
                    if merge {
                        match doc {
                            Yaml::Hash(hash) => {
                                for (k, v) in hash {
                                    self.insert_new_node((k, 0));
                                    self.insert_new_node((v, 0));
                                }
                            }
                            _ => {
                                self.error = Some(LoaderError::InvalidInclude(
                                    "hash required for include at key",
                                ))
                            }
                        }
                    } else {
                        self.insert_new_node((doc, 0));
                    }
                }
            }
        }
    }

    fn resolve_include_filename(&self, include: &str) -> PathBuf {
        let mut filename = if let Some(filename) = &self.filename {
            filename.parent().unwrap().to_path_buf()
        } else {
            PathBuf::new()
        };
        filename.push(include);
        filename
    }
}

impl MarkedEventReceiver for SuricataYamlLoader {
    fn on_event(&mut self, ev: yaml_rust::Event, _: yaml_rust::scanner::Marker) {
        // If an error has occurred, do nothing. Unfortutantely we have to do
        // this until the scanner has an error or end of file.
        if self.error.is_some() {
            return;
        }
        if self.include {
            match ev {
                Event::Scalar(v, _, _, _) => {
                    self.load_include(&v, true);
                }
                _ => {
                    self.error = Some(LoaderError::InvalidInclude(
                        "include found with non-scalar value",
                    ));
                }
            }
            self.include = false;
            return;
        }
        match ev {
            Event::DocumentStart => {
                // do nothing
            }
            Event::DocumentEnd => {
                match self.doc_stack.len() {
                    // empty document
                    0 => self.docs.push(Yaml::BadValue),
                    1 => self.docs.push(self.doc_stack.pop().unwrap().0),
                    _ => unreachable!(),
                }
            }
            Event::SequenceStart(aid) => {
                self.doc_stack.push((Yaml::Array(Vec::new()), aid));
            }
            Event::SequenceEnd => {
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node);
            }
            Event::MappingStart(aid) => {
                self.doc_stack.push((Yaml::Hash(Hash::new()), aid));
                self.key_stack.push(Yaml::BadValue);
            }
            Event::MappingEnd => {
                self.key_stack.pop().unwrap();
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node);
            }
            Event::Scalar(v, style, aid, tag) => {
                if self.is_key() && v == "include" {
                    self.include = true;
                    return;
                }
                if is_include(&tag) {
                    self.load_include(&v, false);
                    return;
                }
                let node = if style != TScalarStyle::Plain {
                    Yaml::String(v)
                } else if let Some(TokenType::Tag(ref handle, ref suffix)) = tag {
                    // XXX tag:yaml.org,2002:
                    if handle == "!!" {
                        match suffix.as_ref() {
                            "bool" => {
                                // "true" or "false"
                                match v.parse::<bool>() {
                                    Err(_) => Yaml::BadValue,
                                    Ok(v) => Yaml::Boolean(v),
                                }
                            }
                            "int" => match v.parse::<i64>() {
                                Err(_) => Yaml::BadValue,
                                Ok(v) => Yaml::Integer(v),
                            },
                            "float" => match parse_f64(&v) {
                                Some(_) => Yaml::Real(v),
                                None => Yaml::BadValue,
                            },
                            "null" => match v.as_ref() {
                                "~" | "null" => Yaml::Null,
                                _ => Yaml::BadValue,
                            },
                            _ => Yaml::String(v),
                        }
                    } else {
                        Yaml::String(v)
                    }
                } else {
                    // Datatype is not specified, or unrecognized
                    match v.to_lowercase().as_ref() {
                        // Suricata accepts any form of unquoted "null" as a null.
                        "null" => Yaml::Null,
                        _ => Yaml::from_str(&v),
                    }
                };

                self.insert_new_node((node, aid));
            }
            Event::Alias(id) => {
                let n = match self.anchor_map.get(&id) {
                    Some(v) => v.clone(),
                    None => Yaml::BadValue,
                };
                self.insert_new_node((n, 0));
            }
            _ => { /* ignore */ }
        }
    }
}

fn is_include(token: &Option<TokenType>) -> bool {
    if let Some(TokenType::Tag(prefix, value)) = token {
        if prefix.starts_with('!') && value == "include" {
            return true;
        }
    }
    false
}

pub fn load_from_str(source: &str) -> Result<Vec<Yaml>, LoaderError> {
    let mut loader = SuricataYamlLoader::new();
    let mut parser = yaml_rust::parser::Parser::new(source.chars());
    parser
        .load(&mut loader, true)
        .map_err(|err| LoaderError::YamlScanError {
            filename: None,
            source: err,
        })?;
    Ok(loader.docs)
}

pub fn load_from_file<P: AsRef<Path>>(filename: P) -> Result<Vec<Yaml>, LoaderError> {
    let file = std::fs::File::open(&filename).map_err(|err| LoaderError::FileOpen {
        filename: filename.as_ref().display().to_string(),
        source: err,
    })?;

    // Prevent attempts to read from a directory. This is to match the behaviour of the C code.
    if let Ok(metadata) = file.metadata() {
        if metadata.is_dir() {
            return Err(LoaderError::NotAFile(
                filename.as_ref().display().to_string(),
            ));
        }
    }

    let mut loader = SuricataYamlLoader::new();
    loader.set_filename(&filename);
    let mut parser = yaml_rust::parser::Parser::new(FileCharIterator::new(file));
    parser
        .load(&mut loader, false)
        .map_err(|err| LoaderError::YamlScanError {
            filename: Some(filename.as_ref().to_str().unwrap().to_string()),
            source: err,
        })?;
    if let Some(err) = loader.error {
        Err(err)
    } else {
        Ok(loader.docs)
    }
}
