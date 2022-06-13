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

mod ffi;
mod file;
pub mod loader;
pub mod printer;

pub use crate::loader::LoaderError;
use lazy_static::lazy_static;
use linked_hash_map::LinkedHashMap;
use std::sync::RwLock;
pub use yaml_rust::Yaml;

lazy_static! {
    static ref GLOBAL: RwLock<Yaml> = RwLock::new(Yaml::Hash(LinkedHashMap::new()));
    static ref DEFAULT: Yaml = build_default();
}

pub fn build_default() -> Yaml {
    let default_string = include_str!("default.yaml");
    loader::load_from_str(default_string)
        .unwrap()
        .pop()
        .unwrap()
}

pub trait SuricataYaml {
    fn set_int(&mut self, key: &str, value: i64) -> bool;
    fn set_from_str(&mut self, key: &str, value: &str) -> bool;

    /// The legacy Yaml handling in Suricata treated strings with certain values as truthy
    /// for boolean values, such as "yes", or "on", or "1". This method gives an interface
    /// that is compatible with that logic.
    fn is_true(&self) -> bool;

    fn get_node(&self, key: &str) -> Option<&Yaml>;
}

impl SuricataYaml for Yaml {
    fn is_true(&self) -> bool {
        match self {
            Yaml::Boolean(v) => *v,
            Yaml::String(v) => matches!(v.to_lowercase().as_str(), "1" | "yes" | "true" | "on"),
            Yaml::Integer(v) => *v != 0,
            _ => false,
        }
    }

    fn set_int(&mut self, key: &str, value: i64) -> bool {
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        let key = Yaml::from_str(parts[0]);
        match self {
            Yaml::Hash(hash) => {
                if parts.len() == 1 {
                    match hash.get(&key) {
                        None | Some(Yaml::Integer(_)) => {
                            hash.insert(key, Yaml::Integer(value));
                            true
                        }
                        _ => false,
                    }
                } else {
                    let entry = hash
                        .entry(key)
                        .or_insert_with(|| Yaml::Hash(LinkedHashMap::new()));
                    entry.set_int(parts[1], value)
                }
            }
            _ => false,
        }
    }

    fn set_from_str(&mut self, key: &str, value: &str) -> bool {
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        let key = Yaml::from_str(parts[0]);
        match self {
            Yaml::Hash(hash) => {
                if parts.len() == 1 {
                    match hash.get(&key) {
                        None | Some(Yaml::Integer(_)) => {
                            hash.insert(key, Yaml::from_str(value));
                            true
                        }
                        _ => false,
                    }
                } else {
                    let entry = hash
                        .entry(key)
                        .or_insert_with(|| Yaml::Hash(LinkedHashMap::new()));
                    entry.set_from_str(parts[1], value)
                }
            }
            _ => false,
        }
    }

    fn get_node(&self, key: &str) -> Option<&Yaml> {
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        if parts.is_empty() {
            return None;
        }
        if let Yaml::Hash(hash) = self {
            let key = Yaml::from_str(parts[0]);
            if let Some(node) = hash.get(&key) {
                if parts.len() == 1 {
                    return Some(node);
                } else {
                    return node.get_node(parts[1]);
                }
            }
        }
        None
    }
}

pub fn get_node<'a>(node: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    if parts.is_empty() {
        return None;
    }
    if let Yaml::Hash(hash) = node {
        let key = Yaml::from_str(parts[0]);
        if let Some(node) = hash.get(&key) {
            if parts.len() == 1 {
                return Some(node);
            } else {
                return get_node(node, parts[1]);
            }
        }
    }
    None
}

pub fn set_global(yaml: Yaml) {
    let mut default = GLOBAL.write().unwrap();
    *default = yaml;
}

/// Merge Yaml b into a.
///
/// This really only deals with hashes. All over types, including lists are terminal
/// values that the merge does not descend into.
pub fn merge(a: &mut Yaml, b: &Yaml) {
    match b {
        Yaml::Hash(b) => {
            if let Yaml::Hash(ahash) = a {
                for (k, v) in b {
                    if let Yaml::String(key) = k {
                        if key.starts_with("_") {
                            continue;
                        }
                    }
                    if ahash.contains_key(k) {
                        merge(ahash.get_mut(k).unwrap(), v);
                    } else {
                        ahash.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        Yaml::Array(_)
        | Yaml::String(_)
        | Yaml::Boolean(_)
        | Yaml::Integer(_)
        | Yaml::Null
        | Yaml::Real(_)
        | Yaml::Alias(_)
        | Yaml::BadValue => {}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::loader::load_from_str;
    use crate::printer::print_node;

    #[test]
    fn test_merge() {
        let default = DEFAULT.clone();

        let user_config = r#"
        outputs:
          - fast:
              enabled: yes
        "#;
        let mut user = load_from_str(user_config).unwrap().pop().unwrap();

        // Merge default into user.
        merge(&mut user, &default);

        // Now do some business logic merging.
        if let Yaml::Array(outputs) = &user["outputs"] {
            for output in outputs {
                if let Yaml::Hash(hash) = output {
                    for (k, _v) in hash {
                        if let Yaml::String(_k) = k {
                            let defaults = DEFAULT.get_node("outputs");
                            dbg!(defaults);
                        }
                    }
                }
            }
        }

        print_node(&user, vec![]);
    }

    #[test]
    fn test_get_node() {
        let doc = r#"
        simple: value
        nested:
            aaa: bbb
        "#;

        let config = loader::load_from_str(doc).unwrap().pop().unwrap();

        let node = get_node(&config, "simple").unwrap();
        assert_eq!(node.as_str().unwrap(), "value");

        let node = get_node(&config, "nested.aaa").unwrap();
        assert_eq!(node.as_str().unwrap(), "bbb");
    }

    #[test]
    fn test_set_int() {
        let mut config = Yaml::Hash(LinkedHashMap::new());
        config.set_int("foo", 1);
        assert_eq!(config["foo"], Yaml::Integer(1));

        config.set_int("foo", 2);
        assert_eq!(config["foo"], Yaml::Integer(2));

        config.set_int("bar.foo", 3);
        assert_eq!(config["bar"]["foo"], Yaml::Integer(3));

        config.set_int("bar.far", 4);
        assert_eq!(config["bar"]["far"], Yaml::Integer(4));

        // This will fail as bar is a hash, so we can't set it to a value of a different
        // type.
        assert_eq!(config.set_int("bar", 5), false);
    }
}
