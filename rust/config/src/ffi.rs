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

use crate::{get_node, LoaderError, SuricataYaml, GLOBAL};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;
pub use yaml_rust::Yaml;

#[repr(C)]
#[derive(Debug)]
pub enum ScYamlType {
    Unknown = 0,
    Hash,
    Array,
    String,
    Boolean,
    Integer,
    Real,
    Null,
}

// Rust strings converted to CString's will be stored to avoid memory leaks.
// They still never get free'd, but are held onto and re-used when the same
// input is provided more than once.
//
// This also allows C users to hold onto a string pointer that is returned
// and not need to worry about freeing it.
lazy_static! {
    static ref CSTRINGS: Mutex<HashMap<String, CString>> = Mutex::new(HashMap::new());
}

/// The size of the error buffer that is passed to some of the FFI functions.
pub const SC_CONFIG_ERRBUF_SIZE: usize = 4096;

#[no_mangle]
pub unsafe extern "C" fn ScConfigLoadFromFile(
    filename: *const c_char, errbuf: *mut c_char,
) -> *mut Yaml {
    let filename = match CStr::from_ptr(filename).to_str() {
        Ok(cs) => cs,
        Err(err) => {
            let error = format!("Failed to convert C filename to UTF-8: {:?}", err);
            let error = CString::new(error).unwrap();
            let size = std::cmp::min(error.as_bytes_with_nul().len(), SC_CONFIG_ERRBUF_SIZE);
            std::ptr::copy_nonoverlapping(error.as_ptr(), errbuf, size);
            return std::ptr::null_mut();
        }
    };

    let config = match crate::loader::load_from_file(filename) {
        Ok(mut docs) => docs.pop().unwrap(),
        Err(err) => {
            let error = match err {
                LoaderError::NotAFile(_) => "Provided filename is not a file".to_string(),
                LoaderError::YamlScanError { filename, source } => {
                    let error = format!(
                        "YAML scan error at line {}, col {}",
                        source.marker().line(),
                        source.marker().col()
                    );

                    // Include the filename if there is one, the error could originate
                    // from an include.
                    if let Some(filename) = filename {
                        format!("{}, filename={}", error, filename)
                    } else {
                        error
                    }
                }
                _ => {
                    format!("{:?}", err)
                }
            };
            let error = CString::new(error).unwrap();
            let size = std::cmp::min(error.as_bytes_with_nul().len(), SC_CONFIG_ERRBUF_SIZE);
            std::ptr::copy_nonoverlapping(error.as_ptr(), errbuf, size);
            return std::ptr::null_mut();
        }
    };
    Box::into_raw(Box::new(config)) as *const _ as *mut _
}

#[no_mangle]
pub unsafe extern "C" fn ScConfigYamlFree(yaml: *mut Yaml) {
    let _ = Box::from_raw(yaml);
}

/// Get, and create if a required a CString for the provided &str.
fn get_cstring(value: &str) -> *const c_char {
    let mut cstrings = CSTRINGS.lock().unwrap();
    if let Some(cs) = cstrings.get(value) {
        return cs.as_ptr();
    }
    let cstring = CString::new(value).unwrap();
    cstrings.insert(value.to_string(), cstring);
    cstrings.get(value).unwrap().as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ScConfigLoadFromString(
    input: *const c_char, errptr: *mut *const c_char,
) -> *mut Yaml {
    let input = match CStr::from_ptr(input).to_str() {
        Ok(input) => input,
        Err(err) => {
            let error = format!("Failed to convert input to UTF-8: {:?}", err);
            *errptr = get_cstring(&error);
            return std::ptr::null_mut();
        }
    };

    match crate::loader::load_from_str(input) {
        Ok(mut config) => Box::into_raw(Box::new(config.pop().unwrap())),
        Err(err) => {
            let error = format!("Failed to load config from string: {:?}", err);
            *errptr = get_cstring(&error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ScConfGet(key: *const c_char, vptr: *mut *const c_char) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(key) => key,
        Err(_) => return -1,
    };

    let root = GLOBAL.read().unwrap();
    let node = get_node(&*root, key).unwrap();
    if let Yaml::String(s) = node {
        let cstring = get_cstring(s);
        *vptr = cstring;
        return 0;
    }
    -1
}

#[no_mangle]
pub unsafe extern "C" fn ScConfGetInt(key: *const c_char, vptr: *mut i64) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(key) => key,
        Err(_) => return 0,
    };
    let root = GLOBAL.read().unwrap();
    if let Some(node) = get_node(&*root, key) {
        if let Some(n) = node.as_i64() {
            *vptr = n;
            return 1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn ScConfGetNode(key: *const c_char) -> *const Yaml {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(key) => key,
        Err(_) => return std::ptr::null(),
    };

    let root = GLOBAL.read().unwrap();
    if let Some(node) = get_node(&*root, key) {
        node as *const _
    } else {
        std::ptr::null()
    }
}

pub struct YamlArrayIter(std::slice::Iter<'static, Yaml>);

#[no_mangle]
pub unsafe extern "C" fn ScConfArrayIter(node: &'static Yaml) -> *mut YamlArrayIter {
    if let Yaml::Array(array) = node {
        let iter = YamlArrayIter(array.iter());
        return Box::into_raw(Box::new(iter)) as *mut _;
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn ScConfArrayIterNext(
    iter: &mut YamlArrayIter, vptr: *mut *mut Yaml,
) -> bool {
    if let Some(next) = iter.0.next() {
        *vptr = next as *const _ as *mut _;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn ScConfArrayIterFree(iter: *mut YamlArrayIter) {
    let _iter = Box::from_raw(iter as *mut YamlArrayIter);
}

#[no_mangle]
pub unsafe extern "C" fn ScConfDebug(node: &Yaml) {
    dbg!(node);
}

pub struct YamlHashIter(linked_hash_map::Iter<'static, Yaml, Yaml>);

/// Create a hash iterator from a YAML value.
///
/// Returns null if the Yaml configuration node is not a hash.
#[no_mangle]
pub unsafe extern "C" fn ScConfHashIter(node: *const Yaml) -> *mut YamlHashIter {
    if let Yaml::Hash(hash) = &*node {
        let iter = YamlHashIter(hash.iter());
        Box::into_raw(Box::new(iter)) as *mut _
    } else {
        std::ptr::null_mut()
    }
}

/// Get the next result from the hash iterator.
///
/// The key and value are returned using the output pointers `kptr` and `vptr`.
///
/// This function will return true if there was a next value to return, false is not.
#[no_mangle]
pub unsafe extern "C" fn ScConfHashIterNext(
    iter: *mut YamlHashIter, kptr: *mut *const c_char, vptr: *mut *mut Yaml,
) -> bool {
    if let Some((key, val)) = (*iter).0.next() {
        let xkey = match key {
            Yaml::String(v) | Yaml::Real(v) => v.to_string(),
            Yaml::Integer(v) => v.to_string(),
            Yaml::Boolean(v) => v.to_string(),
            _ => return false,
        };
        *kptr = get_cstring(&xkey) as *mut _;
        *vptr = val as *const _ as *mut _;
        true
    } else {
        false
    }
}

/// Free a HashIter returned from ScConfHashIter.
#[no_mangle]
pub unsafe extern "C" fn ScConfHashIterFree(iter: *mut YamlHashIter) {
    let _ = Box::from_raw(iter);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn ScConfSet(key: *const c_char, value: *const c_char) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let value = match CStr::from_ptr(value).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let mut root = GLOBAL.write().unwrap();
    if root.set_from_str(key, value) {
        1
    } else {
        0
    }
}

/// Check if a configuration value is truthy.
///
/// In addition to boolean with a true value, this will also return true on strings
/// that are truthy like "yes", "on", or "1", or treat non-zero integer values
/// as true.
#[no_mangle]
pub unsafe extern "C" fn ScConfValueIsTrue(value: *const Yaml) -> bool {
    if value.is_null() {
        false
    } else {
        (*value).is_true()
    }
}

#[no_mangle]
pub unsafe extern "C" fn ScConfValueString(node: &Yaml) -> *const c_char {
    match node {
        Yaml::String(s) => get_cstring(s),
        Yaml::Boolean(v) => get_cstring(&*v.to_string()),
        Yaml::Integer(v) => get_cstring(&*v.to_string()),
        Yaml::Real(v) => get_cstring(v),
        Yaml::Null => get_cstring("~"),
        _ => std::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ScConfHashGet(node: &Yaml, key: *const c_char) -> *const Yaml {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(s) => Yaml::from_str(s),
        Err(_) => return std::ptr::null(),
    };

    if let Some(value) = node.as_hash().and_then(|h| h.get(&key)) {
        value as *const _
    } else {
        std::ptr::null()
    }
}

#[no_mangle]
pub extern "C" fn ScYamlGetType(node: &Yaml) -> ScYamlType {
    match node {
        Yaml::Hash(_) => ScYamlType::Hash,
        Yaml::Array(_) => ScYamlType::Array,
        Yaml::String(_) => ScYamlType::String,
        Yaml::Boolean(_) => ScYamlType::Boolean,
        Yaml::Integer(_) => ScYamlType::Integer,
        Yaml::Real(_) => ScYamlType::Real,
        Yaml::Null => ScYamlType::Null,
        _ => ScYamlType::Unknown,
    }
}

#[no_mangle]
pub extern "C" fn ScYamlIsHash(node: &Yaml) -> bool {
    node.as_hash().is_some()
}

#[no_mangle]
pub extern "C" fn ScConfGetGlobal() -> *mut Yaml {
    let global = GLOBAL.read().unwrap();
    (&*global) as *const _ as *mut _
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{loader, set_global};

    fn test_ffi_conf_get() {
        let doc = r#"
        simple: value
        nested:
            aaa: bbb
        "#;
        let config = loader::load_from_str(doc).unwrap().pop().unwrap();
        set_global(config);

        let key = CString::new("nested.aaa").unwrap();
        let mut value: *const c_char = std::ptr::null();
        let rc = unsafe { ScConfGet(key.as_ptr(), &mut value) };
        assert_eq!(rc, 0);
        assert_ne!(value, std::ptr::null());
        let expected = CString::new("bbb").unwrap();
        let actual = unsafe { CString::from_raw(value as *mut _) };
        assert_eq!(expected, actual);
    }

    fn test_ffi_conf_getint() {
        let doc = r#"
        simple: value
        nested:
            int: 999
        "#;
        let config = loader::load_from_str(doc).unwrap().pop().unwrap();
        set_global(config);
        let mut vptr: i64 = -1;
        let key = CString::new("nested.int").unwrap();
        let rc = unsafe { ScConfGetInt(key.as_ptr() as *mut _, &mut vptr) };
        assert_eq!(rc, 1);
        assert_eq!(vptr, 999);
    }

    #[test]
    fn run_tests() {
        test_ffi_conf_get();
        test_ffi_conf_getint();
    }
}
