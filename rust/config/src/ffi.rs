// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! The C interface to the loader, used by `conf-yaml-loader.c` to load
//! a configuration and walk the resulting tree.
//!
//! A loaded configuration is an opaque `SCConfTree`, its nodes are
//! opaque `SCConfTreeNode`s owned by the tree. Strings returned to C are
//! a pointer and a length, not NUL terminated, and are valid as long as
//! the tree is. Errors are returned as a message allocated by Rust,
//! freed with `SCConfTreeErrorFree`.
//!
//! Nothing here logs: loading returns a result and C logs the error.

use std::ffi::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

use crate::loader::load_file_with_include_dir;
use crate::loader::load_string_with_include_dir;
use crate::loader::merge_file;
use crate::overrides::apply_override;
use crate::LoadError;
use crate::Node;
use crate::Override;
use crate::OverrideError;

/// A loaded configuration.
pub struct ConfTree {
    root: Node,
    // The command line overrides, in the order they were given.
    overrides: Vec<OverrideResult>,
}

// What became of a command line override.
struct OverrideResult {
    // The path as resolved, joined with dots, with the indexes of
    // sequences in their canonical form.
    path: String,
    // Whether it was applied to the tree. An override that names a
    // child of a sequence is not: the tree has no place for it, and C
    // applies it to its own tree, which does.
    applied: bool,
    // Whether the node at the path still has the value of the override
    // after all of them were applied, that is a later override did not
    // replace it. The value is converted to UTF-8 for the tree, so the
    // caller sets it again from the bytes it was given.
    is_value: bool,
}

/// Why a configuration could not be loaded.
#[derive(Debug, thiserror::Error)]
enum FfiError {
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error(transparent)]
    Override(#[from] OverrideError),
}

/// The kind of a node.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SCConfTreeKind {
    Null,
    Scalar,
    Sequence,
    Mapping,
}

// The directory of a configuration file, for resolving includes.
fn file_include_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

// Return a message to C through `err`, if it is not NULL.
unsafe fn set_error(err: *mut *mut c_char, message: String) {
    if err.is_null() {
        return;
    }
    // A message can't contain a NUL unless a file name does.
    let message = CString::new(message.replace('\0', "\u{fffd}")).unwrap_or_default();
    *err = message.into_raw();
}

// A file system path from a NUL terminated string, as the bytes it is
// (on Unix a path need not be UTF-8).
unsafe fn path(s: *const c_char) -> PathBuf {
    let bytes = CStr::from_ptr(s).to_bytes();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

// The paths of a C array of NUL terminated strings.
unsafe fn paths(array: *const *const c_char, len: usize) -> Vec<PathBuf> {
    if array.is_null() {
        return Vec::new();
    }
    std::slice::from_raw_parts(array, len)
        .iter()
        .map(|s| path(*s))
        .collect()
}

// The strings of a C array of NUL terminated strings, with bytes that
// are not UTF-8 replaced.
unsafe fn strings(array: *const *const c_char, len: usize) -> Vec<String> {
    if array.is_null() {
        return Vec::new();
    }
    std::slice::from_raw_parts(array, len)
        .iter()
        .map(|s| CStr::from_ptr(*s).to_string_lossy().into_owned())
        .collect()
}

// Load a configuration file, merge the `--include` files into it and
// apply the overrides. The overrides are checked first, so a bad path
// fails before any file is read.
fn load(
    path: &Path, include_dir: &Path, includes: &[PathBuf], overrides: &[(String, String)],
) -> Result<ConfTree, FfiError> {
    let overrides = overrides
        .iter()
        .map(|(path, value)| Override::new(path, value))
        .collect::<Result<Vec<Override>, _>>()?;
    let mut root = load_file_with_include_dir(path, include_dir)?;
    for include in includes {
        merge_file(&mut root, include, include_dir)?;
    }
    let mut results = Vec::with_capacity(overrides.len());
    for override_ in &overrides {
        let result = match apply_override(&mut root, override_) {
            Ok(resolved) => OverrideResult {
                path: resolved.join("."),
                applied: true,
                is_value: false,
            },
            Err(OverrideError::NotAnIndex { path, .. }) => OverrideResult {
                path,
                applied: false,
                is_value: false,
            },
            Err(error) => return Err(error.into()),
        };
        results.push(result);
    }
    for (result, override_) in results.iter_mut().zip(&overrides) {
        result.is_value = result.applied
            && root.get_path(&result.path).and_then(Node::as_str) == Some(override_.value.as_str());
    }
    Ok(ConfTree {
        root,
        overrides: results,
    })
}

/// Load a configuration file, then the `includes` (the `--include`
/// files) into it in order, then apply the command line overrides in
/// order: the values at `override_values` for the dotted paths at
/// `override_paths`, both used as given (a `--set` argument is split
/// and trimmed by the caller).
///
/// An override that names a child of a sequence, like
/// `pcap.buffer-size` where `pcap` is a sequence, is not an error but
/// is not applied either, see `SCConfTreeOverrideApplied`.
///
/// Relative include paths, also in included files, are resolved from
/// `include_dir`, or the directory of `path` if `include_dir` is NULL.
/// On error NULL is returned and, if `err` is not NULL, `*err` is set to
/// a message to be freed with `SCConfTreeErrorFree`.
///
/// # Safety
///
/// `path`, and `include_dir` if not NULL, must be NUL terminated
/// strings, `includes` must point to `n_includes` of them and
/// `override_paths` and `override_values` to `n_overrides` of them
/// each.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeLoadFile(
    path: *const c_char, include_dir: *const c_char, includes: *const *const c_char,
    n_includes: usize, override_paths: *const *const c_char, override_values: *const *const c_char,
    n_overrides: usize, err: *mut *mut c_char,
) -> *mut ConfTree {
    let path = self::path(path);
    let include_dir = if include_dir.is_null() {
        file_include_dir(&path)
    } else {
        self::path(include_dir)
    };
    let includes = paths(includes, n_includes);
    let overrides: Vec<(String, String)> = strings(override_paths, n_overrides)
        .into_iter()
        .zip(strings(override_values, n_overrides))
        .collect();

    match load(&path, &include_dir, &includes, &overrides) {
        Ok(tree) => Box::into_raw(Box::new(tree)),
        Err(error) => {
            set_error(err, error.to_string());
            ptr::null_mut()
        }
    }
}

/// Load a configuration from a string of `len` bytes.
///
/// Relative include paths are resolved from `include_dir`, or the
/// current directory if it is NULL. Errors are returned like
/// `SCConfTreeLoadFile`.
///
/// # Safety
///
/// `input` must point to `len` bytes, and `include_dir` must be a NUL
/// terminated string if not NULL.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeLoadString(
    input: *const c_char, len: usize, include_dir: *const c_char, err: *mut *mut c_char,
) -> *mut ConfTree {
    let input = std::slice::from_raw_parts(input as *const u8, len);
    let input = String::from_utf8_lossy(input);
    let include_dir = if include_dir.is_null() {
        PathBuf::from(".")
    } else {
        path(include_dir)
    };

    match load_string_with_include_dir(&input, &include_dir) {
        Ok(root) => Box::into_raw(Box::new(ConfTree {
            root,
            overrides: Vec::new(),
        })),
        Err(error) => {
            set_error(err, error.to_string());
            ptr::null_mut()
        }
    }
}

/// Free a configuration returned by `SCConfTreeLoadFile` or
/// `SCConfTreeLoadString`, and all its nodes.
///
/// # Safety
///
/// `tree` must have been returned by one of the load functions, or be
/// NULL.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeFree(tree: *mut ConfTree) {
    if !tree.is_null() {
        drop(Box::from_raw(tree));
    }
}

/// Free an error message returned by one of the load functions.
///
/// # Safety
///
/// `err` must have been returned by one of the load functions, or be
/// NULL.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeErrorFree(err: *mut c_char) {
    if !err.is_null() {
        drop(CString::from_raw(err));
    }
}

/// The root node of a configuration, a mapping.
///
/// # Safety
///
/// `tree` must be a valid configuration.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeRoot(tree: *const ConfTree) -> *const Node {
    &(*tree).root
}

/// The number of command line overrides of a configuration, applied or
/// not.
///
/// # Safety
///
/// `tree` must be a valid configuration.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeOverrideCount(tree: *const ConfTree) -> usize {
    let tree = &*tree;
    tree.overrides.len()
}

/// Whether command line override `index` was applied to the tree. An
/// override that names a child of a sequence is not, as a sequence has
/// only indexes; the caller applies it to its own tree. False if `index`
/// is out of range.
///
/// # Safety
///
/// `tree` must be a valid configuration.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeOverrideApplied(tree: *const ConfTree, index: usize) -> bool {
    let tree = &*tree;
    tree.overrides
        .get(index)
        .is_some_and(|result| result.applied)
}

/// Whether the node at the path of command line override `index`, an
/// applied one, has the value of the override after all of them were
/// applied, that is a later override did not replace it or give it
/// children. The tree has the value converted to UTF-8, with invalid
/// bytes replaced, so the caller can set it again from the bytes it was
/// given, like a file name that is not UTF-8. False if `index` is out
/// of range.
///
/// # Safety
///
/// `tree` must be a valid configuration.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeOverrideIsValue(tree: *const ConfTree, index: usize) -> bool {
    let tree = &*tree;
    tree.overrides
        .get(index)
        .is_some_and(|result| result.is_value)
}

/// The dotted path of command line override `index` as resolved, like
/// `stream.midstream` or `outputs.1.eve-log.enabled` with the indexes
/// of sequences in their canonical form, with its length in bytes in
/// `*len`. The string is not NUL terminated. NULL, with `*len` 0, if
/// `index` is out of range.
///
/// # Safety
///
/// `tree` must be a valid configuration and `len` a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeOverridePath(
    tree: *const ConfTree, index: usize, len: *mut usize,
) -> *const c_char {
    let tree = &*tree;
    match tree.overrides.get(index) {
        Some(result) => {
            *len = result.path.len();
            str_ptr(&result.path)
        }
        None => {
            *len = 0;
            ptr::null()
        }
    }
}

/// The kind of a node.
///
/// # Safety
///
/// `node` must be a valid node.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeNodeKind(node: *const Node) -> SCConfTreeKind {
    match &*node {
        Node::Null => SCConfTreeKind::Null,
        Node::Scalar(_) => SCConfTreeKind::Scalar,
        Node::Sequence(_) => SCConfTreeKind::Sequence,
        Node::Mapping(_) => SCConfTreeKind::Mapping,
    }
}

/// A pointer to the bytes of a string for C. An empty `String` has no
/// allocation and `as_ptr` returns a dangling pointer, which C string
/// functions may read even for a length of 0 (glibc's `strndup` does),
/// so an empty string points at a NUL instead.
///
/// Not a `c""` literal: the syn 1 based cbindgen of some distributions
/// cannot parse those.
fn str_ptr(s: &str) -> *const c_char {
    static EMPTY: [c_char; 1] = [0];
    if s.is_empty() {
        EMPTY.as_ptr()
    } else {
        s.as_ptr() as *const c_char
    }
}

/// The value of a scalar node, with its length in bytes in `*len`. The
/// string is not NUL terminated. NULL, with `*len` 0, for a node that
/// is not a scalar.
///
/// # Safety
///
/// `node` must be a valid node and `len` a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeNodeScalar(node: *const Node, len: *mut usize) -> *const c_char {
    match &*node {
        Node::Scalar(value) => {
            *len = value.len();
            str_ptr(value)
        }
        _ => {
            *len = 0;
            ptr::null()
        }
    }
}

/// The number of items of a sequence or entries of a mapping, 0 for
/// other nodes.
///
/// # Safety
///
/// `node` must be a valid node.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeNodeLen(node: *const Node) -> usize {
    match &*node {
        Node::Sequence(items) => items.len(),
        Node::Mapping(mapping) => mapping.len(),
        _ => 0,
    }
}

/// Item `index` of a sequence, or entry `index` of a mapping in document
/// order. For a mapping `*key` and `*key_len` are set to the key, not
/// NUL terminated; for a sequence they are set to NULL and 0. NULL if
/// `index` is out of range or the node is neither.
///
/// # Safety
///
/// `node` must be a valid node, `key` and `key_len` valid pointers.
#[no_mangle]
pub unsafe extern "C" fn SCConfTreeNodeItem(
    node: *const Node, index: usize, key: *mut *const c_char, key_len: *mut usize,
) -> *const Node {
    *key = ptr::null();
    *key_len = 0;
    match &*node {
        Node::Sequence(items) => items.get(index).map_or(ptr::null(), |item| item),
        Node::Mapping(mapping) => match mapping.get_index(index) {
            Some((name, item)) => {
                *key = str_ptr(name);
                *key_len = name.len();
                item
            }
            None => ptr::null(),
        },
        _ => ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The items of a node, with the keys of a mapping.
    unsafe fn items(node: *const Node) -> Vec<(Option<String>, *const Node)> {
        (0..SCConfTreeNodeLen(node))
            .map(|index| {
                let mut key = ptr::null();
                let mut key_len = 0;
                let item = SCConfTreeNodeItem(node, index, &mut key, &mut key_len);
                let key = (!key.is_null()).then(|| {
                    String::from_utf8(
                        std::slice::from_raw_parts(key as *const u8, key_len).to_vec(),
                    )
                    .unwrap()
                });
                (key, item)
            })
            .collect()
    }

    unsafe fn scalar(node: *const Node) -> Option<String> {
        let mut len = 0;
        let value = SCConfTreeNodeScalar(node, &mut len);
        (!value.is_null()).then(|| {
            String::from_utf8(std::slice::from_raw_parts(value as *const u8, len).to_vec()).unwrap()
        })
    }

    #[test]
    fn test_load_string() {
        let input = "a: 1\nb:\n  - x\n  - k: v\nc: ~\n";
        unsafe {
            let mut err = ptr::null_mut();
            let tree = SCConfTreeLoadString(
                input.as_ptr() as *const c_char,
                input.len(),
                ptr::null(),
                &mut err,
            );
            assert!(!tree.is_null());
            assert!(err.is_null());

            let root = SCConfTreeRoot(tree);
            assert_eq!(SCConfTreeNodeKind(root), SCConfTreeKind::Mapping);
            assert_eq!(SCConfTreeNodeLen(root), 3);
            assert!(scalar(root).is_none());

            let entries = items(root);
            assert_eq!(entries[0].0.as_deref(), Some("a"));
            assert_eq!(SCConfTreeNodeKind(entries[0].1), SCConfTreeKind::Scalar);
            assert_eq!(scalar(entries[0].1).as_deref(), Some("1"));

            assert_eq!(entries[1].0.as_deref(), Some("b"));
            let seq = entries[1].1;
            assert_eq!(SCConfTreeNodeKind(seq), SCConfTreeKind::Sequence);
            let seq_items = items(seq);
            assert_eq!(seq_items.len(), 2);
            assert_eq!(seq_items[0].0, None);
            assert_eq!(scalar(seq_items[0].1).as_deref(), Some("x"));
            assert_eq!(SCConfTreeNodeKind(seq_items[1].1), SCConfTreeKind::Mapping);
            assert_eq!(items(seq_items[1].1)[0].0.as_deref(), Some("k"));

            assert_eq!(entries[2].0.as_deref(), Some("c"));
            assert_eq!(SCConfTreeNodeKind(entries[2].1), SCConfTreeKind::Null);
            assert_eq!(SCConfTreeNodeLen(entries[2].1), 0);
            assert!(scalar(entries[2].1).is_none());

            // Out of range.
            let mut key = ptr::null();
            let mut key_len = 0;
            assert!(SCConfTreeNodeItem(root, 3, &mut key, &mut key_len).is_null());
            assert!(SCConfTreeNodeItem(entries[0].1, 0, &mut key, &mut key_len).is_null());

            SCConfTreeFree(tree);
        }
    }

    /// Empty strings are not returned as the dangling pointer of an
    /// empty `String`, as C reads it even for a length of 0.
    #[test]
    fn test_empty_strings() {
        let input = "a: \"\"\n\"\": b\n";
        unsafe {
            let mut err = ptr::null_mut();
            let tree = SCConfTreeLoadString(
                input.as_ptr() as *const c_char,
                input.len(),
                ptr::null(),
                &mut err,
            );
            assert!(!tree.is_null());
            let entries = items(SCConfTreeRoot(tree));
            assert_eq!(scalar(entries[0].1).as_deref(), Some(""));
            assert_eq!(entries[1].0.as_deref(), Some(""));

            let mut len = 0;
            let value = SCConfTreeNodeScalar(entries[0].1, &mut len);
            assert_eq!(len, 0);
            assert_eq!(*value, 0);
            let mut key = ptr::null();
            let mut key_len = 0;
            SCConfTreeNodeItem(SCConfTreeRoot(tree), 1, &mut key, &mut key_len);
            assert_eq!(key_len, 0);
            assert_eq!(*key, 0);

            SCConfTreeFree(tree);
        }
    }

    #[test]
    fn test_load_string_error() {
        let input = "a: [\n";
        unsafe {
            let mut err = ptr::null_mut();
            let tree = SCConfTreeLoadString(
                input.as_ptr() as *const c_char,
                input.len(),
                ptr::null(),
                &mut err,
            );
            assert!(tree.is_null());
            assert!(!err.is_null());
            let message = CStr::from_ptr(err).to_str().unwrap();
            assert!(message.starts_with("failed to parse"), "{message}");
            SCConfTreeErrorFree(err);

            // Without an error pointer.
            let tree = SCConfTreeLoadString(
                input.as_ptr() as *const c_char,
                input.len(),
                ptr::null(),
                ptr::null_mut(),
            );
            assert!(tree.is_null());
        }
    }

    #[test]
    fn test_load_file() {
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
        let path = CString::new(data.join("cli-include.yaml").to_str().unwrap()).unwrap();
        let include_a = CString::new("cli-include-a.yaml").unwrap();
        let include_b = CString::new("cli-include-b.yaml").unwrap();
        let includes = [include_a.as_ptr(), include_b.as_ptr()];
        let dir = CString::new(data.to_str().unwrap()).unwrap();
        unsafe {
            let mut err = ptr::null_mut();
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                ptr::null(),
                includes.as_ptr(),
                includes.len(),
                ptr::null(),
                ptr::null(),
                0,
                &mut err,
            );
            assert!(!tree.is_null(), "{:?}", CStr::from_ptr(err));
            let root = SCConfTreeRoot(tree);
            let keys: Vec<_> = items(root)
                .into_iter()
                .map(|(key, _)| key.unwrap())
                .collect();
            assert!(keys.contains(&"from-main".to_string()), "{keys:?}");
            assert!(keys.contains(&"from-a".to_string()), "{keys:?}");
            assert!(keys.contains(&"from-b".to_string()), "{keys:?}");
            SCConfTreeFree(tree);

            // The same with an explicit include directory.
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                dir.as_ptr(),
                includes.as_ptr(),
                includes.len(),
                ptr::null(),
                ptr::null(),
                0,
                &mut err,
            );
            assert!(!tree.is_null(), "{:?}", CStr::from_ptr(err));
            SCConfTreeFree(tree);

            // A missing include file is an error.
            let missing = CString::new("nope.yaml").unwrap();
            let includes = [missing.as_ptr()];
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                ptr::null(),
                includes.as_ptr(),
                includes.len(),
                ptr::null(),
                ptr::null(),
                0,
                &mut err,
            );
            assert!(tree.is_null());
            let message = CStr::from_ptr(err).to_str().unwrap();
            assert!(message.contains("nope.yaml"), "{message}");
            SCConfTreeErrorFree(err);

            // A missing file.
            let tree = SCConfTreeLoadFile(
                missing.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
                0,
                &mut err,
            );
            assert!(tree.is_null());
            SCConfTreeErrorFree(err);

            SCConfTreeFree(ptr::null_mut());
            SCConfTreeErrorFree(ptr::null_mut());
        }
    }

    unsafe fn override_paths(tree: *const ConfTree) -> Vec<String> {
        (0..SCConfTreeOverrideCount(tree))
            .map(|index| {
                let mut len = 0;
                let path = SCConfTreeOverridePath(tree, index, &mut len);
                String::from_utf8(std::slice::from_raw_parts(path as *const u8, len).to_vec())
                    .unwrap()
            })
            .collect()
    }

    // A value that is not UTF-8, like a file name, is replaced in the
    // tree, and the caller is told to set it again from its bytes,
    // unless a later override replaced it.
    #[test]
    fn test_load_file_override_is_value() {
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
        let path = CString::new(data.join("ffi-overrides.yaml").to_str().unwrap()).unwrap();
        let c = |s: &[u8]| CString::new(s).unwrap();
        let overrides = [
            (c(b"pcap-file.file"), c(b"/tmp/\xff.pcap")),
            (c(b"shared"), c(b"1")),
            (c(b"shared"), c(b"2")),
            (c(b"mapping"), c(b"3")),
            (c(b"mapping.b"), c(b"4")),
            (c(b"list.0"), c(b"5")),
        ];
        let paths: Vec<_> = overrides.iter().map(|(p, _)| p.as_ptr()).collect();
        let values: Vec<_> = overrides.iter().map(|(_, v)| v.as_ptr()).collect();
        unsafe {
            let mut err = ptr::null_mut();
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                paths.as_ptr(),
                values.as_ptr(),
                paths.len(),
                &mut err,
            );
            assert!(!tree.is_null(), "{:?}", CStr::from_ptr(err));
            let root = &(*tree).root;
            assert_eq!(
                root["pcap-file"]["file"].as_str(),
                Some("/tmp/\u{fffd}.pcap")
            );
            let is_value: Vec<bool> = (0..overrides.len())
                .map(|index| SCConfTreeOverrideIsValue(tree, index))
                .collect();
            assert_eq!(is_value, [true, false, true, false, true, true]);
            SCConfTreeFree(tree);
        }
    }

    #[test]
    fn test_load_file_overrides() {
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
        let path = CString::new(data.join("ffi-overrides.yaml").to_str().unwrap()).unwrap();
        let include_a = CString::new("cli-include-a.yaml").unwrap();
        let includes = [include_a.as_ptr()];
        let c = |s: &str| CString::new(s).unwrap();
        let (p1, v1) = (c("shared"), c(" from-set"));
        let (p2, v2) = (c("mapping.new.key"), c("1"));
        let (p3, v3) = (c("list.00"), c("x"));
        let (p4, v4) = (c("list.name"), c("y"));
        let paths = [p1.as_ptr(), p2.as_ptr(), p3.as_ptr(), p4.as_ptr()];
        let values = [v1.as_ptr(), v2.as_ptr(), v3.as_ptr(), v4.as_ptr()];
        unsafe {
            let mut err = ptr::null_mut();
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                ptr::null(),
                includes.as_ptr(),
                includes.len(),
                paths.as_ptr(),
                values.as_ptr(),
                paths.len(),
                &mut err,
            );
            assert!(!tree.is_null(), "{:?}", CStr::from_ptr(err));
            // The overrides are applied after the --include file, with
            // the values as given.
            let root = &(*tree).root;
            assert_eq!(root["shared"].as_str(), Some(" from-set"));
            assert_eq!(root["from-a"].as_str(), Some("1"));
            assert_eq!(root["mapping"]["new"]["key"].as_str(), Some("1"));
            assert_eq!(root["list"][0].as_str(), Some("x"));
            // The paths are resolved, and a name into a sequence is
            // reported as not applied.
            assert_eq!(
                override_paths(tree),
                ["shared", "mapping.new.key", "list.0", "list.name"]
            );
            assert!(SCConfTreeOverrideApplied(tree, 0));
            assert!(SCConfTreeOverrideApplied(tree, 2));
            assert!(!SCConfTreeOverrideApplied(tree, 3));
            assert!(!SCConfTreeOverrideApplied(tree, 4));
            assert!(SCConfTreeOverrideIsValue(tree, 0));
            assert!(!SCConfTreeOverrideIsValue(tree, 3));
            assert!(!SCConfTreeOverrideIsValue(tree, 4));
            SCConfTreeFree(tree);

            // A bad path is an error, before anything is read.
            let bad = c("a..b");
            let paths = [bad.as_ptr()];
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                paths.as_ptr(),
                values.as_ptr(),
                paths.len(),
                &mut err,
            );
            assert!(tree.is_null());
            let message = CStr::from_ptr(err).to_str().unwrap();
            assert!(
                message.starts_with("invalid argument for --set"),
                "{message}"
            );
            SCConfTreeErrorFree(err);

            // An index past the end of a sequence is an error.
            let bad = c("list.5");
            let paths = [bad.as_ptr()];
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                paths.as_ptr(),
                values.as_ptr(),
                paths.len(),
                &mut err,
            );
            assert!(tree.is_null());
            let message = CStr::from_ptr(err).to_str().unwrap();
            assert!(
                message.starts_with("cannot apply --set list.5"),
                "{message}"
            );
            SCConfTreeErrorFree(err);

            // A scalar along the path of an override is replaced with
            // a mapping.
            let deep = c("mapping.a.b.c");
            let paths = [deep.as_ptr()];
            let tree = SCConfTreeLoadFile(
                path.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                paths.as_ptr(),
                values.as_ptr(),
                paths.len(),
                &mut err,
            );
            assert!(!tree.is_null(), "{:?}", CStr::from_ptr(err));
            let root = &(*tree).root;
            assert_eq!(root["mapping"]["a"]["b"]["c"].as_str(), Some(" from-set"));
            SCConfTreeFree(tree);

            // No overrides from a string.
            let input = "a: 1\n";
            let tree = SCConfTreeLoadString(
                input.as_ptr() as *const c_char,
                input.len(),
                ptr::null(),
                &mut err,
            );
            assert_eq!(SCConfTreeOverrideCount(tree), 0);
            let mut len = 1;
            assert!(SCConfTreeOverridePath(tree, 0, &mut len).is_null());
            assert_eq!(len, 0);
            assert!(!SCConfTreeOverrideApplied(tree, 0));
            SCConfTreeFree(tree);
        }
    }
}
