//! Utility library module for commonly used strings, hexadecimals and other elements.

use super::build_slice;
use crate::jsonbuilder::HEX;
use std::ffi::CString;
use std::os::raw::c_char;

pub mod nom7 {
    use nom7::bytes::streaming::{tag, take_until};
    use nom7::error::{Error, ParseError};
    use nom7::ErrorConvert;
    use nom7::IResult;

    /// Reimplementation of `take_until_and_consume` for nom 7
    ///
    /// `take_until` does not consume the matched tag, and
    /// `take_until_and_consume` was removed in nom 7. This function
    /// provides an implementation (specialized for `&[u8]`).
    pub fn take_until_and_consume<'a, E: ParseError<&'a [u8]>>(
        t: &'a [u8],
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], &'a [u8], E> {
        move |i: &'a [u8]| {
            let (i, res) = take_until(t)(i)?;
            let (i, _) = tag(t)(i)?;
            Ok((i, res))
        }
    }

    /// Specialized version of the nom 7 `bits` combinator
    ///
    /// The `bits combinator has trouble inferring the transient error type
    /// used by the tuple parser, because the function is generic and any
    /// error type would be valid.
    /// Use an explicit error type (as described in
    /// https://docs.rs/nom/7.1.0/nom/bits/fn.bits.html) to solve this problem, and
    /// specialize this function for `&[u8]`.
    pub fn bits<'a, O, E, P>(parser: P) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
    where
        E: ParseError<&'a [u8]>,
        Error<(&'a [u8], usize)>: ErrorConvert<E>,
        P: FnMut((&'a [u8], usize)) -> IResult<(&'a [u8], usize), O, Error<(&'a [u8], usize)>>,
    {
        // use full path to disambiguate nom `bits` from this current function name
        nom7::bits::bits(parser)
    }
}

#[cfg(not(feature = "debug-validate"))]
#[macro_export]
macro_rules! debug_validate_bug_on (
  ($item:expr) => {};
);

#[cfg(feature = "debug-validate")]
#[macro_export]
macro_rules! debug_validate_bug_on (
  ($item:expr) => {
    if $item {
        panic!("Condition check failed");
    }
  };
);

#[cfg(not(feature = "debug-validate"))]
#[macro_export]
macro_rules! debug_validate_fail (
  ($msg:expr) => {};
);

#[cfg(feature = "debug-validate")]
#[macro_export]
macro_rules! debug_validate_fail (
  ($msg:expr) => {
    // Wrap in a conditional to prevent unreachable code warning in caller.
    if true {
      panic!($msg);
    }
  };
);

/// Convert a String to C-compatible string
///
/// This function will consume the provided data and use the underlying bytes to construct a new
/// string, ensuring that there is a trailing 0 byte. This trailing 0 byte will be appended by this
/// function; the provided data should *not* contain any 0 bytes in it.
///
/// Returns a valid pointer, or NULL
pub fn rust_string_to_c(s: String) -> *mut c_char {
    CString::new(s)
        .map(|c_str| c_str.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Free a CString allocated by Rust (for ex. using `rust_string_to_c`)
///
/// # Safety
///
/// s must be allocated by rust, using `CString::new`
#[no_mangle]
pub unsafe extern "C" fn rs_cstring_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}

/// Convert an u8-array of data into a hexadecimal representation
pub fn to_hex(input: &[u8]) -> String {
    return input
        .iter()
        .flat_map(|b| {
            vec![
                char::from(HEX[(b >> 4) as usize]),
                char::from(HEX[(b & 0xf) as usize]),
            ]
        })
        .collect();
}

#[no_mangle]
pub unsafe extern "C" fn rs_to_hex(
    output: *mut u8, out_len: usize, input: *const u8, in_len: usize,
) {
    if out_len < 2 * in_len + 1 {
        return;
    }
    let islice = build_slice!(input, in_len);
    let oslice = std::slice::from_raw_parts_mut(output, 2 * in_len + 1);
    // only used from C
    for i in 0..islice.len() {
        oslice[2 * i] = HEX[(islice[i] >> 4) as usize];
        oslice[2 * i + 1] = HEX[(islice[i] & 0xf) as usize];
    }
    oslice[2 * islice.len()] = 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_to_hex_sep(
    output: *mut u8, out_len: usize, sep: u8, input: *const u8, in_len: usize,
) {
    if out_len < 3 * in_len {
        return;
    }
    let islice = build_slice!(input, in_len);
    let oslice = std::slice::from_raw_parts_mut(output, 3 * in_len);
    // only used from C
    for i in 0..islice.len() {
        oslice[3 * i] = HEX[(islice[i] >> 4) as usize];
        oslice[3 * i + 1] = HEX[(islice[i] & 0xf) as usize];
        oslice[3 * i + 2] = sep;
    }
    // overwrites last separator with final null char
    oslice[3 * islice.len() - 1] = 0;
}

use aho_corasick::AhoCorasick;
use std::collections::HashMap;

#[derive(Debug,Clone)]
struct AhoCorasickPatternData {
    pat: Vec<u8>,
    sids: Vec<u32>,
    ci: bool,
    offset: u16,
    depth: u16,
}

impl AhoCorasickPatternData {
    fn new(pat: Vec<u8>, ci: bool, sids: Vec<u32>, offset: u16, depth: u16) -> Self {
        Self { pat, ci, sids, offset, depth }
    }
}

#[derive(Default)]
pub struct AhoCorasickStateBuilder {
    /// vector of patterns. The final pattern id will depend on the position in this
    /// vector, starting at 0.
    patterns: Vec<Vec<u8>>,
    pattern_id: u32,
    /// Hash of patterns with their settings. Will be copied to AhoCorasickStateBuilder
    /// in the prepare step.
    pattern_data: HashMap<u32,AhoCorasickPatternData>,
    /// track if we have case insensitive patterns. If so, we need to tell AC and
    /// do a bit more work in validation.
    has_ci: bool,
}

impl AhoCorasickStateBuilder {
    fn new() -> Self {
        Self { ..Default::default() }
    }
    fn add_pattern(&mut self, pat: Vec<u8>, ci: bool, sids: Vec<u32>, offset: u16, depth: u16) {
        self.patterns.push(pat.clone());
        if ci {
            self.has_ci = true;
        }
        let pattern_id = self.pattern_id;
        self.pattern_id += 1;

        self.pattern_data.insert(pattern_id, AhoCorasickPatternData::new(pat.clone(), ci, sids, offset, depth));
    }
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_new_builder() -> *mut std::os::raw::c_void {
    let state = AhoCorasickStateBuilder::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_free_builder(state: *mut std::os::raw::c_void) {
    let mut _state = unsafe { Box::from_raw(state as *mut AhoCorasickStateBuilder) };
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_add_pattern(state: &mut AhoCorasickStateBuilder,
    pat: *mut u8, pat_len: u16, sids: *mut u32, sids_len: u32, ci: bool, offset: u16, depth: u16) -> i32 {
    let p = unsafe { build_slice!(pat, pat_len as usize) };
    let s = unsafe { build_slice!(sids, sids_len as usize) };
    state.add_pattern(p.to_vec(), ci, s.to_vec(), offset, depth);
    return 0;
}

pub struct AhoCorasickState {
    pattern_cnt: u32,
    pattern_data: HashMap<u32,AhoCorasickPatternData>,
    has_ci: bool,
    ac: AhoCorasick,
}

impl AhoCorasickState {
    /// build the AC state from the builder
    fn prepare(builder: &AhoCorasickStateBuilder) -> Self {
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(builder.has_ci)
            .build(&builder.patterns)
            .unwrap();
        Self { ac, has_ci: builder.has_ci, pattern_cnt: builder.pattern_id, pattern_data: builder.pattern_data.clone() }
    }

    /// Search for the patterns. Returns number of matches.
    /// Per pattern found sids are only appended once.
    /// TODO review match_cnt logic. In general it's tuned to the unittests now, but it leads to
    /// some inefficienty. Could make sense to check the bool array first instead of doing the
    /// hash map lookup.
    fn search(&self, haystack: &[u8], sids: &mut Vec<u32>) -> u32 {
        SCLogDebug!("haystack {:?}: looking for {} patterns. Has CI {}", haystack, self.pattern_cnt, self.has_ci);
        let mut match_cnt = 0;
        // array of bools for patterns we found
        let mut matches = vec![false; self.pattern_cnt as usize];
        for mat in self.ac.find_overlapping_iter(haystack) {
            let pat_id = mat.pattern();
            let data = self.pattern_data.get(&pat_id.as_u32()).unwrap();
            if self.has_ci && !data.ci {
                let found = &haystack[mat.start()..mat.end()];
                if found != data.pat {
                    SCLogDebug!("pattern {:?} failed: not an exact match", pat_id);
                    continue;
                }
            }
            match_cnt += 1;

            /* bail if we found this pattern before */
            // TODO would prefer to do this first, but this messes up match_cnt.
            if matches[pat_id] {
                SCLogDebug!("pattern {:?} already found", pat_id);
                continue;
            }
            /* enforce offset and depth */
            if data.offset as usize > mat.start() {
                SCLogDebug!("pattern {:?} failed: found before offset", pat_id);
                continue;
            }
            if data.depth != 0 && mat.end() > data.depth as usize {
                SCLogDebug!("pattern {:?} failed: after depth", pat_id);
                continue;
            }
            matches[pat_id] = true;
            SCLogDebug!("match! {:?}: {:?}", pat_id, data);
            sids.append(&mut data.sids.clone());
        }
        return match_cnt;
    }
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_prepare_builder(builder: &AhoCorasickStateBuilder) -> *mut std::os::raw::c_void {
    let state = AhoCorasickState::prepare(builder);
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}
#[no_mangle]
pub extern "C" fn rs_mpm_acrs_state_free(state: *mut std::os::raw::c_void) {
    let mut _state = unsafe { Box::from_raw(state as *mut AhoCorasickState) };
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_search(state: &AhoCorasickState, data: *const u8, data_len: u32,
    func: unsafe extern "C" fn(*mut std::os::raw::c_void, *const u32, u32),
    thunk: *mut std::os::raw::c_void) -> u32
{
    let mut sids: Vec<u32> = Vec::new();
    let data = unsafe { build_slice!(data, data_len as usize) };
    let matches = state.search(data, &mut sids);
    if !sids.is_empty() {
        let sids_s = sids.as_ptr();
        unsafe { func(thunk, sids_s, sids.len() as u32); };
    }
    matches
}
