/* Copyright (C) 2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/* Wrapper around the aho-corasick crate to expose to the Suricata's
 * MPM API. */

use aho_corasick::{AhoCorasick,AhoCorasickKind};

#[derive(Debug,Clone)]
struct AhoCorasickPatternData {
    pat: Vec<u8>,
    ci: bool,
    offset: u16,
    depth: u16,
    sids: Vec<u32>,
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
    /// Hash of patterns with their settings. Will be copied to AhoCorasickStateBuilder
    /// in the prepare step.
    pattern_data: Vec<AhoCorasickPatternData>,
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
        self.pattern_data.push(AhoCorasickPatternData::new(pat.clone(), ci, sids, offset, depth));
    }
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_new_builder() -> *mut std::os::raw::c_void {
    let state = AhoCorasickStateBuilder::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mpm_acrs_free_builder(state: *mut std::os::raw::c_void) {
    let mut _state = Box::from_raw(state as *mut AhoCorasickStateBuilder);
}

#[no_mangle]
pub unsafe extern "C" fn rs_mpm_acrs_add_pattern(state: &mut AhoCorasickStateBuilder,
    pat: *mut u8, pat_len: u16, sids: *mut u32, sids_len: u32, ci: bool, offset: u16, depth: u16) -> i32 {
    let p = build_slice!(pat, pat_len as usize);
    let s = build_slice!(sids, sids_len as usize);
    state.add_pattern(p.to_vec(), ci, s.to_vec(), offset, depth);
    return 0;
}

pub struct AhoCorasickState {
    _pattern_cnt: u32,
    pat_bitarray_size: u32,
    ac: AhoCorasick,
    pattern_data: Vec<AhoCorasickPatternData>,
    has_ci: bool,
}

impl AhoCorasickState {
    /// build the AC state from the builder
    fn prepare(builder: &AhoCorasickStateBuilder) -> Self {
        let ac = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .ascii_case_insensitive(builder.has_ci)
            .build(&builder.patterns)
            .unwrap();
        Self { ac, has_ci: builder.has_ci, _pattern_cnt: builder.patterns.len() as u32, 
            pat_bitarray_size: (builder.patterns.len() as u32 / 8) + 1,
            pattern_data: builder.pattern_data.clone() }
    }
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_prepare_builder(builder: &AhoCorasickStateBuilder) -> *mut std::os::raw::c_void {
    let state = AhoCorasickState::prepare(builder);
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}
#[no_mangle]
pub unsafe extern "C" fn rs_mpm_acrs_state_free(state: *mut std::os::raw::c_void) {
    let mut _state = Box::from_raw(state as *mut AhoCorasickState);
}

/// Search for the patterns. Returns number of matches.
/// Per pattern found sids are only appended once.
#[no_mangle]
pub unsafe extern "C" fn rs_mpm_acrs_search(state: &AhoCorasickState, data: *const u8, data_len: u32,
    cb: unsafe extern "C" fn(*mut std::os::raw::c_void, *const u32, u32),
    cbdata: *mut std::os::raw::c_void) -> u32
{
    let haystack = build_slice!(data, data_len as usize);
    let mut match_cnt : u32 = 0;
    // track unique matches using a bitarray
    let mut bitarray = vec![0u8; state.pat_bitarray_size as usize];
    for mat in state.ac.find_overlapping_iter(haystack) {
        let pat_id = mat.pattern().as_u32();
        /* bail if we found this pattern before */
        if bitarray[(pat_id / 8) as usize] & (1 << (pat_id % 8) as usize) != 0 {
            SCLogDebug!("pattern {:?} already found", pat_id);
            continue;
        }

        let pattern = &state.pattern_data[mat.pattern()];
        if state.has_ci && !pattern.ci {
            let found = &haystack[mat.start()..mat.end()];
            if found != pattern.pat {
                SCLogDebug!("pattern {:?} failed: not an exact match", pat_id);
                continue;
            }
        }

        /* enforce offset and depth */
        if pattern.offset as usize > mat.start() {
            SCLogDebug!("pattern {:?} failed: found before offset", pat_id);
            continue;
        }
        if pattern.depth != 0 && mat.end() > pattern.depth as usize {
            SCLogDebug!("pattern {:?} failed: after depth", pat_id);
            continue;
        }
        bitarray[(pat_id / 8) as usize] |= 1 << (pat_id % 8) as usize;
        SCLogDebug!("match! {:?}: {:?}", pat_id, pattern);
        cb(cbdata, pattern.sids.as_ptr(), pattern.sids.len() as u32);
        match_cnt += 1;
    }
    match_cnt
}

use aho_corasick::{ automaton::Automaton, dfa::DFA, Input };

pub struct AhoCorasickDFAState {
    _pattern_cnt: u32,
    pat_bitarray_size: u32,
    dfa: DFA,
    pattern_data: Vec<AhoCorasickPatternData>,
    has_ci: bool,
}

impl AhoCorasickDFAState {
    /// build the AC state from the builder
    fn prepare(builder: &AhoCorasickStateBuilder) -> Self {
        let dfa = DFA::builder()
            .ascii_case_insensitive(builder.has_ci)
            .build(&builder.patterns)
            .unwrap();
        Self { dfa, has_ci: builder.has_ci, _pattern_cnt: builder.patterns.len() as u32, 
            pat_bitarray_size: (builder.patterns.len() as u32 / 8) + 1,
            pattern_data: builder.pattern_data.clone() }
    }
}

#[no_mangle]
pub extern "C" fn rs_mpm_acrs_dfa_prepare_builder(builder: &AhoCorasickStateBuilder) -> *mut std::os::raw::c_void {
    let state = AhoCorasickDFAState::prepare(builder);
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}
#[no_mangle]
pub unsafe extern "C" fn rs_mpm_acrs_dfa_state_free(state: *mut std::os::raw::c_void) {
    let mut _state = Box::from_raw(state as *mut AhoCorasickDFAState);
}

/// Search for the patterns. Returns number of matches.
/// Per pattern found sids are only appended once.
#[no_mangle]
pub unsafe extern "C" fn rs_mpm_acrs_dfa_search(state: &AhoCorasickDFAState, data: *const u8, data_len: u32,
    cb: unsafe extern "C" fn(*mut std::os::raw::c_void, *const u32, u32),
    cbdata: *mut std::os::raw::c_void) -> u32
{
    let haystack = build_slice!(data, data_len as usize);
    let mut match_cnt : u32 = 0;
    // track unique matches using a bitarray
    let mut bitarray = vec![0u8; state.pat_bitarray_size as usize];
    for mat in state.dfa.try_find_overlapping_iter(Input::new(haystack)).unwrap() {
        let pat_id = mat.pattern().as_u32();
        /* bail if we found this pattern before */
        if bitarray[(pat_id / 8) as usize] & (1 << (pat_id % 8) as usize) != 0 {
            SCLogDebug!("pattern {:?} already found", pat_id);
            continue;
        }

        let pattern = &state.pattern_data[mat.pattern()];
        if state.has_ci && !pattern.ci {
            let found = &haystack[mat.start()..mat.end()];
            if found != pattern.pat {
                SCLogDebug!("pattern {:?} failed: not an exact match", pat_id);
                continue;
            }
        }

        /* enforce offset and depth */
        if pattern.offset as usize > mat.start() {
            SCLogDebug!("pattern {:?} failed: found before offset", pat_id);
            continue;
        }
        if pattern.depth != 0 && mat.end() > pattern.depth as usize {
            SCLogDebug!("pattern {:?} failed: after depth", pat_id);
            continue;
        }
        bitarray[(pat_id / 8) as usize] |= 1 << (pat_id % 8) as usize;
        SCLogDebug!("match! {:?}: {:?}", pat_id, pattern);
        cb(cbdata, pattern.sids.as_ptr(), pattern.sids.len() as u32);
        match_cnt += 1;
    }
    match_cnt
}
