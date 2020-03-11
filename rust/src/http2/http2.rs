/* Copyright (C) 2020 Open Information Security Foundation
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

use super::parser;
use crate::applayer::{self, LoggerFlags};
use crate::core::{self, AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::log::*;
use crate::parser::*;
use nom;
use std;
use std::ffi::CString;
use std::mem::transmute;

static mut ALPROTO_HTTP2: AppProto = ALPROTO_UNKNOWN;

const HTTP2_DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

pub struct HTTP2Transaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
}

impl HTTP2Transaction {
    pub fn new() -> HTTP2Transaction {
        HTTP2Transaction {
            tx_id: 0,
            request: None,
            response: None,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for HTTP2Transaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct HTTP2State {
    tx_id: u64,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    transactions: Vec<HTTP2Transaction>,
}

impl HTTP2State {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            transactions: Vec::new(),
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&HTTP2Transaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> HTTP2Transaction {
        let mut tx = HTTP2Transaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut HTTP2Transaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return true;
        }

        // For simplicity, always extend the buffer and work on it.
        self.request_buffer.extend(input);

        return true;
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return true;
        }

        // For simplicity, always extend the buffer and work on it.
        self.response_buffer.extend(input);

        return true;
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&HTTP2Transaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

// C exports.

export_tx_get_detect_state!(rs_http2_tx_get_detect_state, HTTP2Transaction);
export_tx_set_detect_state!(rs_http2_tx_set_detect_state, HTTP2Transaction);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_http2_probing_parser_tc(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    if input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        match parser::http2_parse_frame_header(slice) {
            Ok((_, header)) => {
                if header.reserved != 0
                    || header.length > HTTP2_DEFAULT_MAX_FRAME_SIZE
                    || header.flags & 0xFE != 0
                    || header.ftype != 4
                {
                    //TODO why unsafe ?
                    return unsafe { ALPROTO_FAILED };
                }
                return unsafe { ALPROTO_HTTP2 };
            }
            Err(nom::Err::Incomplete(_)) => {
                return ALPROTO_UNKNOWN;
            }
            Err(_) => {
                return unsafe { ALPROTO_FAILED };
            }
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_new() -> *mut std::os::raw::c_void {
    let state = HTTP2State::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_http2_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<HTTP2State> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_http2_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, HTTP2State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };

    if eof {
        // If needed, handled EOF, or pass it into the parser.
    }

    let state = cast_pointer!(state, HTTP2State);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_request(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, HTTP2State);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_response(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, HTTP2State);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, HTTP2State);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_event_info_by_id(
    _event_id: std::os::raw::c_int,
    _event_name: *mut *const std::os::raw::c_char,
    _event_type: *mut core::AppLayerEventType,
) -> i8 {
    return -1;
}
#[no_mangle]
pub extern "C" fn rs_http2_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, HTTP2State);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(c_tx, out_tx_id, has_next);
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub extern "C" fn rs_http2_get_request_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    if let Some(ref request) = tx.request {
        if request.len() > 0 {
            unsafe {
                *len = request.len() as u32;
                *buf = request.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub extern "C" fn rs_http2_get_response_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    if let Some(ref response) = tx.response {
        if response.len() > 0 {
            unsafe {
                *len = response.len() as u32;
                *buf = response.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"http2-rust\0";

#[no_mangle]
pub unsafe extern "C" fn rs_http2_register_parser() {
    let default_port = CString::new("[3000]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: None, // big magic string
        probe_tc: Some(rs_http2_probing_parser_tc),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_http2_state_new,
        state_free: rs_http2_state_free,
        tx_free: rs_http2_state_tx_free,
        parse_ts: rs_http2_parse_request,
        parse_tc: rs_http2_parse_response,
        get_tx_count: rs_http2_state_get_tx_count,
        get_tx: rs_http2_state_get_tx,
        //TODO
        tx_get_comp_st: rs_http2_state_progress_completion_status,
        tx_get_progress: rs_http2_tx_get_alstate_progress,
        get_tx_logged: Some(rs_http2_tx_get_logged),
        set_tx_logged: Some(rs_http2_tx_set_logged),
        get_de_state: rs_http2_tx_get_detect_state,
        set_de_state: rs_http2_tx_set_detect_state,
        get_events: Some(rs_http2_state_get_events),
        get_eventinfo: Some(rs_http2_state_get_event_info),
        get_eventinfo_byid: Some(rs_http2_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: Some(rs_http2_state_get_tx_iterator),
        get_tx_detect_flags: None,
        set_tx_detect_flags: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_HTTP2 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust http2 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for HTTP2.");
    }
}
