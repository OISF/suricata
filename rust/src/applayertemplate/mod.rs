/* Copyright (C) 2018 Open Information Security Foundation
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

use std;
use core::{self, ALPROTO_UNKNOWN, AppProto, Flow};
use libc;
use log::*;
use std::mem::transmute;
use applayer::{self, LoggerFlags};
use parser::*;
use std::ffi::CString;
use nom;

mod parser;

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"template-rust\0";

static mut ALPROTO_TEMPLATE: AppProto = ALPROTO_UNKNOWN;

pub struct TemplateTransaction {
    _tx_id: u64,
    _message: String,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
}

impl TemplateTransaction {
    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for TemplateTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct TemplateState {
    tx_id: u64,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
}

impl TemplateState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, _tx_id: u64) {}

    pub fn get_tx(&mut self, _tx_id: u64) -> Option<&TemplateTransaction> {
        return None;
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        // For simplicity, always extend the buffer and work on it.
        self.request_buffer.extend(input);

        let tmp: Vec<u8>;
        let mut current = {
            tmp = self.request_buffer.split_off(0);
            tmp.as_slice()
        };

        while current.len() > 0 {
            match parser::parse_message(current) {
                nom::IResult::Done(rem, _message) => {
                    current = rem;
                }
                nom::IResult::Incomplete(_) => {
                    self.request_buffer.extend_from_slice(current);
                    break;
                }
                nom::IResult::Error(_) => {
                    return false;
                }
            }
        }

        return true;
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        // For simplicity, always extend the buffer and work on it.
        self.response_buffer.extend(input);

        let mut _tmp: Vec<u8>;
        let mut current = {
            _tmp = self.response_buffer.split_off(0);
            _tmp.as_slice()
        };

        while current.len() > 0 {
            match parser::parse_message(current) {
                nom::IResult::Done(rem, _message) => {
                    current = rem;
                }
                nom::IResult::Incomplete(_) => {
                    self.response_buffer.extend_from_slice(current);
                    break;
                }
                nom::IResult::Error(_) => {
                    return false;
                }
            }
        }

        return true;
    }

    fn tx_iterator(
        &mut self,
        _min_tx_id: u64,
        _state: &mut u64,
    ) -> Option<(&TemplateTransaction, u64, bool)> {
        return None;
    }
}

/// Probe to see if this looks like a chat message.
///
/// For the purposes of example, this will be very simple. Check that
/// the first character (after the leading length) is a basic ascii
/// character.
fn probe(input: &[u8]) -> bool {
    if input.len() > 1 && input[1] >= 32 && input[1] <= 127 {
        return true;
    }
    return false;
}

// C exports.

export_tx_get_detect_state!(
    rs_template_tx_get_detect_state,
    TemplateTransaction
);
export_tx_set_detect_state!(
    rs_template_tx_set_detect_state,
    TemplateTransaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_template_probing_parser(
    _flow: *const Flow,
    input: *const libc::uint8_t,
    input_len: u32,
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return unsafe { ALPROTO_TEMPLATE };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_template_state_new() -> *mut libc::c_void {
    let state = TemplateState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_template_state_free(state: *mut libc::c_void) {
    // Just unbox...
    let _drop: Box<TemplateState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_template_state_tx_free(
    state: *mut libc::c_void,
    tx_id: libc::uint64_t,
) {
    let state = cast_pointer!(state, TemplateState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_template_parse_request(
    _flow: *const Flow,
    state: *mut libc::c_void,
    _pstate: *mut libc::c_void,
    input: *const libc::uint8_t,
    input_len: u32,
    _data: *const libc::c_void,
    _flags: u8,
) -> i8 {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(_pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, TemplateState);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_request(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_template_parse_response(
    _flow: *const Flow,
    state: *mut libc::c_void,
    _pstate: *mut libc::c_void,
    input: *const libc::uint8_t,
    input_len: u32,
    _data: *const libc::c_void,
    _flags: u8,
) -> i8 {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(_pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, TemplateState);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_response(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_template_state_get_tx(
    state: *mut libc::c_void,
    tx_id: libc::uint64_t,
) -> *mut libc::c_void {
    let state = cast_pointer!(state, TemplateState);
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
pub extern "C" fn rs_template_state_get_tx_count(
    state: *mut libc::c_void,
) -> libc::uint64_t {
    let state = cast_pointer!(state, TemplateState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_template_state_progress_completion_status(
    _direction: libc::uint8_t,
) -> libc::c_int {
    // The presence of a transaction means we are complete.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_template_tx_get_alstate_progress(
    _tx: *mut libc::c_void,
    _direction: libc::uint8_t,
) -> libc::c_int {
    // As this is a stateless parser, simply use 1.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_template_tx_get_logged(
    _state: *mut libc::c_void,
    tx: *mut libc::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, TemplateTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_template_tx_set_logged(
    _state: *mut libc::c_void,
    tx: *mut libc::c_void,
    logged: libc::uint32_t,
) {
    let tx = cast_pointer!(tx, TemplateTransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_template_state_get_events(
    state: *mut libc::c_void,
    tx_id: libc::uint64_t,
) -> *mut core::AppLayerDecoderEvents {
    let state = cast_pointer!(state, TemplateState);
    match state.get_tx(tx_id) {
        Some(tx) => tx.events,
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_template_state_get_event_info(
    _event_name: *const libc::c_char,
    _event_id: *mut libc::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> libc::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_template_state_get_tx_iterator(
    _ipproto: libc::uint8_t,
    _alproto: AppProto,
    state: *mut libc::c_void,
    min_tx_id: libc::uint64_t,
    _max_tx_id: libc::uint64_t,
    istate: &mut libc::uint64_t,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, TemplateState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(
                c_tx,
                out_tx_id,
                has_next,
            );
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_register_parser() {
    SCLogDebug!("Registering template parser.");
    let default_port = CString::new("7000").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const libc::c_char,
        default_port: default_port.as_ptr(),
        ipproto: libc::IPPROTO_TCP,
        probe_ts: rs_template_probing_parser,
        probe_tc: rs_template_probing_parser,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_template_state_new,
        state_free: rs_template_state_free,
        tx_free: rs_template_state_tx_free,
        parse_ts: rs_template_parse_request,
        parse_tc: rs_template_parse_response,
        get_tx_count: rs_template_state_get_tx_count,
        get_tx: rs_template_state_get_tx,
        tx_get_comp_st: rs_template_state_progress_completion_status,
        tx_get_progress: rs_template_tx_get_alstate_progress,
        get_tx_logged: Some(rs_template_tx_get_logged),
        set_tx_logged: Some(rs_template_tx_set_logged),
        get_de_state: rs_template_tx_get_detect_state,
        set_de_state: rs_template_tx_set_detect_state,
        get_events: Some(rs_template_state_get_events),
        get_eventinfo: Some(rs_template_state_get_event_info),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: Some(rs_template_state_get_tx_iterator),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_TEMPLATE = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for TEMPLATE.");
    }
}
