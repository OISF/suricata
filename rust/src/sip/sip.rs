/* Copyright (C) 2019-2020 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

extern crate nom;

use crate::applayer::{self, *};
use crate::core;
use crate::core::{sc_detect_engine_state_free, AppProto, Flow, ALPROTO_UNKNOWN};
use crate::log::*;
use crate::sip::parser::*;
use std;
use std::ffi::{CStr, CString};

#[repr(u32)]
pub enum SIPEvent {
    IncompleteData = 0,
    InvalidData,
}

impl SIPEvent {
    fn from_i32(value: i32) -> Option<SIPEvent> {
        match value {
            0 => Some(SIPEvent::IncompleteData),
            1 => Some(SIPEvent::InvalidData),
            _ => None,
        }
    }
}

pub struct SIPState {
    transactions: Vec<SIPTransaction>,
    tx_id: u64,
}

pub struct SIPTransaction {
    id: u64,
    pub request: Option<Request>,
    pub response: Option<Response>,
    pub request_line: Option<String>,
    pub response_line: Option<String>,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    logged: applayer::LoggerFlags,
}

impl SIPState {
    pub fn new() -> SIPState {
        SIPState {
            transactions: Vec::new(),
            tx_id: 0,
        }
    }

    pub fn free(&mut self) {
        self.transactions.clear();
    }

    fn new_tx(&mut self) -> SIPTransaction {
        self.tx_id += 1;
        SIPTransaction::new(self.tx_id)
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&SIPTransaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self
            .transactions
            .iter()
            .position(|ref tx| tx.id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    fn set_event(&mut self, event: SIPEvent) {
        if let Some(tx) = self.transactions.last_mut() {
            let ev = event as u8;
            core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
        }
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        match sip_parse_request(input) {
            Ok((_, request)) => {
                let mut tx = self.new_tx();
                tx.request = Some(request);
                if let Ok((_, req_line)) = sip_take_line(input) {
                    tx.request_line = req_line;
                }
                self.transactions.push(tx);
                return true;
            }
            Err(nom::Err::Incomplete(_)) => {
                self.set_event(SIPEvent::IncompleteData);
                return false;
            }
            Err(_) => {
                self.set_event(SIPEvent::InvalidData);
                return false;
            }
        }
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        match sip_parse_response(input) {
            Ok((_, response)) => {
                let mut tx = self.new_tx();
                tx.response = Some(response);
                if let Ok((_, resp_line)) = sip_take_line(input) {
                    tx.response_line = resp_line;
                }
                self.transactions.push(tx);
                return true;
            }
            Err(nom::Err::Incomplete(_)) => {
                self.set_event(SIPEvent::IncompleteData);
                return false;
            }
            Err(_) => {
                self.set_event(SIPEvent::InvalidData);
                return false;
            }
        }
    }
}

impl SIPTransaction {
    pub fn new(id: u64) -> SIPTransaction {
        SIPTransaction {
            id: id,
            de_state: None,
            request: None,
            response: None,
            request_line: None,
            response_line: None,
            events: std::ptr::null_mut(),
            logged: applayer::LoggerFlags::new(),
        }
    }
}

impl Drop for SIPTransaction {
    fn drop(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            sc_detect_engine_state_free(state);
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_sip_state_new() -> *mut std::os::raw::c_void {
    let state = SIPState::new();
    let boxed = Box::new(state);
    return unsafe { std::mem::transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_sip_state_free(state: *mut std::os::raw::c_void) {
    let mut state: Box<SIPState> = unsafe { std::mem::transmute(state) };
    state.free();
}

#[no_mangle]
pub extern "C" fn rs_sip_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, SIPState);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => unsafe { std::mem::transmute(tx) },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_sip_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, SIPState);
    state.tx_id
}

#[no_mangle]
pub extern "C" fn rs_sip_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, SIPState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_sip_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_sip_tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    1
}

#[no_mangle]
pub extern "C" fn rs_sip_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, SIPTransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_sip_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, SIPTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_sip_state_set_tx_detect_state(
    tx: *mut std::os::raw::c_void,
    de_state: &mut core::DetectEngineState,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SIPTransaction);
    tx.de_state = Some(de_state);
    0
}

#[no_mangle]
pub extern "C" fn rs_sip_state_get_tx_detect_state(
    tx: *mut std::os::raw::c_void,
) -> *mut core::DetectEngineState {
    let tx = cast_pointer!(tx, SIPTransaction);
    match tx.de_state {
        Some(ds) => ds,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_sip_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, SIPTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_sip_state_get_event_info(
    event_name: *const std::os::raw::c_char,
    event_id: *mut std::os::raw::c_int,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if event_name == std::ptr::null() {
        return -1;
    }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "incomplete_data" => SIPEvent::IncompleteData as i32,
                "invalid_data" => SIPEvent::InvalidData as i32,
                _ => -1, // unknown event
            }
        }
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe {
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}

#[no_mangle]
pub extern "C" fn rs_sip_state_get_event_info_by_id(
    event_id: std::os::raw::c_int,
    event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = SIPEvent::from_i32(event_id as i32) {
        let estr = match e {
            SIPEvent::IncompleteData => "incomplete_data\0",
            SIPEvent::InvalidData => "invalid_data\0",
        };
        unsafe {
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}

static mut ALPROTO_SIP: AppProto = ALPROTO_UNKNOWN;

#[no_mangle]
pub extern "C" fn rs_sip_probing_parser_ts(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    if sip_parse_request(buf).is_ok() {
        return unsafe { ALPROTO_SIP };
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_sip_probing_parser_tc(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    if sip_parse_response(buf).is_ok() {
        return unsafe { ALPROTO_SIP };
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_sip_parse_request(
    _flow: *const core::Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let buf = build_slice!(input, input_len as usize);
    let state = cast_pointer!(state, SIPState);
    state.parse_request(buf).into()
}

#[no_mangle]
pub extern "C" fn rs_sip_parse_response(
    _flow: *const core::Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let buf = build_slice!(input, input_len as usize);
    let state = cast_pointer!(state, SIPState);
    state.parse_response(buf).into()
}

const PARSER_NAME: &'static [u8] = b"sip\0";

#[no_mangle]
pub unsafe extern "C" fn rs_sip_register_parser() {
    let default_port = CString::new("5060").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: core::IPPROTO_UDP,
        probe_ts: Some(rs_sip_probing_parser_ts),
        probe_tc: Some(rs_sip_probing_parser_tc),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_sip_state_new,
        state_free: rs_sip_state_free,
        tx_free: rs_sip_state_tx_free,
        parse_ts: rs_sip_parse_request,
        parse_tc: rs_sip_parse_response,
        get_tx_count: rs_sip_state_get_tx_count,
        get_tx: rs_sip_state_get_tx,
        tx_get_comp_st: rs_sip_state_progress_completion_status,
        tx_get_progress: rs_sip_tx_get_alstate_progress,
        get_tx_logged: Some(rs_sip_tx_get_logged),
        set_tx_logged: Some(rs_sip_tx_set_logged),
        get_de_state: rs_sip_state_get_tx_detect_state,
        set_de_state: rs_sip_state_set_tx_detect_state,
        get_events: Some(rs_sip_state_get_events),
        get_eventinfo: Some(rs_sip_state_get_event_info),
        get_eventinfo_byid: Some(rs_sip_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: None,
        get_tx_detect_flags: None,
        set_tx_detect_flags: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detecter and parser disabled for SIP/UDP.");
    }
}
