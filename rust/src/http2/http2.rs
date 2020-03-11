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
use std::ffi::{CStr, CString};
use std::mem::transmute;

static mut ALPROTO_HTTP2: AppProto = ALPROTO_UNKNOWN;

const HTTP2_DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq)]
pub enum HTTP2ConnectionState {
    Http2StateInit = 0,
    Http2StateMagicDone = 1,
}

pub struct HTTP2Transaction {
    tx_id: u64,
    pub ftype: Option<parser::HTTP2FrameType>,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
}

impl HTTP2Transaction {
    pub fn new() -> HTTP2Transaction {
        HTTP2Transaction {
            tx_id: 0,
            ftype: None,
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

//TODO rules file
#[repr(u32)]
pub enum HTTP2Event {
    InvalidFrameHeader = 0,
    InvalidClientMagic,
}

impl HTTP2Event {
    fn from_i32(value: i32) -> Option<HTTP2Event> {
        match value {
            0 => Some(HTTP2Event::InvalidFrameHeader),
            1 => Some(HTTP2Event::InvalidClientMagic),
            _ => None,
        }
    }
}

pub struct HTTP2State {
    tx_id: u64,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    request_frame_size: u32,
    response_frame_size: u32,
    transactions: Vec<HTTP2Transaction>,
    progress: HTTP2ConnectionState,
}

impl HTTP2State {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            request_frame_size: 0,
            response_frame_size: 0,
            transactions: Vec::new(),
            progress: HTTP2ConnectionState::Http2StateInit,
        }
    }

    fn set_event(&mut self, event: HTTP2Event) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }
        let tx = &mut self.transactions[len - 1];
        let ev = event as u8;
        core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
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

    fn parse_ts(&mut self, input: &[u8]) -> bool {
        let mut toparse = input;
        //first consume frame bytes
        if self.request_frame_size > 0 {
            let ilen = input.len() as u32;
            if self.request_frame_size >= ilen {
                self.request_frame_size -= ilen;
                return true;
            } else {
                let start = self.request_frame_size as usize;
                toparse = &toparse[start..];
                self.request_frame_size = 0;
            }
        }
        //second extend buffer if present
        if self.request_buffer.len() > 0 {
            self.request_buffer.extend(toparse);
            //parse one header locally as we borrow self and self.request_buffer
            match parser::http2_parse_frame_header(&self.request_buffer) {
                Ok((rem, head)) => {
                    let hl = head.length as usize;
                    let rlu = rem.len();
                    //TODO handle transactions the right way
                    let mut tx = self.new_tx();
                    tx.ftype = Some(head.ftype);
                    self.transactions.push(tx);

                    if rlu < hl {
                        let rl = rlu as u32;
                        self.request_frame_size = head.length - rl;
                        return true;
                    } else {
                        toparse = &toparse[toparse.len() - rlu - hl..];
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    return true;
                }
                Err(_) => {
                    self.set_event(HTTP2Event::InvalidFrameHeader);
                    return false;
                }
            }
        }
        //then parse all we can
        while toparse.len() > 0 {
            match parser::http2_parse_frame_header(toparse) {
                Ok((rem, head)) => {
//TODO debug not logged SCLogNotice!("rs_http2_parse_ts http2_parse_frame_header ok");
                    let mut tx = self.new_tx();
                    tx.ftype = Some(head.ftype);
                    self.transactions.push(tx);

                    let hl = head.length as usize;
                    if rem.len() < hl {
                        let rl = rem.len() as u32;
                        self.request_frame_size = head.length - rl;
                        return true;
                    } else {
                        toparse = &rem[rem.len() - hl..];
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    self.request_buffer.extend(toparse);
                    return true;
                }
                Err(_) => {
                    self.set_event(HTTP2Event::InvalidFrameHeader);
                    return false;
                }
            }
        }
        return true;
    }

    fn parse_tc(&mut self, input: &[u8]) -> bool {
        let mut toparse = input;
        //first consume frame bytes
        if self.response_frame_size > 0 {
            let ilen = input.len() as u32;
            if self.response_frame_size >= ilen {
                self.response_frame_size -= ilen;
                return true;
            } else {
                let start = self.response_frame_size as usize;
                toparse = &toparse[start..];
                self.response_frame_size = 0;
            }
        }
        //second extend buffer if present
        if self.response_buffer.len() > 0 {
            self.response_buffer.extend(toparse);
            //parse one header locally as we borrow self and self.response_buffer
            match parser::http2_parse_frame_header(&self.response_buffer) {
                Ok((rem, head)) => {
                    let hl = head.length as usize;
                    let rlu = rem.len();

                    let mut tx = self.new_tx();
                    tx.ftype = Some(head.ftype);
                    self.transactions.push(tx);

                    //TODO parse deeper based on frame type
                    if rlu < hl {
                        let rl = rlu as u32;
                        self.response_frame_size = head.length - rl;
                        return true;
                    } else {
                        toparse = &toparse[toparse.len() - rlu - hl..];
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    return true;
                }
                Err(_) => {
                    self.set_event(HTTP2Event::InvalidFrameHeader);
                    return false;
                }
            }
        }
        //then parse all we can
        while toparse.len() > 0 {
            match parser::http2_parse_frame_header(toparse) {
                Ok((rem, head)) => {
                    let mut tx = self.new_tx();
                    tx.ftype = Some(head.ftype);
                    self.transactions.push(tx);

                    //TODO parse deeper based on frame type
                    let hl = head.length as usize;
                    if rem.len() < hl {
                        let rl = rem.len() as u32;
                        self.response_frame_size = head.length - rl;
                        return true;
                    } else {
                        toparse = &rem[rem.len() - hl..];
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    self.response_buffer.extend(toparse);
                    return true;
                }
                Err(_) => {
                    self.set_event(HTTP2Event::InvalidFrameHeader);
                    return false;
                }
            }
        }
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

//TODO connection upgrade from HTTP1
/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_http2_probing_parser_tc(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
//TODO debug not called SCLogNotice!("rs_http2_probing_parser_tc");
    if input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        match parser::http2_parse_frame_header(slice) {
            Ok((_, header)) => {
                if header.reserved != 0
                    || header.length > HTTP2_DEFAULT_MAX_FRAME_SIZE
                    || header.flags & 0xFE != 0
                    || header.ftype != parser::HTTP2FrameType::SETTINGS
                {
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
pub extern "C" fn rs_http2_parse_ts(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let state = cast_pointer!(state, HTTP2State);
    let mut buf = build_slice!(input, input_len as usize);

    if state.progress < HTTP2ConnectionState::Http2StateMagicDone {
        //skip magic lol
        if state.request_buffer.len() > 0 {
            state.request_buffer.extend(buf);
            if state.request_buffer.len() >= 24 {
                //skip magic
                match std::str::from_utf8(&state.request_buffer[..24]) {
                    Ok("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") => {}
                    Ok(&_) => {
                        state.set_event(HTTP2Event::InvalidClientMagic);
                    }
                    Err(_) => {
                        return -1;
                    }
                }
                buf = &buf[state.request_buffer.len() - buf.len() - 24..];
                state.request_buffer.clear()
            } else {
                //still more buffer
                return 1;
            }
        } else {
            if buf.len() >= 24 {
                //skip magic
                match std::str::from_utf8(&buf[..24]) {
                    Ok("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") => {}
                    Ok(&_) => {
                        state.set_event(HTTP2Event::InvalidClientMagic);
                    }
                    Err(_) => {
                        return -1;
                    }
                }
                buf = &buf[24..];
            } else {
                //need to bufferize content
                state.request_buffer.extend(buf);
                return 1;
            }
        }
        state.progress = HTTP2ConnectionState::Http2StateMagicDone;
    }

    if state.parse_ts(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_tc(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let state = cast_pointer!(state, HTTP2State);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_tc(buf) {
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
    if tx.ftype.is_some() {
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
                "invalid_frame_header" => HTTP2Event::InvalidFrameHeader as i32,
                "invalid_client_magic" => HTTP2Event::InvalidClientMagic as i32,
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
pub extern "C" fn rs_http2_state_get_event_info_by_id(
    event_id: std::os::raw::c_int,
    event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = HTTP2Event::from_i32(event_id as i32) {
        let estr = match e {
            HTTP2Event::InvalidFrameHeader => "invalid_frame_header\0",
            HTTP2Event::InvalidClientMagic => "invalid_client_magic\0",
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

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"http2\0";

#[no_mangle]
pub unsafe extern "C" fn rs_http2_register_parser() {
    let default_port = CString::new("[3000]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: None, // big magic string should be enough
        probe_tc: Some(rs_http2_probing_parser_tc),
        min_depth: 0,  // frame header size
        max_depth: 24, // client magic size
        state_new: rs_http2_state_new,
        state_free: rs_http2_state_free,
        tx_free: rs_http2_state_tx_free,
        parse_ts: rs_http2_parse_ts,
        parse_tc: rs_http2_parse_tc,
        get_tx_count: rs_http2_state_get_tx_count,
        get_tx: rs_http2_state_get_tx,
        //TODO progress completion
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
