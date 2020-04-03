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
use crate::applayer::{self, *};
use crate::core::{self, AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::log::*;
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

const HTTP2_FRAME_HEADER_LEN: usize = 9;
const HTTP2_MAGIC_LEN: usize = 24;
const HTTP2_FRAME_GOAWAY_LEN: usize = 4;
const HTTP2_FRAME_RSTSTREAM_LEN: usize = 4;
const HTTP2_FRAME_SETTINGS_LEN: usize = 6;
const HTTP2_FRAME_PRIORITY_LEN: usize = 1;
const HTTP2_FRAME_WINDOWUPDATE_LEN: usize = 4;

pub enum HTTP2FrameTypeData {
    //TODO PUSH_PROMISE
    //TODO DATA
    //TODO HEADERS
    //TODO CONTINATION
    PRIORITY(parser::HTTP2FramePriority),
    GOAWAY(parser::HTTP2FrameGoAway),
    RSTSTREAM(parser::HTTP2FrameRstStream),
    SETTINGS(parser::HTTP2FrameSettings),
    WINDOWUPDATE(parser::HTTP2FrameWindowUpdate),
}

pub struct HTTP2Transaction {
    tx_id: u64,
    pub ftype: Option<parser::HTTP2FrameType>,

    /// Command specific data
    pub type_data: Option<HTTP2FrameTypeData>,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    detect_flags: TxDetectFlags,
    events: *mut core::AppLayerDecoderEvents,
}

impl HTTP2Transaction {
    pub fn new() -> HTTP2Transaction {
        HTTP2Transaction {
            tx_id: 0,
            ftype: None,
            type_data: None,
            logged: LoggerFlags::new(),
            de_state: None,
            detect_flags: TxDetectFlags::default(),
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
    InvalidFrameData,
}

impl HTTP2Event {
    fn from_i32(value: i32) -> Option<HTTP2Event> {
        match value {
            0 => Some(HTTP2Event::InvalidFrameHeader),
            1 => Some(HTTP2Event::InvalidClientMagic),
            2 => Some(HTTP2Event::InvalidFrameData),
            _ => None,
        }
    }
}

pub struct HTTP2State {
    tx_id: u64,
    request_frame_size: u32,
    response_frame_size: u32,
    transactions: Vec<HTTP2Transaction>,
    progress: HTTP2ConnectionState,
}

impl HTTP2State {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_frame_size: 0,
            response_frame_size: 0,
            transactions: Vec::new(),
            progress: HTTP2ConnectionState::Http2StateInit,
        }
    }

    pub fn free(&mut self) {
        self.transactions.clear();
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

    fn parse_ts(&mut self, mut input: &[u8]) -> AppLayerResult {
        //first consume frame bytes
        let il = input.len();
        if self.request_frame_size > 0 {
            let ilen = input.len() as u32;
            if self.request_frame_size >= ilen {
                self.request_frame_size -= ilen;
                return AppLayerResult::ok();
            } else {
                let start = self.request_frame_size as usize;
                input = &input[start..];
                self.request_frame_size = 0;
            }
        }

        //then parse all we can
        while input.len() > 0 {
            match parser::http2_parse_frame_header(input) {
                Ok((rem, head)) => {
                    //TODO handle transactions the right way
                    let mut tx = self.new_tx();
                    tx.ftype = Some(head.ftype);
                    match head.ftype {
                        parser::HTTP2FrameType::GOAWAY => {
                            match parser::http2_parse_frame_goaway(rem) {
                                Ok((_, goaway)) => {
                                    tx.type_data = Some(HTTP2FrameTypeData::GOAWAY(goaway));
                                }
                                // do not trust nom incomplete value
                                Err(nom::Err::Incomplete(_)) => {
                                    return AppLayerResult::incomplete(
                                        (il - input.len()) as u32,
                                        (HTTP2_FRAME_HEADER_LEN + HTTP2_FRAME_GOAWAY_LEN) as u32,
                                    );
                                }
                                Err(_) => {
                                    self.set_event(HTTP2Event::InvalidFrameData);
                                }
                            }
                        }
                        parser::HTTP2FrameType::SETTINGS => {
                            match parser::http2_parse_frame_settings(rem) {
                                Ok((_, set)) => {
                                    tx.type_data = Some(HTTP2FrameTypeData::SETTINGS(set));
                                }
                                Err(nom::Err::Incomplete(_)) => {
                                    return AppLayerResult::incomplete(
                                        (il - input.len()) as u32,
                                        (HTTP2_FRAME_HEADER_LEN + HTTP2_FRAME_SETTINGS_LEN) as u32,
                                    );
                                }
                                Err(_) => {
                                    self.set_event(HTTP2Event::InvalidFrameData);
                                }
                            }
                        }
                        parser::HTTP2FrameType::RSTSTREAM => {
                            match parser::http2_parse_frame_rststream(rem) {
                                Ok((_, rst)) => {
                                    tx.type_data = Some(HTTP2FrameTypeData::RSTSTREAM(rst));
                                }
                                Err(nom::Err::Incomplete(_)) => {
                                    return AppLayerResult::incomplete(
                                        (il - input.len()) as u32,
                                        (HTTP2_FRAME_HEADER_LEN + HTTP2_FRAME_RSTSTREAM_LEN) as u32,
                                    );
                                }
                                Err(_) => {
                                    self.set_event(HTTP2Event::InvalidFrameData);
                                }
                            }
                        }
                        parser::HTTP2FrameType::PRIORITY => {
                            match parser::http2_parse_frame_priority(rem) {
                                Ok((_, priority)) => {
                                    tx.type_data = Some(HTTP2FrameTypeData::PRIORITY(priority));
                                }
                                Err(nom::Err::Incomplete(_)) => {
                                    return AppLayerResult::incomplete(
                                        (il - input.len()) as u32,
                                        (HTTP2_FRAME_HEADER_LEN + HTTP2_FRAME_PRIORITY_LEN) as u32,
                                    );
                                }
                                Err(_) => {
                                    self.set_event(HTTP2Event::InvalidFrameData);
                                }
                            }
                        }
                        parser::HTTP2FrameType::WINDOWUPDATE => {
                            match parser::http2_parse_frame_windowupdate(rem) {
                                Ok((_, wu)) => {
                                    tx.type_data = Some(HTTP2FrameTypeData::WINDOWUPDATE(wu));
                                }
                                Err(nom::Err::Incomplete(_)) => {
                                    return AppLayerResult::incomplete(
                                        (il - input.len()) as u32,
                                        (HTTP2_FRAME_HEADER_LEN + HTTP2_FRAME_WINDOWUPDATE_LEN) as u32,
                                    );
                                }
                                Err(_) => {
                                    self.set_event(HTTP2Event::InvalidFrameData);
                                }
                            }
                        }
                        //ignore ping case with opaque u64
                        _ => {}
                    }
                    self.transactions.push(tx);

                    let hl = head.length as usize;
                    if rem.len() < hl {
                        let rl = rem.len() as u32;
                        self.request_frame_size = head.length - rl;
                        return AppLayerResult::ok();
                    } else {
                        input = &rem[hl..];
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    //we may have consumed data from previous records
                    if input.len() < HTTP2_FRAME_HEADER_LEN {
                        return AppLayerResult::incomplete(
                            (il - input.len()) as u32,
                            HTTP2_FRAME_HEADER_LEN as u32,
                        );
                    } else {
                        panic!("HTTP2 invalid length frame header");
                    }
                }
                Err(_) => {
                    self.set_event(HTTP2Event::InvalidFrameHeader);
                    return AppLayerResult::err();
                }
            }
        }
        return AppLayerResult::ok();
    }

    fn parse_tc(&mut self, mut input: &[u8]) -> AppLayerResult {
        //first consume frame bytes
        let il = input.len();
        if self.response_frame_size > 0 {
            let ilen = input.len() as u32;
            if self.response_frame_size >= ilen {
                self.response_frame_size -= ilen;
                return AppLayerResult::ok();
            } else {
                let start = self.response_frame_size as usize;
                input = &input[start..];
                self.response_frame_size = 0;
            }
        }
        //then parse all we can
        while input.len() > 0 {
            match parser::http2_parse_frame_header(input) {
                Ok((rem, head)) => {
                    let mut tx = self.new_tx();
                    tx.ftype = Some(head.ftype);
                    self.transactions.push(tx);

                    //TODO parse frame types as in request once transactions are well handled
                    let hl = head.length as usize;
                    if rem.len() < hl {
                        let rl = rem.len() as u32;
                        self.response_frame_size = head.length - rl;
                        return AppLayerResult::ok();
                    } else {
                        input = &rem[hl..];
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    //we may have consumed data from previous records
                    if input.len() < HTTP2_FRAME_HEADER_LEN {
                        return AppLayerResult::incomplete(
                            (il - input.len()) as u32,
                            HTTP2_FRAME_HEADER_LEN as u32,
                        );
                    } else {
                        panic!("HTTP2 invalid length frame header");
                    }
                }
                Err(_) => {
                    self.set_event(HTTP2Event::InvalidFrameHeader);
                    return AppLayerResult::err();
                }
            }
        }
        return AppLayerResult::ok();
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

export_tx_detect_flags_set!(rs_http2_set_tx_detect_flags, HTTP2Transaction);
export_tx_detect_flags_get!(rs_http2_get_tx_detect_flags, HTTP2Transaction);

//TODO connection upgrade from HTTP1 cf SMTP STARTTLS
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
    let mut state: Box<HTTP2State> = unsafe { transmute(state) };
    state.free();
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
) -> AppLayerResult {
    let state = cast_pointer!(state, HTTP2State);
    let mut buf = build_slice!(input, input_len as usize);

    if state.progress < HTTP2ConnectionState::Http2StateMagicDone {
        //skip magic
        if buf.len() >= HTTP2_MAGIC_LEN {
            //skip magic
            match std::str::from_utf8(&buf[..HTTP2_MAGIC_LEN]) {
                Ok("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") => {
                    buf = &buf[HTTP2_MAGIC_LEN..];
                }
                Ok(&_) => {
                    state.set_event(HTTP2Event::InvalidClientMagic);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
            state.progress = HTTP2ConnectionState::Http2StateMagicDone;
        } else {
            //still more buffer
            return AppLayerResult::incomplete(0 as u32, HTTP2_MAGIC_LEN as u32);
        }
    }

    return state.parse_ts(buf);
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
) -> AppLayerResult {
    let state = cast_pointer!(state, HTTP2State);
    let buf = build_slice!(input, input_len as usize);
    return state.parse_tc(buf);
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
                "invalid_frame_data" => HTTP2Event::InvalidFrameData as i32,
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
            HTTP2Event::InvalidFrameData => "invalid_frame_data\0",
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
    //TODO default port
    let default_port = CString::new("[3000]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: None, // big magic string should be enough
        probe_tc: Some(rs_http2_probing_parser_tc),
        min_depth: HTTP2_FRAME_HEADER_LEN as u16,
        max_depth: HTTP2_MAGIC_LEN as u16,
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
        get_tx_detect_flags: Some(rs_http2_get_tx_detect_flags),
        set_tx_detect_flags: Some(rs_http2_set_tx_detect_flags),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_HTTP2 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust http2 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for HTTP2.");
    }
}
