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

use super::files::*;
use super::parser;
use crate::applayer::{self, *};
use crate::core::{
    self, AppProto, Flow, SuricataFileContext, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP,
    STREAM_TOCLIENT, STREAM_TOSERVER,
};
use crate::filecontainer::*;
use crate::filetracker::*;
use crate::log::*;
use nom;
use std;
use std::ffi::{CStr, CString};
use std::mem::transmute;

static mut ALPROTO_HTTP2: AppProto = ALPROTO_UNKNOWN;

const HTTP2_DEFAULT_MAX_FRAME_SIZE: u32 = 16384;
const HTTP2_MAX_HANDLED_FRAME_SIZE: usize = 65536;

//TODOask why option ?
pub static mut SURICATA_HTTP2_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

#[no_mangle]
pub extern "C" fn rs_http2_init(context: &'static mut SuricataFileContext) {
    unsafe {
        SURICATA_HTTP2_FILE_CONFIG = Some(context);
    }
}

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
const HTTP2_FRAME_PRIORITY_LEN: usize = 1;
const HTTP2_FRAME_WINDOWUPDATE_LEN: usize = 4;

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub enum HTTP2FrameUnhandledReason {
    UnknownType = 0,
    TooLong = 1,
    ParsingError = 2,
    Incomplete = 3,
}

#[derive(Debug)]
pub struct HTTP2FrameUnhandled {
    pub reason: HTTP2FrameUnhandledReason,
}

pub enum HTTP2FrameTypeData {
    PRIORITY(parser::HTTP2FramePriority),
    GOAWAY(parser::HTTP2FrameGoAway),
    RSTSTREAM(parser::HTTP2FrameRstStream),
    SETTINGS(Vec<parser::HTTP2FrameSettings>),
    WINDOWUPDATE(parser::HTTP2FrameWindowUpdate),
    HEADERS(parser::HTTP2FrameHeaders),
    PUSHPROMISE(parser::HTTP2FramePushPromise),
    CONTINUATION(parser::HTTP2FrameContinuation),
    PING,
    DATA,
    //not a defined frame
    UNHANDLED(HTTP2FrameUnhandled),
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq)]
pub enum HTTP2TransactionState {
    Http2StreamStateIdle = 0,
    Http2StreamStateOpen = 1,
    Http2StreamStateClosed = 2,
    Http2StreamStateGlobal = 3,
}

pub struct HTTP2Frame {
    pub header: parser::HTTP2FrameHeader,
    pub data: HTTP2FrameTypeData,
}

pub struct HTTP2Transaction {
    tx_id: u64,
    stream_id: u32,
    state_tc: HTTP2TransactionState,
    state_ts: HTTP2TransactionState,

    pub frames_tc: Vec<HTTP2Frame>,
    pub frames_ts: Vec<HTTP2Frame>,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    detect_flags: TxDetectFlags,
    events: *mut core::AppLayerDecoderEvents,
    ft: FileTransferTracker,
}

impl HTTP2Transaction {
    pub fn new() -> HTTP2Transaction {
        HTTP2Transaction {
            tx_id: 0,
            stream_id: 0,
            state_tc: HTTP2TransactionState::Http2StreamStateIdle,
            state_ts: HTTP2TransactionState::Http2StreamStateIdle,
            frames_tc: Vec::new(),
            frames_ts: Vec::new(),
            logged: LoggerFlags::new(),
            de_state: None,
            detect_flags: TxDetectFlags::default(),
            events: std::ptr::null_mut(),
            ft: FileTransferTracker::new(),
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

//TODOnext rules file
#[repr(u32)]
pub enum HTTP2Event {
    InvalidFrameHeader = 0,
    InvalidClientMagic,
    InvalidFrameData,
    InvalidHeader,
    InvalidFrameLength,
    ExtraHeaderData,
    LongFrameData,
}

impl HTTP2Event {
    fn from_i32(value: i32) -> Option<HTTP2Event> {
        match value {
            0 => Some(HTTP2Event::InvalidFrameHeader),
            1 => Some(HTTP2Event::InvalidClientMagic),
            2 => Some(HTTP2Event::InvalidFrameData),
            3 => Some(HTTP2Event::InvalidHeader),
            4 => Some(HTTP2Event::InvalidFrameLength),
            5 => Some(HTTP2Event::ExtraHeaderData),
            6 => Some(HTTP2Event::LongFrameData),
            _ => None,
        }
    }
}

pub struct HTTP2State {
    tx_id: u64,
    request_frame_size: u32,
    response_frame_size: u32,
    dynamic_headers_ts: Vec<parser::HTTP2FrameHeaderBlock>,
    dynamic_headers_tc: Vec<parser::HTTP2FrameHeaderBlock>,
    transactions: Vec<HTTP2Transaction>,
    progress: HTTP2ConnectionState,
    pub files: HTTP2Files,
}

impl HTTP2State {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_frame_size: 0,
            response_frame_size: 0,
            dynamic_headers_ts: Vec::with_capacity(255 - parser::HTTP2_STATIC_HEADERS_NUMBER),
            dynamic_headers_tc: Vec::with_capacity(255 - parser::HTTP2_STATIC_HEADERS_NUMBER),
            transactions: Vec::new(),
            progress: HTTP2ConnectionState::Http2StateInit,
            files: HTTP2Files::new(),
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

    fn parse_frame_data(
        &mut self, ftype: u8, input: &[u8], _complete: bool, hflags: u8,
    ) -> HTTP2FrameTypeData {
        //TODO5 use complete ? and HTTP2FrameUnhandledReason::TooLong
        match num::FromPrimitive::from_u8(ftype) {
            Some(parser::HTTP2FrameType::GOAWAY) => {
                if input.len() < HTTP2_FRAME_GOAWAY_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                } else {
                    match parser::http2_parse_frame_goaway(input) {
                        Ok((_, goaway)) => {
                            //TODOask set an event on remaining data
                            return HTTP2FrameTypeData::GOAWAY(goaway);
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::SETTINGS) => {
                match parser::http2_parse_frame_settings(input) {
                    Ok((_, set)) => {
                        return HTTP2FrameTypeData::SETTINGS(set);
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::RSTSTREAM) => {
                if input.len() != HTTP2_FRAME_RSTSTREAM_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                } else {
                    match parser::http2_parse_frame_rststream(input) {
                        Ok((_, rst)) => {
                            return HTTP2FrameTypeData::RSTSTREAM(rst);
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::PRIORITY) => {
                if input.len() != HTTP2_FRAME_PRIORITY_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                } else {
                    match parser::http2_parse_frame_priority(input) {
                        Ok((_, priority)) => {
                            return HTTP2FrameTypeData::PRIORITY(priority);
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::WINDOWUPDATE) => {
                if input.len() != HTTP2_FRAME_WINDOWUPDATE_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                } else {
                    match parser::http2_parse_frame_windowupdate(input) {
                        Ok((_, wu)) => {
                            return HTTP2FrameTypeData::WINDOWUPDATE(wu);
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::PUSHPROMISE) => {
                match parser::http2_parse_frame_push_promise(
                    input,
                    hflags,
                    &mut self.dynamic_headers_ts,
                ) {
                    Ok((_, hs)) => {
                        for i in 0..hs.blocks.len() {
                            if hs.blocks[i].error
                                >= parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeError
                            {
                                self.set_event(HTTP2Event::InvalidHeader);
                            }
                        }
                        //TODO6tx right transaction wih promised headers
                        return HTTP2FrameTypeData::PUSHPROMISE(hs);
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::DATA) => {
                //TODOask use streaming buffer directly
                /*TODO6tx match unsafe { SURICATA_HTTP2_FILE_CONFIG } {
                    Some(sfcm) => {
                        let xid: u32 = tx.tx_id as u32;
                        tx.ft.new_chunk(
                            sfcm,
                            &mut self.files.files_ts,
                            self.files.flags_ts,
                            b"",
                            input,
                            tx.ft.tracked, //offset = append
                            input.len() as u32,
                            0,
                            hflags & parser::HTTP2_FLAG_HEADER_END_STREAM != 0,
                            &xid,
                        );
                    }
                    None => panic!("BUG"),
                }*/
                return HTTP2FrameTypeData::DATA;
            }
            Some(parser::HTTP2FrameType::CONTINUATION) => {
                match parser::http2_parse_frame_continuation(input, &mut self.dynamic_headers_ts) {
                    Ok((_, hs)) => {
                        for i in 0..hs.blocks.len() {
                            if hs.blocks[i].error
                                >= parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeError
                            {
                                self.set_event(HTTP2Event::InvalidHeader);
                            }
                        }
                        //TODO6tx right transaction wih continued headers
                        return HTTP2FrameTypeData::CONTINUATION(hs);
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::HEADERS) => {
                match parser::http2_parse_frame_headers(input, hflags, &mut self.dynamic_headers_ts)
                {
                    Ok((hrem, hs)) => {
                        for i in 0..hs.blocks.len() {
                            if hs.blocks[i].error
                                >= parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeError
                            {
                                self.set_event(HTTP2Event::InvalidHeader);
                            }
                        }
                        if hrem.len() > 0 {
                            SCLogNotice!("Remaining data for HTTP2 headers");
                            self.set_event(HTTP2Event::ExtraHeaderData);
                        }
                        return HTTP2FrameTypeData::HEADERS(hs);
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::PING) => {
                return HTTP2FrameTypeData::PING;
            }
            _ => {
                return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                    reason: HTTP2FrameUnhandledReason::UnknownType,
                });
            }
        }
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
                    //TODO6tx handle transactions the right way
                    let mut tx = self.new_tx();
                    let hl = head.length as usize;

                    //we check for completeness first
                    if rem.len() < hl {
                        //but limit ourselves so as not to exhaust memory
                        if hl < HTTP2_MAX_HANDLED_FRAME_SIZE {
                            return AppLayerResult::incomplete(
                                (il - input.len()) as u32,
                                (HTTP2_FRAME_HEADER_LEN + hl) as u32,
                            );
                        } else {
                            self.set_event(HTTP2Event::LongFrameData);
                            self.request_frame_size = head.length - (rem.len() as u32);
                        }
                    }

                    //get a safe length for the buffer
                    let (hlsafe, complete) = if rem.len() < hl {
                        (rem.len(), false)
                    } else {
                        (hl, true)
                    };

                    let txdata =
                        self.parse_frame_data(head.ftype, &rem[..hlsafe], complete, head.flags);
                    tx.frames_ts.push(HTTP2Frame {
                        header: head,
                        data: txdata,
                    });
                    self.transactions.push(tx);
                    input = &rem[hlsafe..];
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
                    let tx = self.new_tx();

                    //TODO6tx parse frame types as in request once transactions are well handled
                    let hl = head.length as usize;

                    self.transactions.push(tx);
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
        &mut self, min_tx_id: u64, state: &mut u64,
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

//TODOnext connection upgrade from HTTP1 cf SMTP STARTTLS
/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_http2_probing_parser_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        match parser::http2_parse_frame_header(slice) {
            Ok((_, header)) => {
                if header.reserved != 0
                    || header.length > HTTP2_DEFAULT_MAX_FRAME_SIZE
                    || header.flags & 0xFE != 0
                    || header.ftype != parser::HTTP2FrameType::SETTINGS as u8
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
    flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
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

    //TODOask use FILE_USE_DETECT ?
    state.files.flags_ts = unsafe { FileFlowToFlags(flow, STREAM_TOSERVER) };
    return state.parse_ts(buf);
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_tc(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, HTTP2State);
    let buf = build_slice!(input, input_len as usize);
    return state.parse_tc(buf);
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
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
    //TODO6tx progress completion
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    //TODO6tx progress completion
    let tx = cast_pointer!(tx, HTTP2Transaction);

    // Transaction is done if we have a response.
    if tx.frames_tc.len() + tx.frames_ts.len() > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_logged(
    _state: *mut std::os::raw::c_void, tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_set_logged(
    _state: *mut std::os::raw::c_void, tx: *mut std::os::raw::c_void, logged: u32,
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
    event_name: *const std::os::raw::c_char, event_id: *mut std::os::raw::c_int,
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
                "invalid_header" => HTTP2Event::InvalidHeader as i32,
                "invalid_frame_length" => HTTP2Event::InvalidFrameLength as i32,
                "extra_header_data" => HTTP2Event::ExtraHeaderData as i32,
                "long_frame_data" => HTTP2Event::LongFrameData as i32,
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
    event_id: std::os::raw::c_int, event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = HTTP2Event::from_i32(event_id as i32) {
        let estr = match e {
            HTTP2Event::InvalidFrameHeader => "invalid_frame_header\0",
            HTTP2Event::InvalidClientMagic => "invalid_client_magic\0",
            HTTP2Event::InvalidFrameData => "invalid_frame_data\0",
            HTTP2Event::InvalidHeader => "invalid_header\0",
            HTTP2Event::InvalidFrameLength => "invalid_frame_length\0",
            HTTP2Event::ExtraHeaderData => "extra_header_data\0",
            HTTP2Event::LongFrameData => "long_frame_data\0",
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
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: &mut u64,
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

#[no_mangle]
pub extern "C" fn rs_http2_getfiles(
    state: *mut std::os::raw::c_void, direction: u8,
) -> *mut FileContainer {
    let state = cast_pointer!(state, HTTP2State);
    if direction == STREAM_TOCLIENT {
        &mut state.files.files_tc as *mut FileContainer
    } else {
        &mut state.files.files_ts as *mut FileContainer
    }
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"http2\0";

#[no_mangle]
pub unsafe extern "C" fn rs_http2_register_parser() {
    //TODOend default port
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
        get_files: Some(rs_http2_getfiles),
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
