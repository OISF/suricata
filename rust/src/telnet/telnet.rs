/* Copyright (C) 2021 Open Information Security Foundation
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
use crate::core::{ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};
use crate::applayer::{self, *};
use crate::frames::*;
use std::ffi::CString;
use nom;
use super::parser;

static mut ALPROTO_TELNET: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum TelnetEvent {}

#[derive(AppLayerFrameType)]
pub enum TelnetFrameType {
    Pdu,
    Ctl,
    Data,
}

pub struct TelnetTransaction {
    tx_id: u64,
    tx_data: AppLayerTxData,
}

impl TelnetTransaction {
    pub fn new() -> TelnetTransaction {
        TelnetTransaction {
            tx_id: 0,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for TelnetTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

pub enum TelnetProtocolState {
    Idle,
    LoginSent,
    LoginRecv,
    PasswdSent,
    PasswdRecv,
    AuthOk,
    AuthFail,
}

pub struct TelnetState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: Vec<TelnetTransaction>,
    request_gap: bool,
    response_gap: bool,

    request_frame: Option<Frame>,
    response_frame: Option<Frame>,

    /// either control or data frame
    request_specific_frame: Option<Frame>,
    /// either control or data frame
    response_specific_frame: Option<Frame>,
    state: TelnetProtocolState,
}

impl State<TelnetTransaction> for TelnetState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&TelnetTransaction> {
        self.transactions.get(index)
    }
}

impl TelnetState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: Vec::new(),
            request_gap: false,
            response_gap: false,
            request_frame: None,
            request_specific_frame: None,
            response_frame: None,
            response_specific_frame: None,
            state: TelnetProtocolState::Idle,
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&TelnetTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn _new_tx(&mut self) -> TelnetTransaction {
        let mut tx = TelnetTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn _find_request(&mut self) -> Option<&mut TelnetTransaction> {
        // TODO
        None
    }

    // app-layer-frame-documentation tag start: parse_request
    fn parse_request(
        &mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8],
    ) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this telnet, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while start.len() > 0 {
            if self.request_frame.is_none() {
                self.request_frame = Frame::new(
                    flow,
                    stream_slice,
                    start,
                    -1 as i64,
                    TelnetFrameType::Pdu as u8,
                );
            }
            if self.request_specific_frame.is_none() {
                if let Ok((_, is_ctl)) = parser::peek_message_is_ctl(start) {
                    let f = if is_ctl {
                        Frame::new(
                            flow,
                            stream_slice,
                            start,
                            -1 as i64,
                            TelnetFrameType::Ctl as u8,
                        )
                    } else {
                        Frame::new(
                            flow,
                            stream_slice,
                            start,
                            -1 as i64,
                            TelnetFrameType::Data as u8,
                        )
                    // app-layer-frame-documentation tag end: parse_request
                    };
                    self.request_specific_frame = f;
                }
            }
            // app-layer-frame-documentation tag start: update frame_len
            match parser::parse_message(start) {
                Ok((rem, request)) => {
                    let consumed = start.len() - rem.len();
                    if rem.len() == start.len() {
                        panic!("lockup");
                    }
                    start = rem;

                    if let Some(frame) = &self.request_frame {
                        frame.set_len(flow, consumed as i64);
                        // app-layer-frame-documentation tag end: update frame_len
                        self.request_frame = None;
                    }
                    if let Some(frame) = &self.request_specific_frame {
                        frame.set_len(flow, consumed as i64);
                        self.request_specific_frame = None;
                    }

                    if let parser::TelnetMessageType::Data(d) = request {
                        match self.state {
                            TelnetProtocolState::LoginSent => {
                                self.state = TelnetProtocolState::LoginRecv;
                            }
                            TelnetProtocolState::PasswdSent => {
                                self.state = TelnetProtocolState::PasswdRecv;
                            }
                            TelnetProtocolState::AuthOk => {
                                let _message = std::str::from_utf8(&d);
                                if let Ok(_message) = _message {
                                    SCLogDebug!("=> {}", _message);
                                }
                            }
                            _ => {}
                        }
                    } else if let parser::TelnetMessageType::Control(_c) = request {
                        SCLogDebug!("request {:?}", _c);
                    }
                }
                Err(nom7::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this telnet, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while start.len() > 0 {
            if self.response_frame.is_none() {
                self.response_frame = Frame::new(flow, stream_slice, start, -1 as i64, TelnetFrameType::Pdu as u8);
            }
            if self.response_specific_frame.is_none() {
                if let Ok((_, is_ctl)) = parser::peek_message_is_ctl(start) {
                    self.response_specific_frame = if is_ctl {
                        Frame::new(flow, stream_slice, start, -1 as i64, TelnetFrameType::Ctl as u8)
                    } else {
                        Frame::new(flow, stream_slice, start, -1 as i64, TelnetFrameType::Data as u8)
                    };
                }
            }

            let r = match self.state {
                TelnetProtocolState::Idle => parser::parse_welcome_message(start),
                TelnetProtocolState::AuthFail => parser::parse_welcome_message(start),
                TelnetProtocolState::LoginRecv => parser::parse_welcome_message(start),
                _ => parser::parse_message(start),
            };
            match r {
                Ok((rem, response)) => {
                    let consumed = start.len() - rem.len();
                    start = rem;

                    if let Some(frame) = &self.response_frame {
                        frame.set_len(flow, consumed as i64);
                        self.response_frame = None;
                    }
                    if let Some(frame) = &self.response_specific_frame {
                        frame.set_len(flow, consumed as i64);
                        self.response_specific_frame = None;
                    }

                    if let parser::TelnetMessageType::Data(d) = response {
                        match self.state {
                            TelnetProtocolState::Idle |
                            TelnetProtocolState::AuthFail => {
                                self.state = TelnetProtocolState::LoginSent;
                            },
                            TelnetProtocolState::LoginRecv => {
                                self.state = TelnetProtocolState::PasswdSent;
                            },
                            TelnetProtocolState::PasswdRecv => {
                                if let Ok(message) = std::str::from_utf8(&d) {
                                    match message {
                                        "Login incorrect" => {
                                            SCLogDebug!("LOGIN FAILED");
                                            self.state = TelnetProtocolState::AuthFail;
                                        },
                                        "" => {

                                        },
                                        &_ => {
                                            SCLogDebug!("LOGIN OK");
                                            self.state = TelnetProtocolState::AuthOk;
                                        },
                                    }
                                }
                            },
                            TelnetProtocolState::AuthOk => {
                                let _message = std::str::from_utf8(&d);
                                if let Ok(_message) = _message {
                                    SCLogDebug!("<= {}", _message);
                                }
                            },
                            _ => {},
                        }
                    } else if let parser::TelnetMessageType::Control(_c) = response {
                        SCLogDebug!("response {:?}", _c);
                    }
                }
                Err(nom7::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_e) => {
                    SCLogDebug!("error! {}", _e);
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/// Probe for a valid header.
///
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    // TODO see if we can implement something here. Ctl message is easy,
    // and 'login: ' is common, but we can have random text and possibly
    // other output as well. So for now data on port 23 is it.
    Ok((input, ()))
}

// C exports.

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_telnet_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            SCLogDebug!("telnet detected");
            return ALPROTO_TELNET;
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_telnet_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = TelnetState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut std::os::raw::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut TelnetState));
}

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, TelnetState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_parse_request(
    flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let eof = if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
        true
    } else {
        false
    };

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, TelnetState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(flow, &stream_slice, buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_parse_response(
    flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let _eof = if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
        true
    } else {
        false
    };
    let state = cast_pointer!(state, TelnetState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(flow, &stream_slice, buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, TelnetState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, TelnetState);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let _tx = cast_pointer!(tx, TelnetTransaction);
    // TODO
    return 0;
}

export_tx_data_get!(rs_telnet_get_tx_data, TelnetTransaction);
export_state_data_get!(rs_telnet_get_state_data, TelnetState);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"telnet\0";

#[no_mangle]
pub unsafe extern "C" fn rs_telnet_register_parser() {
    let default_port = CString::new("[23]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_telnet_probing_parser),
        probe_tc: Some(rs_telnet_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_telnet_state_new,
        state_free: rs_telnet_state_free,
        tx_free: rs_telnet_state_tx_free,
        parse_ts: rs_telnet_parse_request,
        parse_tc: rs_telnet_parse_response,
        get_tx_count: rs_telnet_state_get_tx_count,
        get_tx: rs_telnet_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_telnet_tx_get_alstate_progress,
        get_eventinfo: Some(TelnetEvent::get_event_info),
        get_eventinfo_byid : Some(TelnetEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<TelnetState, TelnetTransaction>),
        get_tx_data: rs_telnet_get_tx_data,
        get_state_data: rs_telnet_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: Some(TelnetFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(TelnetFrameType::ffi_name_from_id),

    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_TELNET = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust telnet parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for TELNET.");
    }
}
