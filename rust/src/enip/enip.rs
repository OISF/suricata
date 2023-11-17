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

use super::parser;
use crate::applayer::{self, *};
use crate::core::{
    AppProto, Direction, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP, IPPROTO_UDP,
    STREAM_TOCLIENT, STREAM_TOSERVER,
};
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

static mut ALPROTO_ENIP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum EnipEvent {}

#[derive(Default)]
pub struct EnipTransaction {
    tx_id: u64,
    pub request: Option<parser::EnipPdu>,
    pub response: Option<parser::EnipPdu>,
    pub done: bool,

    tx_data: AppLayerTxData,
}

impl Transaction for EnipTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct EnipState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<EnipTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<EnipTransaction> for EnipState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&EnipTransaction> {
        self.transactions.get(index)
    }
}

impl EnipState {
    pub fn new() -> Self {
        Default::default()
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&EnipTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> EnipTransaction {
        let mut tx = EnipTransaction::default();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut EnipTransaction> {
        //TODOlol + maxtx ?
        self.transactions
            .iter_mut()
            .find(|tx| tx.response.is_none())
    }

    fn parse_udp(&mut self, input: &[u8], request: bool) -> AppLayerResult {
        match parser::parse_enip_pdu(input) {
            Ok((_, pdu)) => {
                if request {
                    let mut tx = self.new_tx();
                    tx.request = Some(pdu);
                    self.transactions.push_back(tx);
                } else if let Some(tx) = self.find_request() {
                    tx.response = Some(pdu);
                    tx.done = true;
                } else {
                    let mut tx = self.new_tx();
                    tx.response = Some(pdu);
                    tx.done = true;
                    self.transactions.push_back(tx);
                }
                return AppLayerResult::ok();
            }
            Err(_) => {
                return AppLayerResult::err();
            }
        }
    }
    fn parse_tcp(&mut self, input: &[u8], request: bool) -> AppLayerResult {
        if request {
            if self.request_gap {
                if !probe(input) {
                    return AppLayerResult::ok();
                }
                self.request_gap = false;
            }
        } else if self.response_gap {
            if !probe(input) {
                return AppLayerResult::ok();
            }
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_enip_pdu(start) {
                Ok((rem, pdu)) => {
                    start = rem;

                    if request {
                        let mut tx = self.new_tx();
                        tx.request = Some(pdu);
                        self.transactions.push_back(tx);
                    } else if let Some(tx) = self.find_request() {
                        tx.response = Some(pdu);
                        tx.done = true;
                    } else {
                        let mut tx = self.new_tx();
                        tx.response = Some(pdu);
                        tx.done = true;
                        self.transactions.push_back(tx);
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
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
/// As this enip protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> bool {
    match parser::parse_enip_header(input) {
        Ok((rem, header)) => {
            match header.status {
                parser::ENIP_STATUS_SUCCESS
                | parser::ENIP_STATUS_INVALID_CMD
                | parser::ENIP_STATUS_NO_RESOURCES
                | parser::ENIP_STATUS_INCORRECT_DATA
                | parser::ENIP_STATUS_INVALID_SESSION
                | parser::ENIP_STATUS_INVALID_LENGTH
                | parser::ENIP_STATUS_UNSUPPORTED_PROT_REV
                | parser::ENIP_STATUS_ENCAP_HEADER_ERROR => {} // Ok so far, continue
                _ => {
                    return false;
                }
            }

            match header.cmd {
                parser::ENIP_CMD_NOP => {
                    if header.options != 0 {
                        return false;
                    }
                }
                parser::ENIP_CMD_REGISTER_SESSION => {
                    if header.pdulen != 4 {
                        return false;
                    }
                }
                parser::ENIP_CMD_UNREGISTER_SESSION => {
                    if header.pdulen != 4 && header.pdulen != 0 {
                        return false;
                    }
                }
                parser::ENIP_CMD_LIST_INTERFACES => {
                    if parser::parse_enip_list_interfaces(rem).is_err() {
                        return false;
                    }
                }
                parser::ENIP_CMD_LIST_SERVICES
                | parser::ENIP_CMD_LIST_IDENTITY
                | parser::ENIP_CMD_SEND_RRDATA
                | parser::ENIP_CMD_SEND_UNIT_DATA
                | parser::ENIP_CMD_INDICATE_STATUS
                | parser::ENIP_CMD_CANCEL => {} // Ok so far, continue
                _ => {
                    return false;
                }
            }
            return true;
        }
        _ => {
            return false;
        }
    }
}

// C exports.

unsafe extern "C" fn enip_probing_parser_udp(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 24 bytes.
    if input_len >= 24 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return ALPROTO_ENIP;
        }
    }
    return ALPROTO_FAILED;
}

const ENIP_HEADER_LEN: u32 = 24;

unsafe extern "C" fn enip_probing_parser_tcp(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 24 bytes.
    if input.is_null() {
        return ALPROTO_FAILED;
    }
    if input_len < ENIP_HEADER_LEN {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, input_len as usize);
    if probe(slice) {
        return ALPROTO_ENIP;
    }
    return ALPROTO_FAILED;
}

extern "C" fn rs_enip_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = EnipState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn enip_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut EnipState));
}

unsafe extern "C" fn enip_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, EnipState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn enip_parse_request_udp(
    _flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, EnipState);
    let buf = stream_slice.as_slice();
    state.parse_udp(buf, true)
}

unsafe extern "C" fn enip_parse_response_udp(
    _flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, EnipState);
    let buf = stream_slice.as_slice();
    state.parse_udp(buf, false)
}

unsafe extern "C" fn enip_parse_request_tcp(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, EnipState);
    if stream_slice.is_gap() {
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        debug_validate_bug_on!(buf.is_empty());
        state.parse_tcp(buf, true)
    }
}

unsafe extern "C" fn enip_parse_response_tcp(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, EnipState);
    if stream_slice.is_gap() {
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        debug_validate_bug_on!(buf.is_empty());
        state.parse_tcp(buf, false)
    }
}

unsafe extern "C" fn rs_enip_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, EnipState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_enip_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, EnipState);
    return state.tx_id;
}

unsafe extern "C" fn rs_enip_tx_get_alstate_progress(tx: *mut c_void, direction: u8) -> c_int {
    let tx = cast_pointer!(tx, EnipTransaction);

    // Transaction is done if we have a response.
    if tx.done {
        return 1;
    }
    let dir: Direction = direction.into();
    if dir == Direction::ToServer {
        if tx.request.is_some() {
            return 1;
        }
    } else if tx.response.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_enip_get_tx_data, EnipTransaction);
export_state_data_get!(rs_enip_get_state_data, EnipState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"enip\0";

#[no_mangle]
pub unsafe extern "C" fn rs_enip_register_parsers() {
    let default_port = CString::new("[44818]").unwrap();
    let mut parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(enip_probing_parser_udp),
        probe_tc: Some(enip_probing_parser_udp),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_enip_state_new,
        state_free: enip_state_free,
        tx_free: enip_state_tx_free,
        parse_ts: enip_parse_request_udp,
        parse_tc: enip_parse_response_udp,
        get_tx_count: rs_enip_state_get_tx_count,
        get_tx: rs_enip_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_enip_tx_get_alstate_progress,
        get_eventinfo: Some(EnipEvent::get_event_info),
        get_eventinfo_byid: Some(EnipEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<EnipState, EnipTransaction>),
        get_tx_data: rs_enip_get_tx_data,
        get_state_data: rs_enip_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None, //TODOlol
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_ENIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust enip parser registered for UDP.");
        unsafe {
            AppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_UDP,
                ALPROTO_ENIP,
                STREAM_TOSERVER | STREAM_TOCLIENT,
            );
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for ENIP on UDP.");
    }

    parser.ipproto = IPPROTO_TCP;
    parser.probe_ts = Some(enip_probing_parser_tcp);
    parser.probe_tc = Some(enip_probing_parser_tcp);
    parser.parse_ts = enip_parse_request_tcp;
    parser.parse_tc = enip_parse_response_tcp;
    parser.flags = APP_LAYER_PARSER_OPT_ACCEPT_GAPS;

    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_ENIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust enip parser registered for TCP.");
        unsafe {
            AppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_TCP,
                ALPROTO_ENIP,
                STREAM_TOSERVER | STREAM_TOCLIENT,
            );
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for ENIP on TCP.");
    }
}
