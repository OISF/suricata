/* Copyright (C) 2024 Open Information Security Foundation
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

use crate::applayer::{self, *};
use crate::conf::conf_get;
use crate::core::{Flow, *};
use crate::frames::*;
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

use crate::ldap::types::*;

static mut LDAP_MAX_TX: usize = 256;

static mut ALPROTO_LDAP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerFrameType)]
pub enum LdapFrameType {
    Pdu,
}

#[derive(AppLayerEvent)]
enum LdapEvent {
    TooManyTransactions,
    InvalidData,
    RequestNotFound,
}

#[derive(Debug)]
pub struct LdapTransaction {
    pub tx_id: u64,
    pub request: Option<LdapMessage>,
    pub responses: VecDeque<LdapMessage>,
    complete: bool,

    tx_data: AppLayerTxData,
}

impl Default for LdapTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl LdapTransaction {
    pub fn new() -> LdapTransaction {
        Self {
            tx_id: 0,
            request: None,
            responses: VecDeque::new(),
            complete: false,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for LdapTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct LdapState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<LdapTransaction>,
    tx_index_completed: usize,
    request_frame: Option<Frame>,
    response_frame: Option<Frame>,
}

impl State<LdapTransaction> for LdapState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&LdapTransaction> {
        self.transactions.get(index)
    }
}

impl LdapState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            tx_index_completed: 0,
            request_frame: None,
            response_frame: None,
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&LdapTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    pub fn new_tx(&mut self) -> LdapTransaction {
        let mut tx = LdapTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        if self.transactions.len() > unsafe { LDAP_MAX_TX } {
            let mut index = self.tx_index_completed;
            for tx_old in &mut self.transactions.range_mut(self.tx_index_completed..) {
                index += 1;
                if !tx_old.complete {
                    tx_old.complete = true;
                    tx_old
                        .tx_data
                        .set_event(LdapEvent::TooManyTransactions as u8);
                    break;
                }
            }
            self.tx_index_completed = index;
        }
        return tx;
    }

    fn set_event(&mut self, e: LdapEvent) {
        if let Some(tx) = self.transactions.back_mut() {
            tx.tx_data.set_event(e as u8);
        }
    }

    fn find_request(&mut self, message_id: MessageID) -> Option<&mut LdapTransaction> {
        self.transactions.iter_mut().find(|tx| {
            tx.request
                .as_ref()
                .map_or(false, |req| req.message_id == message_id)
        })
    }

    fn parse_request(&mut self, flow: *const Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            if self.request_frame.is_none() {
                self.request_frame = Frame::new(
                    flow,
                    &stream_slice,
                    start,
                    -1_i64,
                    LdapFrameType::Pdu as u8,
                    None,
                );
                SCLogDebug!("ts: pdu {:?}", self.request_frame);
            }
            match ldap_parse_msg(start) {
                Ok((rem, msg)) => {
                    let mut tx = self.new_tx();
                    let tx_id = tx.id();
                    let request = LdapMessage::from(msg);
                    tx.complete = match request.protocol_op {
                        ProtocolOp::UnbindRequest => true,
                        _ => false,
                    };
                    tx.request = Some(request);
                    self.transactions.push_back(tx);

                    let consumed = start.len() - rem.len();
                    start = rem;
                    if let Some(frame) = &self.request_frame {
                        frame.set_len(flow, consumed as i64);
                        frame.set_tx(flow, tx_id);
                        self.request_frame = None;
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

        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, flow: *const Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            if self.response_frame.is_none() {
                self.response_frame = Frame::new(
                    flow,
                    &stream_slice,
                    start,
                    -1_i64,
                    LdapFrameType::Pdu as u8,
                    None,
                );
                SCLogDebug!("tc: pdu {:?}", self.response_frame);
            }
            match ldap_parse_msg(start) {
                Ok((rem, msg)) => {
                    let response = LdapMessage::from(msg);
                    if let Some(tx) = self.find_request(response.message_id) {
                        tx.complete = match response.protocol_op {
                            ProtocolOp::SearchResultDone(_)
                            | ProtocolOp::BindResponse(_)
                            | ProtocolOp::ModifyResponse(_)
                            | ProtocolOp::AddResponse(_)
                            | ProtocolOp::DelResponse(_)
                            | ProtocolOp::ModDnResponse(_)
                            | ProtocolOp::CompareResponse(_)
                            | ProtocolOp::ExtendedResponse(_) => true,
                            _ => false,
                        };
                        let tx_id = tx.id();
                        tx.responses.push_back(response);
                        let consumed = start.len() - rem.len();
                        if let Some(frame) = &self.response_frame {
                            frame.set_len(flow, consumed as i64);
                            frame.set_tx(flow, tx_id);
                            self.response_frame = None;
                        }
                    } else if let ProtocolOp::ExtendedResponse(_) = response.protocol_op {
                        // this is an unsolicited notification, which means
                        // there is no request
                        let mut tx = self.new_tx();
                        let tx_id = tx.id();
                        tx.complete = true;
                        tx.responses.push_back(response);
                        self.transactions.push_back(tx);
                        let consumed = start.len() - rem.len();
                        if let Some(frame) = &self.response_frame {
                            frame.set_len(flow, consumed as i64);
                            frame.set_tx(flow, tx_id);
                            self.response_frame = None;
                        }
                    } else {
                        let mut tx = self.new_tx();
                        tx.complete = true;
                        let tx_id = tx.id();
                        tx.responses.push_back(response);
                        self.transactions.push_back(tx);
                        self.set_event(LdapEvent::RequestNotFound);
                        let consumed = start.len() - rem.len();
                        if let Some(frame) = &self.response_frame {
                            frame.set_len(flow, consumed as i64);
                            frame.set_tx(flow, tx_id);
                            self.response_frame = None;
                        }
                    };
                    start = rem;
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    self.set_event(LdapEvent::InvalidData);
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }
}

fn probe(input: &[u8], direction: Direction, rdir: *mut u8) -> AppProto {
    match ldap_parse_msg(input) {
        Ok((_, msg)) => {
            let ldap_msg = LdapMessage::from(msg);
            if ldap_msg.is_unknown() {
                return unsafe { ALPROTO_FAILED };
            }
            if direction == Direction::ToServer && !ldap_msg.is_request() {
                unsafe {
                    *rdir = Direction::ToClient.into();
                }
            }
            if direction == Direction::ToClient && !ldap_msg.is_response() {
                unsafe {
                    *rdir = Direction::ToServer.into();
                }
            }
            return unsafe { ALPROTO_LDAP };
        }
        Err(nom::Err::Incomplete(_)) => {
            return ALPROTO_UNKNOWN;
        }
        Err(_e) => {
            return unsafe { ALPROTO_FAILED };
        }
    }
}

#[no_mangle]
unsafe extern "C" fn SCLdapProbingParser(
    _flow: *const Flow, direction: u8, input: *const u8, input_len: u32, rdir: *mut u8,
) -> AppProto {
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        return probe(slice, direction.into(), rdir);
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
extern "C" fn SCLdapStateNew(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = LdapState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

#[no_mangle]
unsafe extern "C" fn SCLdapStateFree(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut LdapState));
}

#[no_mangle]
unsafe extern "C" fn SCLdapStateTxFree(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, LdapState);
    state.free_tx(tx_id);
}

#[no_mangle]
unsafe extern "C" fn SCLdapParseRequest(
    flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }
    let state = cast_pointer!(state, LdapState);
    state.parse_request(flow, stream_slice)
}

#[no_mangle]
unsafe extern "C" fn SCLdapParseResponse(
    flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }
    let state = cast_pointer!(state, LdapState);
    state.parse_response(flow, stream_slice)
}

#[no_mangle]
unsafe extern "C" fn SCLdapStateGetTx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, LdapState);
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
unsafe extern "C" fn SCLdapStateGetTxCount(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, LdapState);
    return state.tx_id;
}

#[no_mangle]
unsafe extern "C" fn SCLdapTxGetAlstateProgress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

export_tx_data_get!(SCLdapGetTxData, LdapTransaction);
export_state_data_get!(SCLdapGetStateData, LdapState);

const PARSER_NAME: &[u8] = b"ldap\0";

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_register_parser() {
    let default_port = CString::new("389").unwrap();
    let mut parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(SCLdapProbingParser),
        probe_tc: Some(SCLdapProbingParser),
        min_depth: 0,
        max_depth: 16,
        state_new: SCLdapStateNew,
        state_free: SCLdapStateFree,
        tx_free: SCLdapStateTxFree,
        parse_ts: SCLdapParseRequest,
        parse_tc: SCLdapParseResponse,
        get_tx_count: SCLdapStateGetTxCount,
        get_tx: SCLdapStateGetTx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: SCLdapTxGetAlstateProgress,
        get_eventinfo: Some(LdapEvent::get_event_info),
        get_eventinfo_byid: Some(LdapEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<LdapState, LdapTransaction>),
        get_tx_data: SCLdapGetTxData,
        get_state_data: SCLdapGetStateData,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_LDAP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.ldap.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                LDAP_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for ldap.max-tx");
            }
        }
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_LDAP);
    } else {
        SCLogDebug!("Protocol detection and parser disabled for LDAP.");
    }

    parser.ipproto = IPPROTO_UDP;
    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_LDAP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_LDAP);
    } else {
        SCLogDebug!("Protocol detection and parser disabled for LDAP.");
    }
}
