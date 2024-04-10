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
use crate::core::{AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

use crate::ldap::types::*;

static mut LDAP_MAX_TX: usize = 256;

static mut ALPROTO_LDAP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum LdapEvent {
    TooManyTransactions,
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

    fn set_event(&mut self, e: LdapEvent) {
        self.tx_data.set_event(e as u8);
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
                    tx.set_event(LdapEvent::TooManyTransactions);
                    break;
                }
            }
            self.tx_index_completed = index;
        }
        return tx;
    }

    fn find_request(&mut self, message_id: MessageID) -> Option<&mut LdapTransaction> {
        self.transactions.iter_mut().find(|tx| {
            tx.request
                .as_ref()
                .map_or(false, |req| req.message_id == message_id)
        })
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            match ldap_parse_msg(start) {
                Ok((rem, msg)) => {
                    start = rem;
                    let mut tx = self.new_tx();
                    let request = LdapMessage::from(msg);
                    tx.complete = match request.protocol_op {
                        ProtocolOp::UnbindRequest => true,
                        _ => false,
                    };
                    tx.request = Some(request);
                    self.transactions.push_back(tx);
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

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            match ldap_parse_msg(start) {
                Ok((rem, msg)) => {
                    start = rem;

                    let response = LdapMessage::from(msg);
                    if let Some(tx) = self.find_request(response.message_id) {
                        tx.complete = match response.protocol_op {
                            ProtocolOp::SearchResultDone(_)
                            | ProtocolOp::ModifyResponse(_)
                            | ProtocolOp::AddResponse(_)
                            | ProtocolOp::DelResponse(_)
                            | ProtocolOp::ModDnResponse(_)
                            | ProtocolOp::CompareResponse(_)
                            | ProtocolOp::ExtendedResponse(_) => true,
                            _ => false,
                        };
                        tx.responses.push_back(response);
                    } else if let ProtocolOp::ExtendedResponse(_) = response.protocol_op {
                        // this is an unsolicited notification, which means
                        // there is no request
                        let mut tx = self.new_tx();
                        tx.complete = true;
                        tx.responses.push_back(response);
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
}

fn probe(input: &[u8]) -> AppProto {
    match ldap_parse_msg(input) {
        Ok((_, msg)) => {
            let ldap_msg = LdapMessage::from(msg);
            if ldap_msg.is_unknown() {
                return unsafe { ALPROTO_FAILED };
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

unsafe extern "C" fn rs_ldap_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        return probe(slice);
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn rs_ldap_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = LdapState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_ldap_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut LdapState));
}

unsafe extern "C" fn rs_ldap_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, LdapState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_ldap_parse_request(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
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
    state.parse_request(stream_slice.as_slice());

    AppLayerResult::ok()
}

unsafe extern "C" fn rs_ldap_parse_response(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
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
    state.parse_response(stream_slice.as_slice());

    AppLayerResult::ok()
}

unsafe extern "C" fn rs_ldap_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
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

unsafe extern "C" fn rs_ldap_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, LdapState);
    return state.tx_id;
}

unsafe extern "C" fn rs_ldap_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_ldap_get_tx_data, LdapTransaction);
export_state_data_get!(rs_ldap_get_state_data, LdapState);

const PARSER_NAME: &[u8] = b"ldap\0";

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_register_parser() {
    let default_port = CString::new("389").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_ldap_probing_parser),
        probe_tc: Some(rs_ldap_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_ldap_state_new,
        state_free: rs_ldap_state_free,
        tx_free: rs_ldap_state_tx_free,
        parse_ts: rs_ldap_parse_request,
        parse_tc: rs_ldap_parse_response,
        get_tx_count: rs_ldap_state_get_tx_count,
        get_tx: rs_ldap_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_ldap_tx_get_alstate_progress,
        get_eventinfo: Some(LdapEvent::get_event_info),
        get_eventinfo_byid: Some(LdapEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<LdapState, LdapTransaction>),
        get_tx_data: rs_ldap_get_tx_data,
        get_state_data: rs_ldap_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
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
    } else {
        SCLogDebug!("Protocol detection and parser disabled for LDAP.");
    }
}
