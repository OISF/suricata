/* Copyright (C) 2020-2021 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>

use std;
use std::ffi::CString;
use crate::core::{ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};
use crate::applayer;
use crate::applayer::*;
use nom7::Err;
use super::parser;

static mut ALPROTO_RFB: AppProto = ALPROTO_UNKNOWN;

pub struct RFBTransaction {
    tx_id: u64,
    pub complete: bool,
    pub chosen_security_type: Option<u32>,

    pub tc_server_protocol_version: Option<parser::ProtocolVersion>,
    pub ts_client_protocol_version: Option<parser::ProtocolVersion>,
    pub tc_supported_security_types: Option<parser::SupportedSecurityTypes>,
    pub ts_security_type_selection: Option<parser::SecurityTypeSelection>,
    pub tc_server_security_type: Option<parser::ServerSecurityType>,
    pub tc_vnc_challenge: Option<parser::VncAuth>,
    pub ts_vnc_response: Option<parser::VncAuth>,
    pub ts_client_init: Option<parser::ClientInit>,
    pub tc_security_result: Option<parser::SecurityResult>,
    pub tc_failure_reason: Option<parser::FailureReason>,
    pub tc_server_init: Option<parser::ServerInit>,

    tx_data: applayer::AppLayerTxData,
}

impl Transaction for RFBTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

impl RFBTransaction {
    pub fn new() -> RFBTransaction {
        RFBTransaction {
            tx_id: 0,
            complete: false,
            chosen_security_type: None,

            tc_server_protocol_version: None,
            ts_client_protocol_version: None,
            tc_supported_security_types: None,
            ts_security_type_selection: None,
            tc_server_security_type: None,
            tc_vnc_challenge: None,
            ts_vnc_response: None,
            ts_client_init: None,
            tc_security_result: None,
            tc_failure_reason: None,
            tc_server_init: None,

            tx_data: applayer::AppLayerTxData::new(),
        }
    }
}

pub struct RFBState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: Vec<RFBTransaction>,
    state: parser::RFBGlobalState
}

impl State<RFBTransaction> for RFBState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&RFBTransaction> {
        self.transactions.get(index)
    }

}

impl RFBState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: Vec::new(),
            state: parser::RFBGlobalState::TCServerProtocolVersion
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&RFBTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> RFBTransaction {
        let mut tx = RFBTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn get_current_tx(&mut self) -> Option<&mut RFBTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == self.tx_id {
                return Some(tx);
            }
        }
        return None;
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut current = input;
        let mut consumed = 0;
        SCLogDebug!("request_state {}, input_len {}", self.state, input.len());
        loop {
            if current.len() == 0 {
                return AppLayerResult::ok();
            }
            match self.state {
                parser::RFBGlobalState::TSClientProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            if request.major == "003" && request.minor == "003" {
                                // in version 3.3 the server decided security type
                                self.state = parser::RFBGlobalState::TCServerSecurityType;
                            } else {
                                self.state = parser::RFBGlobalState::TCSupportedSecurityTypes;
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_client_protocol_version = Some(request);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TSSecurityTypeSelection => {
                    match parser::parse_security_type_selection(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            let chosen_security_type = request.security_type;
                            match chosen_security_type {
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                _ => return AppLayerResult::err(),
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_security_type_selection = Some(request);
                                current_transaction.chosen_security_type = Some(chosen_security_type as u32);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TSVncResponse => {
                    match parser::parse_vnc_auth(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TCSecurityResult;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_vnc_response = Some(request);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TSClientInit => {
                    match parser::parse_client_init(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TCServerInit;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_client_init = Some(request);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::Message => {
                    //todo implement RFB messages, for now we stop here
                    return AppLayerResult::err();
                }
                parser::RFBGlobalState::TCServerProtocolVersion => {
                    SCLogDebug!("Reversed traffic, expected response.");
                    return AppLayerResult::err();
                }
                _ => {
                    SCLogDebug!("Invalid state for request {}", self.state);
                    current = b"";
                }
            }
        }
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut current = input;
        let mut consumed = 0;
        SCLogDebug!("response_state {}, response_len {}", self.state, input.len());
        loop {
            if current.len() == 0 {
                return AppLayerResult::ok();
            }
            match self.state {
                parser::RFBGlobalState::TCServerProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TSClientProtocolVersion;
                            let tx = self.new_tx();
                            self.transactions.push(tx);

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_protocol_version = Some(request);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCSupportedSecurityTypes => {
                    match parser::parse_supported_security_types(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            SCLogDebug!(
                                "supported_security_types: {}, types: {}", request.number_of_types,
                                request.types.iter().map(ToString::to_string).map(|v| v + " ").collect::<String>()
                            );

                            self.state = parser::RFBGlobalState::TSSecurityTypeSelection;
                            if request.number_of_types == 0 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_supported_security_types = Some(request);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCServerSecurityType => {
                    // In RFB 3.3, the server decides the authentication type
                    match parser::parse_server_security_type(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            let chosen_security_type = request.security_type;
                            SCLogDebug!("chosen_security_type: {}", chosen_security_type);
                            match chosen_security_type {
                                0 => self.state = parser::RFBGlobalState::TCFailureReason,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                _ => {
                                    // TODO Event unknown security type
                                    return AppLayerResult::err();
                                }
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_security_type = Some(request);
                                current_transaction.chosen_security_type = Some(chosen_security_type);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCVncChallenge => {
                    match parser::parse_vnc_auth(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::TSVncResponse;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_vnc_challenge = Some(request);
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCSecurityResult => {
                    match parser::parse_security_result(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            if request.status == 0 {
                                self.state = parser::RFBGlobalState::TSClientInit;

                                if let Some(current_transaction) = self.get_current_tx() {
                                    current_transaction.tc_security_result = Some(request);
                                } else {
                                    return AppLayerResult::err();
                                }
                            } else if request.status == 1 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            } else {
                                // TODO: Event: unknown security result value
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCFailureReason => {
                    match parser::parse_failure_reason(current) {
                        Ok((_rem, request)) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_failure_reason = Some(request);
                            } else {
                                return AppLayerResult::err();
                            }
                            return AppLayerResult::err();
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCServerInit => {
                    match parser::parse_server_init(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            current = rem;

                            self.state = parser::RFBGlobalState::Message;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_init = Some(request);
                                // connection initialization is complete and parsed
                                current_transaction.complete = true;
                            } else {
                                return AppLayerResult::err();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::Message => {
                    //todo implement RFB messages, for now we stop here
                    return AppLayerResult::err();
                }
                _ => {
                    SCLogDebug!("Invalid state for response");
                    return AppLayerResult::err();
                }
            }
        }
    }
}

// C exports.

#[no_mangle]
pub extern "C" fn rs_rfb_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = RFBState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(unsafe { Box::from_raw(state as *mut RFBState) });
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, RFBState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, RFBState);
    return state.parse_request(stream_slice.as_slice());
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, RFBState);
    return state.parse_response(stream_slice.as_slice());
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, RFBState);
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
pub unsafe extern "C" fn rs_rfb_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, RFBState);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, RFBTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"rfb\0";

export_tx_data_get!(rs_rfb_get_tx_data, RFBTransaction);
export_state_data_get!(rs_rfb_get_state_data, RFBState);

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_register_parser() {
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_rfb_state_new,
        state_free: rs_rfb_state_free,
        tx_free: rs_rfb_state_tx_free,
        parse_ts: rs_rfb_parse_request,
        parse_tc: rs_rfb_parse_response,
        get_tx_count: rs_rfb_state_get_tx_count,
        get_tx: rs_rfb_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_rfb_tx_get_alstate_progress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<RFBState, RFBTransaction>),
        get_tx_data: rs_rfb_get_tx_data,
        get_state_data: rs_rfb_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_RFB = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust rfb parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for RFB.");
    }
}
