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

// Author: Frank Honza <frank.honza@dcso.de>

use std;
use crate::core::{self, ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};
use crate::log::*;
use std::mem::transmute;
use crate::applayer::{self, LoggerFlags};
use crate::parser::*;
use std::ffi::CString;
use nom;
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

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    detect_flags: applayer::TxDetectFlags,
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

            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            detect_flags: applayer::TxDetectFlags::default(),
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

impl Drop for RFBTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct RFBState {
    tx_id: u64,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    transactions: Vec<RFBTransaction>,
    state: parser::RFBGlobalState
}

impl RFBState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
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

    fn parse_request(&mut self, input: &[u8]) -> bool {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return true;
        }

        // For simplicity, always extend the buffer and work on it.
        self.request_buffer.extend(input);

        let tmp: Vec<u8>;
        let mut current = {
            tmp = self.request_buffer.split_off(0);
            tmp.as_slice()
        };

        SCLogDebug!("request_state {}, input_len {}", self.state, input.len());
        loop {
            if current.len() == 0 {
                return true;
            }
            match self.state {
                parser::RFBGlobalState::TSClientProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            current = rem;
                            if request.major.to_string() == "003" && request.minor.to_string() == "003" {
                                // in version 3.3 the server decided security type
                                self.state = parser::RFBGlobalState::TCServerSecurityType;
                            } else {
                                self.state = parser::RFBGlobalState::TCSupportedSecurityTypes;
                            }

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.ts_client_protocol_version = Some(request);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TSSecurityTypeSelection => {
                    match parser::parse_security_type_selection(current) {
                        Ok((rem, request)) => {
                            current = rem;

                            let chosen_security_type = request.security_type;
                            match chosen_security_type {
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                _ => return false
                            }

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.ts_security_type_selection = Some(request);
                                    current_transaction.chosen_security_type = Some(chosen_security_type as u32);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TSVncResponse => {
                    match parser::parse_vnc_auth(current) {
                        Ok((rem, request)) => {
                            current = rem;

                            self.state = parser::RFBGlobalState::TCSecurityResult;

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.ts_vnc_response = Some(request);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TSClientInit => {
                    match parser::parse_client_init(current) {
                        Ok((rem, request)) => {
                            current = rem;
                            self.state = parser::RFBGlobalState::TCServerInit;

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.ts_client_init = Some(request);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::Message => {
                    //todo implement RFB messages, for now we stop here
                    return false;
                }
                parser::RFBGlobalState::TCServerProtocolVersion => {
                    SCLogDebug!("Reversed traffic, expected response.");
                    return false;
                }
                _ => {
                    SCLogDebug!("Invalid state for request {}", self.state);
                    current = b"";
                }
            }
        }
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return true;
        }

        // For simplicity, always extend the buffer and work on it.
        self.response_buffer.extend(input);

        let tmp: Vec<u8>;
        let mut current = {
            tmp = self.response_buffer.split_off(0);
            tmp.as_slice()
        };

        SCLogDebug!("response_state {}, response_len {}", self.state, input.len());
        loop {
            if current.len() == 0 {
                return true;
            }
            match self.state {
                parser::RFBGlobalState::TCServerProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            current = rem;
                            self.state = parser::RFBGlobalState::TSClientProtocolVersion;
                            let tx = self.new_tx();
                            self.transactions.push(tx);

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.tc_server_protocol_version = Some(request);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TCSupportedSecurityTypes => {
                    match parser::parse_supported_security_types(current) {
                        Ok((rem, request)) => {
                            current = rem;
                            SCLogDebug!(
                                "supported_security_types: {}, types: {}", request.number_of_types,
                                request.types.iter().map(ToString::to_string).map(|v| v + " ").collect::<String>()
                            );

                            self.state = parser::RFBGlobalState::TSSecurityTypeSelection;
                            if request.number_of_types == 0 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            }

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.tc_supported_security_types = Some(request);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TCServerSecurityType => {
                    // In RFB 3.3, the server decides the authentication type
                    match parser::parse_server_security_type(current) {
                        Ok((rem, request)) => {
                            current = rem;
                            let chosen_security_type = request.security_type;
                            SCLogDebug!("chosen_security_type: {}", chosen_security_type);
                            match chosen_security_type {
                                0 => self.state = parser::RFBGlobalState::TCFailureReason,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                _ => {
                                    // TODO Event unknown security type
                                    return false
                                }
                            }

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.tc_server_security_type = Some(request);
                                    current_transaction.chosen_security_type = Some(chosen_security_type);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TCVncChallenge => {
                    match parser::parse_vnc_auth(current) {
                        Ok((rem, request)) => {
                            current = rem;

                            self.state = parser::RFBGlobalState::TSVncResponse;

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.tc_vnc_challenge = Some(request);
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                    }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TCSecurityResult => {
                    match parser::parse_security_result(current) {
                        Ok((rem, request)) => {
                            current = rem;

                            if request.status == 0 {
                                self.state = parser::RFBGlobalState::TSClientInit;

                                match self.get_current_tx() {
                                    Some(current_transaction) => {
                                        current_transaction.tc_security_result = Some(request);
                                    }
                                    _ => {
                                        return false
                                    }
                                }
                            } else if request.status == 1 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            } else {
                                // TODO: Event: unknown security result value
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TCFailureReason => {
                    match parser::parse_failure_reason(current) {
                        Ok((_rem, request)) => {
                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.tc_failure_reason = Some(request);
                                }
                                _ => {
                                    return false;
                                }
                            }

                            return false;
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::TCServerInit => {
                    match parser::parse_server_init(current) {
                        Ok((rem, request)) => {
                            current = rem;
                            self.state = parser::RFBGlobalState::Message;

                            match self.get_current_tx() {
                                Some(current_transaction) => {
                                    current_transaction.tc_server_init = Some(request);
                                    // connection initialization is complete and parsed
                                    current_transaction.complete = true;
                                }
                                _ => {
                                    return false
                                }
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            self.request_buffer.extend_from_slice(current);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                parser::RFBGlobalState::Message => {
                    //todo implement RFB messages, for now we stop here
                    return false;
                }
                _ => {
                    SCLogDebug!("Invalid state for response");
                    return false;
                }
            }
        }
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&RFBTransaction, u64, bool)> {
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

/// Probe to see if this input looks like a request or response.
fn probe(input: &[u8]) -> bool {
    // test for RFB
    if input.len() > 4 && input[0] == 82 && input[1] == 70 && input[2] == 66 && input[3] == 32 {
        return true;
    }
    return false;
}

// C exports.

export_tx_get_detect_state!(
    rs_rfb_tx_get_detect_state,
    RFBTransaction
);
export_tx_set_detect_state!(
    rs_rfb_tx_set_detect_state,
    RFBTransaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_rfb_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 4 bytes.
    if input_len > 4 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return unsafe { ALPROTO_RFB };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_new() -> *mut std::os::raw::c_void {
    let state = RFBState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<RFBState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, RFBState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_rfb_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };

    if eof {
        // If needed, handled EOF, or pass it into the parser.
    }

    let state = cast_pointer!(state, RFBState);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_request(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_rfb_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, RFBState);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_response(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, RFBState);
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
pub extern "C" fn rs_rfb_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, RFBState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_progress_completion_status(
    _direction: u8,
) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_rfb_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, RFBTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_rfb_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, RFBTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_rfb_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, RFBTransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_events(
    tx: *mut std::os::raw::c_void
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, RFBTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
                                                         _event_name: *mut *const std::os::raw::c_char,
                                                         _event_type: *mut core::AppLayerEventType
) -> i8 {
    return -1;
}
#[no_mangle]
pub extern "C" fn rs_rfb_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, RFBState);
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

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"rfb\0";

export_tx_detect_flags_set!(rs_rfb_set_tx_detect_flags, RFBTransaction);
export_tx_detect_flags_get!(rs_rfb_get_tx_detect_flags, RFBTransaction);

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_register_parser() {
    let default_port = CString::new("[5900]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_rfb_probing_parser),
        probe_tc: Some(rs_rfb_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_rfb_state_new,
        state_free: rs_rfb_state_free,
        tx_free: rs_rfb_state_tx_free,
        parse_ts: rs_rfb_parse_request,
        parse_tc: rs_rfb_parse_response,
        get_tx_count: rs_rfb_state_get_tx_count,
        get_tx: rs_rfb_state_get_tx,
        tx_get_comp_st: rs_rfb_state_progress_completion_status,
        tx_get_progress: rs_rfb_tx_get_alstate_progress,
        get_tx_logged: Some(rs_rfb_tx_get_logged),
        set_tx_logged: Some(rs_rfb_tx_set_logged),
        get_de_state: rs_rfb_tx_get_detect_state,
        set_de_state: rs_rfb_tx_set_detect_state,
        get_events: Some(rs_rfb_state_get_events),
        get_eventinfo: Some(rs_rfb_state_get_event_info),
        get_eventinfo_byid : Some(rs_rfb_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: Some(rs_rfb_state_get_tx_iterator),
        get_tx_detect_flags: Some(rs_rfb_get_tx_detect_flags),
        set_tx_detect_flags: Some(rs_rfb_set_tx_detect_flags),
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
