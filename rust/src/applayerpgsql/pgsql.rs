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
use nom;
use std::ffi::CString;
use std::mem::transmute;
use crate::applayer::{self, *};
use super::parser::{self, PgsqlBEMessage, PgsqlFEMessage};
use crate::core::{self, ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};

static mut ALPROTO_PGSQL: AppProto = ALPROTO_UNKNOWN;

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub enum PgsqlTransactionState { // a simplified version of this, stored in State - for startup phase, at least
    ConnectionStart = 0, // TODO [Doubt] or ConnectionRequest? Maybe we don't even need this
    SslRequest = 1,
    SslAccepted = 2,  // TODO [Doubt] Maybe we don't even need this
    SimpleAuthentication = 3,
    GssEncryptionRequest = 4,
    AuthenticationGssApi = 5,
    AuthenticationSasl = 6,
    AuthenticationSspi = 7,
    AuthenticationOk = 8,
    BackendInitialization = 9,
    ReadyForQuery = 10,
    NotificationReceived = 11, // TODO not sure if necessary
    ErrorReceived = 12,
    SimpleQueryProtocol = 13, // TODO not sure if necessary
    PossibleInvalidState = 14, // TODO this may be nonsense
    Termination = 15, // TODO not sure if necessary
    Finished = 16,
}

#[derive(Debug)]
pub struct PgsqlTransaction {
    tx_id: u64,
    pub state: PgsqlTransactionState,
    pub request: Vec<PgsqlFEMessage>,
    pub response: Vec<PgsqlBEMessage>,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
}

impl PgsqlTransaction {
    pub fn new() -> PgsqlTransaction {
        PgsqlTransaction {
            tx_id: 0,
            state: PgsqlTransactionState::ConnectionStart, // TODO question is this the best initialization value?
            request: Vec::<PgsqlFEMessage>::new(),
            response: Vec::<PgsqlBEMessage>::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
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

impl Drop for PgsqlTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

#[derive(Debug, PartialEq)]
pub enum PgsqlStateProgress {
    IdleState = 0,
    StartupMessageReceived,
    SASLInitialResponseReceived,
    SSLRequestReceived,
    PasswordMessageReceived,
    ConnectionCompleted,
    ReadyForQueryReceived,
    UnknownState,
}

pub struct PgsqlState {
    tx_id: u64,
    transactions: Vec<PgsqlTransaction>,
    request_gap: bool,
    response_gap: bool,
    backend_secrete_key: u32,
    backend_pid: u32,
    state_progress: PgsqlStateProgress,
}

impl PgsqlState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            request_gap: false,
            response_gap: false,
            backend_secrete_key: 0,
            backend_pid: 0,
            state_progress: PgsqlStateProgress::IdleState,
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&PgsqlTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> PgsqlTransaction {
        let mut tx = PgsqlTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    // TODO this will probably be replaced by find_or_create_tx
    // fn find_request(&mut self) -> Option<&mut PgsqlTransaction> {
    //     // TODO this must be changed, now. HTTP2 doesn't do this, as far as I could tell...
    //     // So I may or may not keep it. I'll have to decide
    //     for tx in &mut self.transactions {
    //         if tx.response.is_none() {
    //             return Some(tx);
    //         }
    //     }
    //     None
    // }

    // find or create a new transaction
    // TODO future, improved version may be based on current message type and dir, too
    fn find_or_create_tx(&mut self) -> &mut PgsqlTransaction {
        // First, check if we should create a new tx (in case the other was completed or there's no tx yet)
        if  self.state_progress == PgsqlStateProgress::IdleState ||
            self.state_progress == PgsqlStateProgress::ConnectionCompleted ||
            self.state_progress == PgsqlStateProgress::ReadyForQueryReceived {
                let tx = self.new_tx();
                self.transactions.push(tx);
            }
            // If we don't have to create a new transaction, just return the current one
            return self.transactions.last_mut().unwrap();
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            // TODO I have changed probe to just return a boolean. will this be an issue, later on?
            if !probe_ts(input) {
                // The parser now needs to decide what to do as we are not in sync.
                // For this pgsql, we'll just try again next time.
                SCLogNotice!("Suricata interprets there's a gap in the request");
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while start.len() > 0 {
            // I think this whole block must be redesigned. Already. lol.
            // Lol, indeed. But let's face the facts:
            /*
                - there may be situations where, for the same flow, there will be more than one
                startupmessage. So I can't assume that those will only happen when there aren't any
                transactions in the State.
                - It is probably cleaner to have a method that returns message type, instead of directly
                trying to extract that from the message. hmmm....

                - so, for the first issue, I can probably have just one match, and check message type
                for whatever is the returned request...?
            */
            // if self.transactions.len() == 0 {
            //     match parser::pgsql_parse_startup_packet(start) {
            //         Ok((ram, request)) => {
            //             start = rem;
            //             SCLogNotice!("Request: {:?}", request);
            //             let mut tx = self.new_tx();
            //             tx.request = Some(request);
            //             let mut e: PgsqlEvent;
            //             let request_type = request.message_type;

            //             if request_type {
            //                 e = PgsqlEvent::SslAccepted;
            //             } else if

            //             self.transactions.push(tx);
            //         }
            //     }
            // } // TODO clean this up, add logic for response, add tests!
            match parser::pgsql_parse_request(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request: {:?}", request);
                    // TODO I can't simply create a new transaction without being sure that's what I need.
                    // if we're in the middle of a transaction, I certainly will not create a new one.
                    // let mut tx = self.new_tx();
                    let mut tx = self.find_or_create_tx();
                    match request {
                        PgsqlFEMessage::SslRequest(_) => {
                            tx.request.push(request);
                            self.state_progress = PgsqlStateProgress::SSLRequestReceived;
                            // self.transactions.push(tx); // TODO question: This is now done in find_or_create_tx. Is that bad practice?
                        }
                        PgsqlFEMessage::StartupMessage(_) => {
                            tx.request.push(request);
                            self.state_progress = PgsqlStateProgress::StartupMessageReceived;
                            // self.transactions.push(tx);
                        }
                        PgsqlFEMessage::PasswordMessage(_) => {
                            tx.request.push(request);
                            self.state_progress = PgsqlStateProgress::PasswordMessageReceived;
                        }
                        _ => {}
                    }
                },
                Err(nom::Err::Incomplete(needed)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    SCLogNotice!("Suricata interprets request as incomplete");
                    let consumed = input.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogNotice!("Needed: {:?}, estimated needed: {:?}", needed, needed_estimation);
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                },
                Err(_) => {
                    return AppLayerResult::err();
                },
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            // TODO I have changed probe to just return a boolean. will this be an issue, later on?
            if !probe_tc(input) {
                // The parser now needs to decide what to do as we are not in sync.
                // For this pgsql, we'll just try again next time.
                SCLogNotice!("Suricata interprets there's a gap in the response");
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while start.len() > 0 {
            match parser::pgsql_parse_response(start) {
                Ok((rem, response)) => {
                    start = rem;
                    SCLogNotice!("Found a response.");
                    SCLogNotice!("- Response: {:?}", &response);
                    let message_type = response.get_message_type();
                    let be_key_pid = response.get_backendkey_info().0;
                    let be_secret_key = response.get_backendkey_info().1;
                    // TODO we must also match on response type, so we can change state...
                    // match on backend_secrete_key - store info
                    // ready for query -- change state to ready for query received
                    match message_type {
                        15 => {
                            self.backend_pid = be_key_pid;
                            self.backend_secrete_key = be_secret_key;
                        }
                        16 => {
                            self.state_progress = PgsqlStateProgress::ReadyForQueryReceived;
                        }
                        _ => {}
                    }
                    let mut tx = self.find_or_create_tx();
                    tx.response.push(response);
                }
                Err(nom::Err::Incomplete(needed)) => {
                    let consumed = input.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogNotice!("Suricata interprets the response as incomplete");
                    SCLogNotice!("Needed: {:?}, estimated needed: {:?}", needed, needed_estimation);
                    SCLogNotice!("start is: {:?}", &start);
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&PgsqlTransaction, u64, bool)> {
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

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/// Probe for a valid PostgreSQL request
///
/// PGSQL messages don't have a header per se, so we parse the slice for an ok()
fn probe_ts(input: &[u8]) -> bool {
    // TODO would it be useful to add a is_valid function?
    parser::pgsql_parse_request(input).is_ok()
}

/// Probe for a valid PostgreSQL response
///
/// PGSQL messages don't have a header per se, so we parse the slice for an ok()
fn probe_tc(input: &[u8]) -> bool {
    parser::pgsql_parse_response(input).is_ok()
}

// C exports.

export_tx_get_detect_state!(
    rs_pgsql_tx_get_detect_state,
    PgsqlTransaction
);
export_tx_set_detect_state!(
    rs_pgsql_tx_set_detect_state,
    PgsqlTransaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_pgsql_probing_parser_ts(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    if input_len >= 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe_ts(slice) {
            return unsafe { ALPROTO_PGSQL };
        }
    }
    return ALPROTO_UNKNOWN;
}

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_pgsql_probing_parser_tc(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    if input_len >= 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe_tc(slice) {
            return unsafe { ALPROTO_PGSQL };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = PgsqlState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<PgsqlState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, PgsqlState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_pgsql_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
            true
        } else {
            false
        }
    };

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        // TODO Victor thinks we can still have data here, so we'd have to process that
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, PgsqlState);

    if input == std::ptr::null_mut() && input_len > 0 {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(input_len);
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_request(buf)
    }
}

#[no_mangle]
pub extern "C" fn rs_pgsql_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, PgsqlState);

    if input == std::ptr::null_mut() && input_len > 0 {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(input_len);
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_response(buf).into()
    }
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, PgsqlState);
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
pub extern "C" fn rs_pgsql_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, PgsqlState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_tx_get_state(tx: *mut std::os::raw::c_void) -> PgsqlTransactionState {
    let tx = cast_pointer!(tx, PgsqlTransaction);
    return tx.state;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    return rs_pgsql_tx_get_state(tx) as i32;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_events(
    tx: *mut std::os::raw::c_void
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, PgsqlTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
    // TODO change this
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
                                                         _event_name: *mut *const std::os::raw::c_char,
                                                         _event_type: *mut core::AppLayerEventType
) -> i8 {
    return -1;
    // TODO change this?
}
#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, PgsqlState);
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

// TODO understand this function, and if I need it, how can I implement it with what I have
// /// Get the request buffer for a transaction from C.
// ///
// /// No required for parsing, but an example function for retrieving a
// /// pointer to the request buffer from C for detection.
// #[no_mangle]
// pub extern "C" fn rs_pgsql_get_request_buffer(
//     tx: *mut std::os::raw::c_void,
//     buf: *mut *const u8,
//     len: *mut u32,
// ) -> u8
// {
//     let tx = cast_pointer!(tx, PgsqlTransaction);
//     if let Some(ref request) = tx.request {
//         if request.len() > 0 {
//             unsafe {
//                 *len = request.len() as u32;
//                 *buf = request.as_ptr();
//             }
//             return 1;
//         }
//     }
//     return 0;
// }

// TODO understand this function, and if I need it, how can I implement it with what I have
// /// Get the response buffer for a transaction from C.
// #[no_mangle]
// pub extern "C" fn rs_pgsql_get_response_buffer(
//     tx: *mut std::os::raw::c_void,
//     buf: *mut *const u8,
//     len: *mut u32,
// ) -> u8
// {
//     let tx = cast_pointer!(tx, PgsqlTransaction);
//     if let Some(ref response) = tx.response {
//         if response.len() > 0 {
//             unsafe {
//                 *len = response.len() as u32;
//                 *buf = response.as_ptr();
//             }
//             return 1;
//         }
//     }
//     return 0;
// }

export_tx_data_get!(rs_pgsql_get_tx_data, PgsqlTransaction);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"pgsql\0";

#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_register_parser() {
    let default_port = CString::new("[5432]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_pgsql_probing_parser_ts),
        probe_tc: Some(rs_pgsql_probing_parser_tc),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_pgsql_state_new,
        state_free: rs_pgsql_state_free,
        tx_free: rs_pgsql_state_tx_free,
        parse_ts: rs_pgsql_parse_request,
        parse_tc: rs_pgsql_parse_response,
        get_tx_count: rs_pgsql_state_get_tx_count,
        get_tx: rs_pgsql_state_get_tx,
        tx_comp_st_ts: PgsqlTransactionState::Finished as i32,
        tx_comp_st_tc: PgsqlTransactionState::Finished as i32,
        tx_get_progress: rs_pgsql_tx_get_alstate_progress,
        get_de_state: rs_pgsql_tx_get_detect_state,
        set_de_state: rs_pgsql_tx_set_detect_state,
        get_events: Some(rs_pgsql_state_get_events),
        get_eventinfo: Some(rs_pgsql_state_get_event_info),
        get_eventinfo_byid : Some(rs_pgsql_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_pgsql_state_get_tx_iterator),
        get_tx_data: rs_pgsql_get_tx_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_PGSQL = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust pgsql parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for PGSQL.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_request_probe() {

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        assert!(probe_ts(&buf));

        // incomplete messages, probe must return false
        assert!(!probe_ts(&buf[0..6]));
        assert!(!probe_ts(&buf[0..3]));

        // length is wrong (7), probe must return false
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x07, 0x04, 0xd2, 0x16, 0x2f];
        assert!(!probe_ts(&buf));

        // A valid startup message/request
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x26, 0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x72, 0x00, 0x6f, 0x72, 0x79,
                            0x78, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61,
                            0x73, 0x65, 0x00, 0x6d, 0x61, 0x69, 0x6c, 0x73,
                            0x74, 0x6f, 0x72, 0x65, 0x00, 0x00];
        assert!(probe_ts(&buf));

        // A non valid startup message/request (length is shorter by one. Would `exact!` help?)
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x25, 0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x72, 0x00, 0x6f, 0x72, 0x79,
                            0x78, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61,
                            0x73, 0x65, 0x00, 0x6d, 0x61, 0x69, 0x6c, 0x73,
                            0x74, 0x6f, 0x72, 0x65, 0x00, 0x00];
        assert!(!probe_ts(&buf));

    }

    #[test]
    fn test_response_probe() {
        let buf: &[u8] = &[0x52, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05,
                        0xf2, 0x11, 0xa3, 0xed];
        assert!(probe_tc(buf));

        let buf: &[u8] = &[ 0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03];
        assert!(probe_tc(buf));

        let buf: &[u8] = &[
        /* R */             0x52,
        /* 54 */            0x00, 0x00, 0x00, 0x36,
        /* 12 */            0x00, 0x00, 0x00, 0x0c,
        /* signature */     0x76, 0x3d, 0x64, 0x31, 0x50, 0x58, 0x61, 0x38, 0x54,
                            0x4b, 0x46, 0x50, 0x5a, 0x72, 0x52, 0x33, 0x4d, 0x42,
                            0x52, 0x6a, 0x4c, 0x79, 0x33, 0x2b, 0x4a, 0x36, 0x79,
                            0x78, 0x72, 0x66, 0x77, 0x2f, 0x7a, 0x7a, 0x70, 0x38,
                            0x59, 0x54, 0x39, 0x65, 0x78, 0x56, 0x37, 0x73, 0x38, 0x3d];
        assert!(probe_tc(buf));

        let buf: &[u8] = &[0x53, 0x00, 0x00, 0x00, 0x1a, 0x61, 0x70, 0x70, 0x6c,
                    0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61,
                    0x6d, 0x65, 0x00, 0x70, 0x73, 0x71, 0x6c, 0x00];
        assert!(probe_tc(buf));

        // length is wrong
        let buf: &[u8] = &[0x53, 0x00, 0x00, 0x00, 0x10, 0x61, 0x70, 0x70, 0x6c,
                    0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61,
                    0x6d, 0x65, 0x00, 0x70, 0x73, 0x71, 0x6c, 0x00];
        assert!(!probe_tc(&buf));

        // incomplete
        assert!(!probe_tc(&buf[0..5]));
    }

    #[test]
    fn test_request_events() {
        let mut state = PgsqlState::new();
        // an SSL Request
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        state.parse_request(buf);
        let ok_state = PgsqlStateProgress::SSLRequestReceived;

        assert_eq!(state.state_progress, ok_state);

        // TODO add test for startup request
    }

    #[test]
    fn test_incomplete_request() {
        let mut state = PgsqlState::new();
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 2});

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 3});

        // This is the first message and only the first message.
        let r = state.parse_request(&buf);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});
    }
}
