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
pub enum PgsqlTransactionState {
    Init = 0,
    RequestReceived,
    ResponseDone,
}

#[derive(Debug)]
pub struct PgsqlTransaction {
    pub tx_id: u64,
    pub tx_state: PgsqlTransactionState,
    pub requests: Vec<PgsqlFEMessage>,
    pub responses: Vec<PgsqlBEMessage>,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
}

impl PgsqlTransaction {
    pub fn new() -> PgsqlTransaction {
        PgsqlTransaction {
            tx_id: 0,
            tx_state: PgsqlTransactionState::Init,
            requests: Vec::<PgsqlFEMessage>::new(),
            responses: Vec::<PgsqlBEMessage>::new(),
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
    IdleState,
    SSLRequestReceived,
    SSLAcceptedReceived,
    SSLRejectedReceived,
    StartupMessageReceived,
    SASLAuthenticationReceived,
    SASLInitialResponseReceived,
    // SSPIAuthenticationReceived, // TODO implement
    SimpleAuthenticationReceived,
    PasswordMessageReceived,
    ConnectionCompleted,
    ReadyForQueryReceived,
    SimpleQueryReceived,
    RowDescriptionReceived,
    DataRowReceived,
    CommandCompletedReceived,
    ErrorMessageReceived,
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
        SCLogNotice!("Creating new transaction. tx_id: {}", tx.tx_id);
        return tx;
    }

    /// Find or create a new transaction
    ///
    /// If a new transaction is created, push that into state.transactions before returning &mut to last tx
    /// If we can't find a transaction and we should not create one, we return None
    /// The moment when this is called will may impact the logic of transaction tracking (e.g. when a tx is considered completed)
    // TODO A future, improved version may be based on current message type and dir, too
    fn find_or_create_tx(&mut self) -> Option<&mut PgsqlTransaction> {
        // First, check if we should create a new tx (in case the other was completed or there's no tx yet)
        if  self.state_progress == PgsqlStateProgress::IdleState ||
            self.state_progress == PgsqlStateProgress::StartupMessageReceived ||
            self.state_progress == PgsqlStateProgress::PasswordMessageReceived ||
            self.state_progress == PgsqlStateProgress::SASLInitialResponseReceived ||
            self.state_progress == PgsqlStateProgress::SASLResponseReceived ||
            self.state_progress == PgsqlStateProgress::SimpleQueryReceived ||
            self.state_progress == PgsqlStateProgress::SSLRequestReceived ||
            self.state_progress == PgsqlStateProgress::ConnectionTerminated {
                let tx = self.new_tx();
                self.transactions.push(tx);
            }
            // If we don't need a new transaction, just return the current one
            SCLogDebug!("find_or_create state is {:?}", &self.state_progress);
            return self.transactions.last_mut();
    }

    /// Define PgsqlState progression, based on the request received
    ///
    /// As PostgreSQL transactions can have multiple messages, State progression
    /// is what helps us keep track of the PgsqlTransactions - when one finished
    /// when the other starts.
    /// State isn't directly updated to avoid reference borrowing conflicts.
    fn request_get_next_state(request: &PgsqlFEMessage) -> Option<PgsqlStateProgress> {
        match request {
            PgsqlFEMessage::SSLRequest(_) => {
                Some(PgsqlStateProgress::SSLRequestReceived)
            },
            PgsqlFEMessage::StartupMessage(_) => {
                Some(PgsqlStateProgress::StartupMessageReceived)
            },
            PgsqlFEMessage::PasswordMessage(_) => {
                Some(PgsqlStateProgress::PasswordMessageReceived)
            },
            PgsqlFEMessage::SASLInitialResponse(_) => {
                Some(PgsqlStateProgress::SASLInitialResponseReceived)
            },
            PgsqlFEMessage::SASLResponse(_) => {
                Some(PgsqlStateProgress::SASLResponseReceived)
            },
            PgsqlFEMessage::SimpleQuery(_) => {
                SCLogDebug!("Match: SimpleQuery");
                Some(PgsqlStateProgress::SimpleQueryReceived)
                // TODO here we may want to save the command that was received, to compare that later on when we receive command completed?
            },
            PgsqlFEMessage::Terminate(_) => {
                SCLogDebug!("Match: Terminate message");
                Some(PgsqlStateProgress::ConnectionTerminated)
            }
        }
    }

    fn state_based_req_parsing(state: PgsqlStateProgress, input: &[u8]) -> Result<(&[u8], parser::PgsqlFEMessage),  nom::Err<(&[u8], nom::error::ErrorKind)>> {
        match state {
            PgsqlStateProgress::SASLAuthenticationReceived => {
                parser::parse_sasl_initial_response(input)
            },
            PgsqlStateProgress::SASLInitialResponseReceived => {
                parser::parse_sasl_response(input)
            },
            PgsqlStateProgress::SimpleAuthenticationReceived => {
                parser::parse_password_message(input)
            },PgsqlStateProgress::IdleState |
            PgsqlStateProgress::AuthenticationOkReceived |
            PgsqlStateProgress::SSLRejectedReceived |
            PgsqlStateProgress::SSLAcceptedReceived |
            PgsqlStateProgress::ReadyForQueryReceived |
            PgsqlStateProgress::CommandCompletedReceived |
            _ => {
                parser::parse_request(input)
            },
        }
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

            // TODO AuthenticationGSS, parse GSS response -> decide if we should offer support for it in the first version
            SCLogDebug!("In 'parse_request' State Progress is: {:?}", &self.state_progress);
            match PgsqlState::state_based_req_parsing(self.state_progress, &start){
                Ok((rem, request)) => {
                    start = rem;
                    if let Some(state) = PgsqlState::request_get_next_state(&request) {
                        self.state_progress = state;
                    };
                    if let Some(tx) = self.find_or_create_tx(){
                        tx.requests.push(request);
                    } else {
                        return AppLayerResult::err();
                    };
                },
                PgsqlStateProgress::SASLAuthenticationReceived => {
                    match parser::parse_sasl_initial_response(start) {
                        Ok((rem, request)) => {
                            start = rem;
                            SCLogNotice!("Request: {:?}", request);
                            let tx = self.find_or_create_tx();
                            tx.requests.push(request);
                        }
                        Err(nom::Err::Incomplete(needed)) => {
                            let consumed = input.len() - start.len();
                            let needed_estimation = start.len() + 1;
                            SCLogNotice!("Needed: {:?}, estimated needed: {:?}", needed, needed_estimation);
                            return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                },
                PgsqlStateProgress::SASLInitialResponseReceived => {
                    match parser::parse_sasl_response(start) {
                        Ok((rem, request)) => {
                            start = rem;
                            SCLogNotice!("Request: {:?}", request);
                            let tx = self.find_or_create_tx();
                            tx.requests.push(request);
                        },
                        Err(nom::Err::Incomplete(needed)) => {
                            let consumed = input.len() - start.len();
                            let needed_estimation = start.len() + 1;
                            SCLogNotice!("Needed: {:?}, estimated needed: {:?}", needed, needed_estimation);
                            return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                        },
                        Err(_) => {
                            return AppLayerResult::err();
                        },
                    }
                },
                PgsqlStateProgress::SimpleAuthenticationReceived => {
                    match parser::parse_password_message(start) {
                        Ok((rem, request)) => {
                            start = rem;
                            SCLogNotice!("Request : {:?}", request);
                            let tx = self.find_or_create_tx();
                            tx.requests.push(request);
                            self.state_progress = PgsqlStateProgress::PasswordMessageReceived;
                        },
                        Err(nom::Err::Incomplete(needed)) => {
                            let consumed = input.len() - start.len() + 1;
                            let needed_estimation = start.len() + 1;
                            SCLogNotice!("Needed: {:?}, estimated needed: {:?}", needed, needed_estimation);
                            return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                        },
                        Err(_) => {
                            return AppLayerResult::err();
                        },
                    }
                },
                // PgsqlStateProgress::SSPIAuthenticationReceived => {
                //     // TODO implement
                // },
                _ => {
                    // TODO handle unexpected situations here
                }
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

        // what changes must be done here?
        // first of them: if SSL was requested, parse ssl response
        // then, if ssl response is "accepted", upgrade to TLS
        // if not, I guess we can simply go on and parse the responses.
        // I think that for most, if not for all of them, just the message should be enough to know how to parse the msg

        let mut start = input;
        while start.len() > 0 {
            // TODO this must be revamped, to take into account PgsqlStateProgress,
            // for cases like SSL handshake (might be the only one, but not sure yet)
            if self.state_progress == PgsqlStateProgress::SslRequestReceived {
                SCLogNotice!("State Progress: {:?}", &self.state_progress);
                let tx = self.find_or_create_tx();
                match parser::parse_ssl_response(start) {
                    Ok((rem, response)) => {
                        start = rem;
                        SCLogNotice!("SSL Response received");
                        SCLogNotice!("Response: {:?}", &response);
                        let message_type = response.get_message_type();
                        if message_type == "SslAccepted" {
                            SCLogNotice!("SSL Request accepted, we must upgrade to TSL");
                            tx.responses.push(response);
                            self.state_progress = PgsqlStateProgress::SslAcceptedReceived;
                            // TODO do we upgrade to TLS here, or leave that for elsewhere?
                        } else if message_type == "SslRejected" {
                            SCLogNotice!("SSL Request rejected");
                            tx.responses.push(response);
                            self.state_progress = PgsqlStateProgress::SslRejectedReceived;
                            // TODO not sure if something else should be done here it may be the case that this tx
                        } else {
                            // TODO what should I do if I get an invalid message here? AppLayerResult error?
                        }
                    },
                    Err(nom::Err::Incomplete(needed)) => {
                        let consumed = input.len() - start.len();
                        let needed_estimation = start.len() + 1;
                        SCLogNotice!("Suricata interprets the response as incomplete");
                        SCLogNotice!("Needed: {:?}, estimated needed: {:?}", needed, needed_estimation);
                        SCLogNotice!("start is: {:?}", &start);
                        return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                    },
                    Err(nom::Err::Error((rem, nom::error::ErrorKind::Verify))) => {
                        // We want to know if we got an ErrorMessage here
                        SCLogNotice!("Nom error while parsing SSL Response. Unparsed input: {:?}", rem);
                        // TODO I think we want to parse the error message
                        self.state_progress = PgsqlStateProgress::ErrorMessageReceived;
                    },
                    _ => {
                        return AppLayerResult::err();
                    }
                }
            } else {
                SCLogNotice!("Found a response. Not sure what it is, yet");
                SCLogNotice!("State progress is {:?}", &self.state_progress);
                match parser::pgsql_parse_response(start) {
                    Ok((rem, response)) => {
                        start = rem;
                        SCLogNotice!("- Start is: {:?}", &start);
                        SCLogNotice!("Found a response.");
                        SCLogNotice!("- Response: {:?}", &response);
                        SCLogNotice!("- Response size is: {:?}", std::mem::size_of_val(&response));
                        let message_type = response.get_message_type();
                        // We must also match on response type, so we can change state...
                        match message_type {
                            "SslAccepted" => { // SSL Response
                                self.state_progress = PgsqlStateProgress::SslRequestReceived;
                                // TODO we must upgrade to TLS here.
                            },
                            "BackendKeyData" => { // BackendKeyDataMessage
                                self.backend_pid = response.get_backendkey_info().0;
                                self.backend_secrete_key = response.get_backendkey_info().1;
                            },
                            "ReadyForQuery" => { // ReadyForQueryMessage
                                self.state_progress = PgsqlStateProgress::ReadyForQueryReceived;
                            },
                            // TODO Question find out if we should store any of the Parameter Statuses in the State.
                            "AuthenticationMD5Password" |
                            "AuthenticationCleartextPassword" => {
                                SCLogNotice!("Simple Authentication type");
                                SCLogNotice!("Message type is {}", &message_type);
                                self.state_progress = PgsqlStateProgress::SimpleAuthenticationReceived;
                            },
                            "RowDescription" => {
                                self.state_progress = PgsqlStateProgress::RowDescriptionReceived;
                                SCLogNotice!("State is: {:?}", &self.state_progress);
                                SCLogNotice!("Input length is {:?}", start.len());
                            },
                            "DataRow" => {
                                self.state_progress = PgsqlStateProgress::DataRowReceived;
                                SCLogNotice!("State is: {:?}", &self.state_progress);
                                // SCLogNotice!("Response is: {:?}", &response);
                                println!("Response: {:?}", &response);
                            },
                            "CommandCompleted" => {
                                self.state_progress = PgsqlStateProgress::CommandCompletedReceived;
                                // TODO here, we may want to compare command that was stored when query was sent with what we received here
                                SCLogNotice!("State is: {:?}", &self.state_progress);
                                SCLogNotice!("Input length is {:?}", start.len());
                            },
                            _ => {
                                // TODO handle unexpected situations here
                                SCLogNotice!("In parse_response, we don't know what do to here, yet.");
                                SCLogNotice!("Response is: {:?}", &response);
                            },
                        }
                        // Handle the tx here to avoid borrow checker issues
                        let tx = self.find_or_create_tx();
                        tx.responses.push(response);
                    }
                    Err(nom::Err::Incomplete(needed)) => {
                        let consumed = input.len() - start.len();
                        let needed_estimation = start.len() + 1;
                        SCLogNotice!("Suricata interprets the response as incomplete");
                        SCLogNotice!("Needed: {:?}, consumed: {:?}", &needed, &consumed);
                        SCLogNotice!("Start in incomplete is: {:?}", &start);
                        return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                    }
                    Err(nom::Err::Error((rem, err))) => {
                        SCLogNotice!("Suricata interprets an error while parsing the response: {:?}", err);
                        SCLogNotice!("Unparsed input is: {:?}", rem);
                        return AppLayerResult::err();
                    }
                    Err(_) => {
                        SCLogNotice!("Suricata interprets another error while parsing the response");
                        return AppLayerResult::err();
                    }
                }
            }
        }

        // All input was fully consumed.
        SCLogNotice!("Suricata interprets we're done with the input");
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
    SCLogNotice!("We are in probe_ts");
    parser::parse_request(input).is_ok()
}

/// Probe for a valid PostgreSQL response
///
/// PGSQL messages don't have a header per se, so we parse the slice for an ok()
/// Doesn't probe for SSL responses, at the moment
fn probe_tc(input: &[u8]) -> bool {
    SCLogNotice!("We are in probe_tc");
    if parser::pgsql_parse_response(input).is_ok() ||
        parser::parse_ssl_response(input).is_ok() {
        return true;
        }
    SCLogNotice!("probe_tc is false");
    false
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
    let tx_safe: &mut PgsqlTransaction;
    unsafe { tx_safe = cast_pointer!(tx, PgsqlTransaction); }
    return tx_safe.tx_state;
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
        tx_comp_st_ts: PgsqlTransactionState::ResponseDone as i32,
        tx_comp_st_tc: PgsqlTransactionState::ResponseDone as i32,
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
    }

    #[test]
    fn test_request_events() {
        let mut state = PgsqlState::new();
        // an SSL Request
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        state.parse_request(buf);
        let ok_state = PgsqlStateProgress::SslRequestReceived;

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

    #[test]
    fn test_find_or_create_tx() {
        let mut state = PgsqlState::new();
        state.state_progress = PgsqlStateProgress::UnknownState;
        let tx = state.find_or_create_tx();
        assert_eq!(tx.is_none(), true);

        let tx = state.find_or_create_tx();
        assert_eq!(tx.is_none(), true);

        state.state_progress = PgsqlStateProgress::IdleState;
        let tx = state.find_or_create_tx();
        assert_eq!(tx.is_some(), true);

        // Now, even though there isn't a new transaction created, the previous one is available
        state.state_progress = PgsqlStateProgress::SSLRejectedReceived;
        let tx = state.find_or_create_tx();
        assert_eq!(tx.is_none(), false);
        assert_eq!(tx.unwrap().tx_id, 1);
    }
}
