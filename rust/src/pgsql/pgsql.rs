/* Copyright (C) 2022 Open Information Security Foundation
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

// Author: Juliana Fajardini <jufajardini@oisf.net>

//! PostgreSQL parser

use super::parser::{self, ConsolidatedDataRowPacket, PgsqlBEMessage, PgsqlFEMessage};
use crate::applayer::*;
use crate::conf::*;
use crate::core::{AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use nom7::{Err, IResult};
use std;
use std::collections::VecDeque;
use std::ffi::CString;

pub const PGSQL_CONFIG_DEFAULT_STREAM_DEPTH: u32 = 0;

static mut ALPROTO_PGSQL: AppProto = ALPROTO_UNKNOWN;

static mut PGSQL_MAX_TX: usize = 1024;

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Debug)]
pub enum PgsqlTransactionState {
    Init = 0,
    RequestReceived,
    ResponseDone,
    FlushedOut,
}

#[derive(Debug)]
pub struct PgsqlTransaction {
    pub tx_id: u64,
    pub tx_state: PgsqlTransactionState,
    pub request: Option<PgsqlFEMessage>,
    pub responses: Vec<PgsqlBEMessage>,

    pub data_row_cnt: u16,
    pub data_size: u64,

    tx_data: AppLayerTxData,
}

impl Transaction for PgsqlTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

impl PgsqlTransaction {
    pub fn new() -> PgsqlTransaction {
        PgsqlTransaction {
            tx_id: 0,
            tx_state: PgsqlTransactionState::Init,
            request: None,
            responses: Vec::<PgsqlBEMessage>::new(),
            data_row_cnt: 0,
            data_size: 0,
            tx_data: AppLayerTxData::new(),
        }
    }

    pub fn incr_row_cnt(&mut self) {
        self.data_row_cnt += 1;
    }

    pub fn get_row_cnt(&self) -> u16 {
        self.data_row_cnt
    }

    pub fn sum_data_size(&mut self, row_size: u64) {
        self.data_size += row_size;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgsqlStateProgress {
    IdleState,
    SSLRequestReceived,
    SSLAcceptedReceived,
    SSLRejectedReceived,
    StartupMessageReceived,
    SASLAuthenticationReceived,
    SASLInitialResponseReceived,
    // SSPIAuthenticationReceived, // TODO implement
    SASLResponseReceived,
    SASLAuthenticationContinueReceived,
    SASLAuthenticationFinalReceived,
    SimpleAuthenticationReceived,
    PasswordMessageReceived,
    AuthenticationOkReceived,
    ParameterSetup,
    BackendKeyReceived,
    ReadyForQueryReceived,
    SimpleQueryReceived,
    RowDescriptionReceived,
    DataRowReceived,
    CommandCompletedReceived,
    ErrorMessageReceived,
    ConnectionTerminated,
    UnknownState,
    Finished,
}

#[derive(Debug)]
pub struct PgsqlState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<PgsqlTransaction>,
    request_gap: bool,
    response_gap: bool,
    backend_secret_key: u32,
    backend_pid: u32,
    state_progress: PgsqlStateProgress,
    tx_index_completed: usize,
}

impl State<PgsqlTransaction> for PgsqlState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&PgsqlTransaction> {
        self.transactions.get(index)
    }
}

impl PgsqlState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            request_gap: false,
            response_gap: false,
            backend_secret_key: 0,
            backend_pid: 0,
            state_progress: PgsqlStateProgress::IdleState,
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
            self.tx_index_completed = 0;
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
        SCLogDebug!("Creating new transaction. tx_id: {}", tx.tx_id);
        if self.transactions.len() > unsafe { PGSQL_MAX_TX } + self.tx_index_completed {
            // If there are too many open transactions,
            // mark the earliest ones as completed, and take care
            // to avoid quadratic complexity
            let mut index = self.tx_index_completed;
            for tx_old in &mut self.transactions.range_mut(self.tx_index_completed..) {
                index += 1;
                if tx_old.tx_state < PgsqlTransactionState::ResponseDone {
                    tx_old.tx_state = PgsqlTransactionState::FlushedOut;
                    //TODO set event
                    break;
                }
            }
            self.tx_index_completed = index;
        }
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
        if self.state_progress == PgsqlStateProgress::IdleState
            || self.state_progress == PgsqlStateProgress::StartupMessageReceived
            || self.state_progress == PgsqlStateProgress::PasswordMessageReceived
            || self.state_progress == PgsqlStateProgress::SASLInitialResponseReceived
            || self.state_progress == PgsqlStateProgress::SASLResponseReceived
            || self.state_progress == PgsqlStateProgress::SimpleQueryReceived
            || self.state_progress == PgsqlStateProgress::SSLRequestReceived
            || self.state_progress == PgsqlStateProgress::ConnectionTerminated
        {
            let tx = self.new_tx();
            self.transactions.push_back(tx);
        }
        // If we don't need a new transaction, just return the current one
        SCLogDebug!("find_or_create state is {:?}", &self.state_progress);
        return self.transactions.back_mut();
    }

    /// Process State progress to decide if PgsqlTransaction is finished
    ///
    /// As Pgsql transactions are bidirectional and may be comprised of several
    /// responses, we must track State progress to decide on tx completion
    fn is_tx_completed(&self) -> bool {
        if let PgsqlStateProgress::ReadyForQueryReceived
        | PgsqlStateProgress::SSLAcceptedReceived
        | PgsqlStateProgress::SSLRejectedReceived
        | PgsqlStateProgress::SimpleAuthenticationReceived
        | PgsqlStateProgress::SASLAuthenticationReceived
        | PgsqlStateProgress::SASLAuthenticationContinueReceived
        | PgsqlStateProgress::SASLAuthenticationFinalReceived
        | PgsqlStateProgress::ConnectionTerminated
        | PgsqlStateProgress::Finished = self.state_progress
        {
            true
        } else {
            false
        }
    }

    /// Define PgsqlState progression, based on the request received
    ///
    /// As PostgreSQL transactions can have multiple messages, State progression
    /// is what helps us keep track of the PgsqlTransactions - when one finished
    /// when the other starts.
    /// State isn't directly updated to avoid reference borrowing conflicts.
    fn request_next_state(request: &PgsqlFEMessage) -> Option<PgsqlStateProgress> {
        match request {
            PgsqlFEMessage::SSLRequest(_) => Some(PgsqlStateProgress::SSLRequestReceived),
            PgsqlFEMessage::StartupMessage(_) => Some(PgsqlStateProgress::StartupMessageReceived),
            PgsqlFEMessage::PasswordMessage(_) => Some(PgsqlStateProgress::PasswordMessageReceived),
            PgsqlFEMessage::SASLInitialResponse(_) => {
                Some(PgsqlStateProgress::SASLInitialResponseReceived)
            }
            PgsqlFEMessage::SASLResponse(_) => Some(PgsqlStateProgress::SASLResponseReceived),
            PgsqlFEMessage::SimpleQuery(_) => {
                SCLogDebug!("Match: SimpleQuery");
                Some(PgsqlStateProgress::SimpleQueryReceived)
                // TODO here we may want to save the command that was received, to compare that later on when we receive command completed?

                // Important to keep in mind that: "In simple Query mode, the format of retrieved values is always text, except when the given command is a FETCH from a cursor declared with the BINARY option. In that case, the retrieved values are in binary format. The format codes given in the RowDescription message tell which format is being used." (from pgsql official documentation)
            }
            PgsqlFEMessage::Terminate(_) => {
                SCLogDebug!("Match: Terminate message");
                Some(PgsqlStateProgress::ConnectionTerminated)
            }
        }
    }

    fn state_based_req_parsing(
        state: PgsqlStateProgress, input: &[u8],
    ) -> IResult<&[u8], parser::PgsqlFEMessage> {
        match state {
            PgsqlStateProgress::SASLAuthenticationReceived => {
                parser::parse_sasl_initial_response(input)
            }
            PgsqlStateProgress::SASLInitialResponseReceived
            | PgsqlStateProgress::SASLAuthenticationContinueReceived => {
                parser::parse_sasl_response(input)
            }
            PgsqlStateProgress::SimpleAuthenticationReceived => {
                parser::parse_password_message(input)
            }
            _ => parser::parse_request(input),
        }
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if !probe_ts(input) {
                // The parser now needs to decide what to do as we are not in sync.
                // For now, we'll just try again next time.
                SCLogDebug!("Suricata interprets there's a gap in the request");
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with the message header
            // clear gap state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            SCLogDebug!(
                "In 'parse_request' State Progress is: {:?}",
                &self.state_progress
            );
            match PgsqlState::state_based_req_parsing(self.state_progress, start) {
                Ok((rem, request)) => {
                    start = rem;
                    if let Some(state) = PgsqlState::request_next_state(&request) {
                        self.state_progress = state;
                    };
                    let tx_completed = self.is_tx_completed();
                    if let Some(tx) = self.find_or_create_tx() {
                        tx.request = Some(request);
                        if tx_completed {
                            tx.tx_state = PgsqlTransactionState::ResponseDone;
                        }
                    } else {
                        // If there isn't a new transaction, we'll consider Suri should move on
                        return AppLayerResult::ok();
                    };
                }
                Err(Err::Incomplete(_needed)) => {
                    let consumed = input.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogDebug!(
                        "Needed: {:?}, estimated needed: {:?}",
                        _needed,
                        needed_estimation
                    );
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    /// When the state changes based on a specific response, there are other actions we may need to perform
    ///
    /// If there is data from the backend message that Suri should store separately in the State or
    /// Transaction, that is also done here
    fn response_process_next_state(
        &mut self, response: &PgsqlBEMessage, f: *const Flow,
    ) -> Option<PgsqlStateProgress> {
        match response {
            PgsqlBEMessage::SSLResponse(parser::SSLResponseMessage::SSLAccepted) => {
                SCLogDebug!("SSL Request accepted");
                unsafe {
                    AppLayerRequestProtocolTLSUpgrade(f);
                }
                Some(PgsqlStateProgress::Finished)
            }
            PgsqlBEMessage::SSLResponse(parser::SSLResponseMessage::SSLRejected) => {
                SCLogDebug!("SSL Request rejected");
                Some(PgsqlStateProgress::SSLRejectedReceived)
            }
            PgsqlBEMessage::AuthenticationSASL(_) => {
                Some(PgsqlStateProgress::SASLAuthenticationReceived)
            }
            PgsqlBEMessage::AuthenticationSASLContinue(_) => {
                Some(PgsqlStateProgress::SASLAuthenticationContinueReceived)
            }
            PgsqlBEMessage::AuthenticationSASLFinal(_) => {
                Some(PgsqlStateProgress::SASLAuthenticationFinalReceived)
            }
            PgsqlBEMessage::AuthenticationOk(_) => {
                Some(PgsqlStateProgress::AuthenticationOkReceived)
            }
            PgsqlBEMessage::ParameterStatus(_) => Some(PgsqlStateProgress::ParameterSetup),
            PgsqlBEMessage::BackendKeyData(_) => {
                let backend_info = response.get_backendkey_info();
                self.backend_pid = backend_info.0;
                self.backend_secret_key = backend_info.1;
                Some(PgsqlStateProgress::BackendKeyReceived)
            }
            PgsqlBEMessage::ReadyForQuery(_) => Some(PgsqlStateProgress::ReadyForQueryReceived),
            // TODO should we store any Parameter Status in PgsqlState?
            PgsqlBEMessage::AuthenticationMD5Password(_)
            | PgsqlBEMessage::AuthenticationCleartextPassword(_) => {
                Some(PgsqlStateProgress::SimpleAuthenticationReceived)
            }
            PgsqlBEMessage::RowDescription(_) => Some(PgsqlStateProgress::RowDescriptionReceived),
            PgsqlBEMessage::ConsolidatedDataRow(msg) => {
                // Increment tx.data_size here, since we know msg type, so that we can later on log that info
                self.transactions.back_mut()?.sum_data_size(msg.data_size);
                Some(PgsqlStateProgress::DataRowReceived)
            }
            PgsqlBEMessage::CommandComplete(_) => {
                // TODO Do we want to compare the command that was stored when
                // query was sent with what we received here?
                Some(PgsqlStateProgress::CommandCompletedReceived)
            }
            PgsqlBEMessage::ErrorResponse(_) => Some(PgsqlStateProgress::ErrorMessageReceived),
            _ => {
                // We don't always have to change current state when we see a response...
                None
            }
        }
    }

    fn state_based_resp_parsing(
        state: PgsqlStateProgress, input: &[u8],
    ) -> IResult<&[u8], parser::PgsqlBEMessage> {
        if state == PgsqlStateProgress::SSLRequestReceived {
            parser::parse_ssl_response(input)
        } else {
            parser::pgsql_parse_response(input)
        }
    }

    fn parse_response(&mut self, input: &[u8], flow: *const Flow) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if !probe_tc(input) {
                // Out of sync, we'll just try again next time.
                SCLogDebug!("Suricata interprets there's a gap in the response");
                return AppLayerResult::ok();
            }

            // It seems we're in sync with a message header, clear gap state and keep parsing.
            self.response_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match PgsqlState::state_based_resp_parsing(self.state_progress, start) {
                Ok((rem, response)) => {
                    start = rem;
                    SCLogDebug!("Response is {:?}", &response);
                    if let Some(state) = self.response_process_next_state(&response, flow) {
                        self.state_progress = state;
                    };
                    let tx_completed = self.is_tx_completed();
                    let curr_state = self.state_progress;
                    if let Some(tx) = self.find_or_create_tx() {
                        if curr_state == PgsqlStateProgress::DataRowReceived {
                            tx.incr_row_cnt();
                        } else if curr_state == PgsqlStateProgress::CommandCompletedReceived
                            && tx.get_row_cnt() > 0
                        {
                            // let's summarize the info from the data_rows in one response
                            let dummy_resp =
                                PgsqlBEMessage::ConsolidatedDataRow(ConsolidatedDataRowPacket {
                                    identifier: b'D',
                                    length: tx.get_row_cnt() as u32, // TODO this is ugly. We can probably get rid of `length` field altogether...
                                    row_cnt: tx.get_row_cnt(),
                                    data_size: tx.data_size, // total byte count of all data_row messages combined
                                });
                            tx.responses.push(dummy_resp);
                            tx.responses.push(response);
                        } else {
                            tx.responses.push(response);
                            if tx_completed {
                                tx.tx_state = PgsqlTransactionState::ResponseDone;
                            }
                        }
                    } else {
                        // If there isn't a new transaction, we'll consider Suri should move on
                        return AppLayerResult::ok();
                    };
                }
                Err(Err::Incomplete(_needed)) => {
                    let consumed = input.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogDebug!(
                        "Needed: {:?}, estimated needed: {:?}, start is {:?}",
                        _needed,
                        needed_estimation,
                        &start
                    );
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                }
                Err(_) => {
                    SCLogDebug!("Error while parsing PostgreSQL response");
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

/// Probe for a valid PostgreSQL request
///
/// PGSQL messages don't have a header per se, so we parse the slice for an ok()
fn probe_ts(input: &[u8]) -> bool {
    SCLogDebug!("We are in probe_ts");
    parser::parse_request(input).is_ok()
}

/// Probe for a valid PostgreSQL response
///
/// Currently, for parser usage only. We have a bit more logic in the function
/// used by the engine.
/// PGSQL messages don't have a header per se, so we parse the slice for an ok()
fn probe_tc(input: &[u8]) -> bool {
    if parser::pgsql_parse_response(input).is_ok() || parser::parse_ssl_response(input).is_ok() {
        return true;
    }
    SCLogDebug!("probe_tc is false");
    false
}

// C exports.

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_probing_parser_ts(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 1 && !input.is_null() {

        let slice: &[u8] = build_slice!(input, input_len as usize);
        if probe_ts(slice) {
            return ALPROTO_PGSQL;
        }
    }
    return ALPROTO_UNKNOWN;
}

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_probing_parser_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 1 && !input.is_null() {

        let slice: &[u8] = build_slice!(input, input_len as usize);

        if parser::parse_ssl_response(slice).is_ok() {
            return ALPROTO_PGSQL;
        }

        match parser::pgsql_parse_response(slice) {
            Ok((_, _response)) => {
                return ALPROTO_PGSQL;
            }
            Err(Err::Incomplete(_)) => {
                return ALPROTO_UNKNOWN;
            }
            Err(_e) => {
                return ALPROTO_FAILED;
            }
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = PgsqlState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(unsafe { Box::from_raw(state as *mut PgsqlState) });
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state_safe: &mut PgsqlState;
    unsafe {
        state_safe = cast_pointer!(state, PgsqlState);
    }
    state_safe.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_parse_request(
    _flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    if stream_slice.len() == 0 {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
            SCLogDebug!(" Suricata reached `eof`");
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }


    let state_safe: &mut PgsqlState = cast_pointer!(state, PgsqlState);

    if stream_slice.is_gap() {
        state_safe.on_request_gap(stream_slice.gap_size());
    } else if stream_slice.len() > 0 {
        return state_safe.parse_request(stream_slice.as_slice());
    }
    AppLayerResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_parse_response(
    flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;

    let state_safe: &mut PgsqlState = cast_pointer!(state, PgsqlState);

    if stream_slice.is_gap() {
        state_safe.on_response_gap(stream_slice.gap_size());
    } else if stream_slice.len() > 0 {
        return state_safe.parse_response(stream_slice.as_slice(), flow);
    }
    AppLayerResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state_safe: &mut PgsqlState = cast_pointer!(state, PgsqlState);
    match state_safe.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state_safe: &mut PgsqlState;
    unsafe {
        state_safe = cast_pointer!(state, PgsqlState);
    }
    return state_safe.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_tx_get_state(tx: *mut std::os::raw::c_void) -> PgsqlTransactionState {
    let tx_safe: &mut PgsqlTransaction;
    unsafe {
        tx_safe = cast_pointer!(tx, PgsqlTransaction);
    }
    return tx_safe.tx_state;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    return rs_pgsql_tx_get_state(tx) as i32;
}

export_tx_data_get!(rs_pgsql_get_tx_data, PgsqlTransaction);
export_state_data_get!(rs_pgsql_get_state_data, PgsqlState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"pgsql\0";

#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_register_parser() {
    let default_port = CString::new("[5432]").unwrap();
    let mut stream_depth = PGSQL_CONFIG_DEFAULT_STREAM_DEPTH;
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
        tx_comp_st_ts: PgsqlTransactionState::RequestReceived as i32,
        tx_comp_st_tc: PgsqlTransactionState::ResponseDone as i32,
        tx_get_progress: rs_pgsql_tx_get_alstate_progress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<PgsqlState, PgsqlTransaction>,
        ),
        get_tx_data: rs_pgsql_get_tx_data,
        get_state_data: rs_pgsql_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_PGSQL = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust pgsql parser registered.");
        let retval = conf_get("app-layer.protocols.pgsql.stream-depth");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => {
                    stream_depth = retval as u32;
                }
                Err(_) => {
                    SCLogError!("Invalid depth value");
                }
            }
            AppLayerParserSetStreamDepth(IPPROTO_TCP, ALPROTO_PGSQL, stream_depth)
        }
        if let Some(val) = conf_get("app-layer.protocols.pgsql.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                PGSQL_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for pgsql.max-tx");
            }
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for PGSQL.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_request_probe() {
        // An SSL Request
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        assert!(probe_ts(buf));

        // incomplete messages, probe must return false
        assert!(!probe_ts(&buf[0..6]));
        assert!(!probe_ts(&buf[0..3]));

        // length is wrong (7), probe must return false
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x07, 0x04, 0xd2, 0x16, 0x2f];
        assert!(!probe_ts(buf));

        // A valid startup message/request
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x26, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x6d,
            0x61, 0x69, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x00,
        ];
        assert!(probe_ts(buf));

        // A non valid startup message/request (length is shorter by one. Would `exact!` help?)
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x25, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x6d,
            0x61, 0x69, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x00,
        ];
        assert!(!probe_ts(buf));
    }

    #[test]
    fn test_response_probe() {
        /* Authentication Request MD5 password salt value f211a3ed */
        let buf: &[u8] = &[
            0x52, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0xf2, 0x11, 0xa3, 0xed,
        ];
        assert!(probe_tc(buf));

        /* R  8 -- Authentication Cleartext */
        let buf: &[u8] = &[0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03];
        assert!(probe_tc(buf));

        let buf: &[u8] = &[
            /* R */ 0x52, /* 54 */ 0x00, 0x00, 0x00, 0x36, /* 12 */ 0x00, 0x00,
            0x00, 0x0c, /* signature */ 0x76, 0x3d, 0x64, 0x31, 0x50, 0x58, 0x61, 0x38, 0x54,
            0x4b, 0x46, 0x50, 0x5a, 0x72, 0x52, 0x33, 0x4d, 0x42, 0x52, 0x6a, 0x4c, 0x79, 0x33,
            0x2b, 0x4a, 0x36, 0x79, 0x78, 0x72, 0x66, 0x77, 0x2f, 0x7a, 0x7a, 0x70, 0x38, 0x59,
            0x54, 0x39, 0x65, 0x78, 0x56, 0x37, 0x73, 0x38, 0x3d,
        ];
        assert!(probe_tc(buf));

        /* S   26 -- parameter status application_name psql*/
        let buf: &[u8] = &[
            0x53, 0x00, 0x00, 0x00, 0x1a, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71, 0x6c, 0x00,
        ];
        assert!(probe_tc(buf));
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
        // An SSL Request
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 2
            }
        );

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 3
            }
        );
    }

    #[test]
    fn test_find_or_create_tx() {
        let mut state = PgsqlState::new();
        state.state_progress = PgsqlStateProgress::UnknownState;
        let tx = state.find_or_create_tx();
        assert!(tx.is_none());

        state.state_progress = PgsqlStateProgress::IdleState;
        let tx = state.find_or_create_tx();
        assert!(tx.is_some());

        // Now, even though there isn't a new transaction created, the previous one is available
        state.state_progress = PgsqlStateProgress::SSLRejectedReceived;
        let tx = state.find_or_create_tx();
        assert!(tx.is_some());
        assert_eq!(tx.unwrap().tx_id, 1);
    }

    #[test]
    fn test_row_cnt() {
        let mut tx = PgsqlTransaction::new();
        assert_eq!(tx.get_row_cnt(), 0);

        tx.incr_row_cnt();
        assert_eq!(tx.get_row_cnt(), 1);
    }
}
