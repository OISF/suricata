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
use crate::core::{self, ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};
use std::mem::transmute;
use crate::applayer::{self, *};
use std::ffi::CString;
use nom;
use parser::{PgsqlGenericStartupMessage, PgsqlSslResponse};
use std::fmt;
use super::parser;
use nom::error::{ErrorKind, ParseError};

static mut ALPROTO_POSTGRESQL: AppProto = ALPROTO_UNKNOWN;

#[derive(Debug)]
pub enum PGSQLError {
    MalformedData,
    NotEnoughData, // not sure about this
    StreamTooSmall, // not sure about this 
    UnknownError, // TODO should this exist?
    NomError(ErrorKind),
}

impl<I> ParseError<I> for PGSQLError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        PGSQLError::NomError(kind)
    }

    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        PGSQLError::NomError(kind)
    }
}

impl fmt::Display for PGSQLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PGSQLError::MalformedData => f.write_str("Malformed data"),
            PGSQLError::NotEnoughData => f.write_str("Not enough data"),
            PGSQLError::StreamTooSmall => f.write_str("Stream is too small"),
            PGSQLError::UnknownError => f.write_str("Unknown error"),
            PGSQLError::NomError(ref inner) => f.write_str(inner.description()),
        }
    }
}

pub struct PGSQLTransaction {
    tx_id: u64,
    pub request: Option<PgsqlGenericStartupMessage>, // TODO implement a struct generic enough to fit all requests here 
    pub response: Option<PgsqlSslResponse>, // TODO implement a struct generic enough to fit all responses here

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
    is_ssl_handshake: bool,
}

impl PGSQLTransaction {
    pub fn new() -> PGSQLTransaction {
        PGSQLTransaction {
            tx_id: 0,
            request: None,
            response: None,
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
            is_ssl_handshake: false, // TODO not sure if this will be useful or necessary, yet
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

impl Drop for PGSQLTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct PGSQLState {
    tx_id: u64,
    transactions: Vec<PGSQLTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl PGSQLState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            request_gap: false,
            response_gap: false,
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&PGSQLTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> PGSQLTransaction {
        let mut tx = PGSQLTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut PGSQLTransaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        // TODO: do I have to change this ok() to something else?
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            SCLogNotice!("Pgsql parser detected a gap.");
            if probe_request(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this pgsql, we'll just try again next time.
                // TODO to implement
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while start.len() > 0 {
            match parser::parse_request_message(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request is: {}", &request);
                    let mut tx = self.new_tx();
                    
                    if request.message_type == parser::PgsqlStartupMessageType::SslRequest {
                        tx.is_ssl_handshake = true;
                    }
                    tx.request = Some(request);
                    self.transactions.push(tx);
                },
                Err(nom::Err::Incomplete(needed)) => {
                    // Not enough data. This parser doesn't give us a good indication yet
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    // TODO print the incomplete

                    if let nom::Needed::Size(n) = needed {
                        SCLogDebug!("Not enough data for request message {:?}", needed);
                        let need = n;
                        let consumed = input.len() - start.len();
                        return AppLayerResult::incomplete(consumed as u32, need as u32);
                    }
                    return AppLayerResult::err();
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

        SCLogNotice!("Parsing response...");
        let mut start = input;
        while start.len() > 0 {
            match parser::parse_response_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    match self.find_request() {
                        Some(tx) => {
                            tx.response = Some(response);
                            SCLogNotice!("Found response for request:");
                            SCLogNotice!("- Request: {:?}", tx.request);
                            SCLogNotice!("- Response: {:?}", tx.response);
                        }
                        None => {}
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

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&PGSQLTransaction, u64, bool)> {
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

/// Probe for a valid request.
fn probe_request(input: &[u8]) -> nom::IResult<&[u8], PgsqlGenericStartupMessage> {
    SCLogNotice!("Probing request...");
    parser::parse_ssl_request(&input)
}

/// Probe for a valid response
fn probe_response(input: &[u8]) -> nom::IResult<&[u8], PgsqlSslResponse> {
    SCLogNotice!("Probing response...");
    // TODO adapt this!!
    parser::parse_ssl_response(&input)
}

// C exports.

export_tx_get_detect_state!(
    rs_pgsql_tx_get_detect_state,
    PGSQLTransaction
);
export_tx_set_detect_state!(
    rs_pgsql_tx_set_detect_state,
    PGSQLTransaction
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
    // Need at least 2 bytes.
    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe_request(slice).is_ok() {
            SCLogNotice!("Probing request: ok");
            return unsafe { ALPROTO_POSTGRESQL };
        }
    }
    return ALPROTO_UNKNOWN;
}

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
        if probe_response(slice).is_ok() {
            SCLogNotice!("Probing response: ok");
            return unsafe { ALPROTO_POSTGRESQL };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = PGSQLState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<PGSQLState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, PGSQLState);
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
        // If needed, handled EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, PGSQLState);

    if input == std::ptr::null_mut() && input_len > 0 {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(input_len);
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_request(buf).into() // TODO What's the difference between using this or not?
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
    let state = cast_pointer!(state, PGSQLState);

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
    let state = cast_pointer!(state, PGSQLState);
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
    let state = cast_pointer!(state, PGSQLState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, PGSQLTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_events(
    tx: *mut std::os::raw::c_void
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, PGSQLTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

// TODO understand this
#[no_mangle]
pub extern "C" fn rs_pgsql_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
                                                         _event_name: *mut *const std::os::raw::c_char,
                                                         _event_type: *mut core::AppLayerEventType
) -> i8 {
    return -1;
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
    let state = cast_pointer!(state, PGSQLState);
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

// TODO these two are commented because I'm not sure yet how to make this happen with my data types

// Get the request buffer for a transaction from C.
//
// No required for parsing, but an example function for retrieving a
// pointer to the request buffer from C for detection.
// #[no_mangle]
// pub extern "C" fn rs_pgsql_get_request_buffer(
//     tx: *mut std::os::raw::c_void,
//     buf: *mut *const u8,
//     len: *mut u32,
// ) -> u8
// {   //TODO I'm not sure how would I use this, yet. Should I pass the message length field?
//     let tx = cast_pointer!(tx, PGSQLTransaction);
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

// Get the response buffer for a transaction from C.
// #[no_mangle]
// pub extern "C" fn rs_pgsql_get_response_buffer(
//     tx: *mut std::os::raw::c_void,
//     buf: *mut *const u8,
//     len: *mut u32,
// ) -> u8
// { //TODO will I need this? How can I adapt it?
//     let tx = cast_pointer!(tx, PGSQLTransaction);
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

export_tx_data_get!(rs_pgsql_get_tx_data, PGSQLTransaction);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"postgresql\0";

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
        max_depth: 16, //TODO find out what should be the max depth
        state_new: rs_pgsql_state_new,
        state_free: rs_pgsql_state_free,
        tx_free: rs_pgsql_state_tx_free,
        parse_ts: rs_pgsql_parse_request,
        parse_tc: rs_pgsql_parse_response,
        get_tx_count: rs_pgsql_state_get_tx_count,
        get_tx: rs_pgsql_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
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
        ALPROTO_POSTGRESQL = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust PostgreSQL parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for PostgreSQL.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe_ssl_request() {

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        let res = probe_request(&buf);
        assert!(res.is_ok());

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x30];
        let res = probe_request(&buf);
        assert!(res.is_err());

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2];
        let res = probe_request(&buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_probe_ssl_response() {
        // 'S'
        let buf: &[u8] = &[0x53];
        let res = probe_response(&buf);
        assert!(res.is_ok());

        // 'N'
        let buf: &[u8] = &[0x4e];
        let res = probe_response(&buf);
        assert!(res.is_ok());

        let buf: &[u8] = &[0x30];
        let res = probe_response(&buf);
        assert!(res.is_err());

        let buf: &[u8] = &[0x30, 0x31];
        let res = probe_response(&buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_incomplete_request() {
        let mut state = PGSQLState::new();
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

        // If we have nothing, we shouldn't be able to parse anything
        let r = state.parse_request(&buf[0..0]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 4});

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 4});

        // Ok, length (4 bytes) parsed. Expects 2 bytes for proto version major
        let r = state.parse_request(&buf[0..5]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 2});

        // Now, missing 2 bytes for proto version min
        let r = state.parse_request(&buf[0..7]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 2});        
    }

    #[test]
    fn test_ssl_response() {
        let mut state = PGSQLState::new();
        // 'S'
        let buf: &[u8] = &[0x53];
        let r = state.parse_response(&buf);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        // 'N'
        let buf: &[u8] = &[0x4e];
        let r = state.parse_response(&buf);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        // this is an invalid character here
        let buf: &[u8] = &[0x30];
        let r = state.parse_response(&buf);
        assert_eq!(r, AppLayerResult{ status: -1, consumed: 0, needed: 0});        
    }
}
