/* Copyright (C) 2018-2022 Open Information Security Foundation
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

// Author: Alex Savage <alexander.savage@cyber.gc.ca>
use crate::applayer::{self, *};
use crate::core::{AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use std;
use std::collections::VecDeque;
use std::ffi::CString;

use sawp::error::Error as SawpError;
use sawp::error::ErrorKind as SawpErrorKind;
use sawp::parser::Direction;
use sawp::parser::Parse;
use sawp::probe::Probe;
use sawp::probe::Status;
use sawp_pop3::{self, Command, ErrorFlag, Flag, Flags, InnerMessage, Response};

pub const POP3_PARSER: sawp_pop3::POP3 = sawp_pop3::POP3 {};
static mut ALPROTO_POP3: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum POP3Event {}

pub struct POP3Transaction {
    tx_id: u64,
    pub error_flags: Flags<ErrorFlag>,
    pub request: Option<Command>,
    pub response: Option<Response>,

    tx_data: AppLayerTxData,
}

impl POP3Transaction {
    pub fn new(tx_id: u64) -> POP3Transaction {
        POP3Transaction {
            tx_id,
            error_flags: ErrorFlag::none(),
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for POP3Transaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

pub struct POP3State {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<POP3Transaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<POP3Transaction> for POP3State {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&POP3Transaction> {
        self.transactions.get(index)
    }
}

impl POP3State {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            request_gap: false,
            response_gap: false,
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self.transactions.iter().position(|tx| tx.id() == tx_id + 1) {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&self, tx_id: u64) -> Option<&POP3Transaction> {
        self.transactions.iter().find(|tx| tx.id() == tx_id + 1)
    }

    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut POP3Transaction> {
        self.transactions.iter_mut().find(|tx| tx.id() == tx_id + 1)
    }

    fn new_tx(&mut self) -> POP3Transaction {
        self.tx_id += 1;
        POP3Transaction::new(self.tx_id)
    }

    fn find_request(&mut self) -> Option<&mut POP3Transaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            unsafe {
                if probe(input) != ALPROTO_POP3 {
                    // The parser now needs to decide what to do as we are not in sync.
                    // For this pop3, we'll just try again next time.
                    return AppLayerResult::ok();
                }
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match POP3_PARSER.parse(start, Direction::ToServer) {
                Ok((rem, Some(msg))) => {
                    if let InnerMessage::Command(request) = msg.inner {
                        let mut tx = self.new_tx();
                        tx.error_flags |= msg.error_flags;
                        tx.request = Some(request);
                        self.transactions.push_back(tx);
                    }

                    start = rem;
                }
                Ok((rem, None)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.

                    let consumed = input.len() - rem.len();
                    let needed = rem.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(SawpError {
                    kind: SawpErrorKind::Incomplete(sawp::error::Needed::Size(needed)),
                }) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + needed.get();
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => return AppLayerResult::err(),
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            unsafe {
                if probe(input) != ALPROTO_POP3 {
                    // The parser now needs to decide what to do as we are not in sync.
                    // For this pop3, we'll just try again next time.
                    return AppLayerResult::ok();
                }
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match POP3_PARSER.parse(start, Direction::ToClient) {
                Ok((rem, Some(msg))) => {
                    if let InnerMessage::Response(response) = msg.inner {
                        let mut tx = if let Some(tx) = self.find_request() {
                            tx
                        } else {
                            // Server sends greeting before any requests
                            let tx = self.new_tx();
                            let tx_id = tx.id();
                            self.transactions.push_back(tx);
                            self.get_tx_mut(tx_id - 1).unwrap()
                        };

                        tx.error_flags |= msg.error_flags;
                        tx.response = Some(response);
                    }
                    start = rem;
                }
                Ok((rem, None)) => {
                    let consumed = input.len() - rem.len();
                    let needed = rem.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(SawpError {
                    kind: SawpErrorKind::Incomplete(sawp::error::Needed::Size(needed)),
                }) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + needed.get();
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => return AppLayerResult::err(),
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
/// As this pop3 protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> AppProto {
    match POP3_PARSER.probe(input, Direction::Unknown) {
        Status::Recognized => unsafe { ALPROTO_POP3 },
        Status::Incomplete => ALPROTO_UNKNOWN,
        Status::Unrecognized => unsafe { ALPROTO_FAILED },
    }
}

// C exports.

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_pop3_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 2 bytes.
    let slice = build_slice!(input, input_len as usize);
    probe(slice)
}

#[no_mangle]
pub extern "C" fn rs_pop3_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = POP3State::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut std::os::raw::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut POP3State));
}

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, POP3State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_parse_request(
    _flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, POP3State);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_parse_response(
    _flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, POP3State);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, POP3State);
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
pub unsafe extern "C" fn rs_pop3_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, POP3State);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, POP3Transaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_pop3_get_tx_data, POP3Transaction);
export_state_data_get!(rs_pop3_get_state_data, POP3State);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"pop3\0";

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_register_parser() {
    let default_port = CString::new("[110]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_pop3_probing_parser),
        probe_tc: Some(rs_pop3_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_pop3_state_new,
        state_free: rs_pop3_state_free,
        tx_free: rs_pop3_state_tx_free,
        parse_ts: rs_pop3_parse_request,
        parse_tc: rs_pop3_parse_response,
        get_tx_count: rs_pop3_state_get_tx_count,
        get_tx: rs_pop3_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_pop3_tx_get_alstate_progress,
        get_eventinfo: Some(POP3Event::get_event_info),
        get_eventinfo_byid: Some(POP3Event::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<POP3State, POP3Transaction>),
        get_tx_data: rs_pop3_get_tx_data,
        get_state_data: rs_pop3_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_POP3 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sawp_pop3::*; // TODO more specific

    const CLIENT_COMMAND_UNKNOWN_KEYWORD: &[u8] = b"HELLO WORLD\r\n";
    const CLIENT_COMMAND_INVALID_KEYWORD: &[u8] = b"\x01\x01\x02\x03 WORLD\r\n";
    const CLIENT_COMMAND_MISSING_ARGUMENT: &[u8] = b"DELE\r\n";
    const CLIENT_COMMAND_INVALID_ARGUMENT: &[u8] = b"CAPA HELLO WORLD\r\n";
    const CLIENT_COMMAND_NO_ARGS: &[u8] = b"CAPA\r\n";
    const CLIENT_COMMAND_ONE_ARG: &[u8] = b"DELE 52\r\n";
    const CLIENT_COMMAND_TWO_ARGS: &[u8] = b"APOP sawp 05aaf79d37225973a0r0cddaaf568eb96\r\n";
    const CLIENT_COMMAND_TOO_LONG: &[u8] =
        b"PASS 12345678901234567890123456789012345678901234567890\
        123456789012345678901234567890123456789012345678901234567890\
        123456789012345678901234567890123456789012345678901234567890\
        123456789012345678901234567890123456789012345678901234567890\
        123456789012345678901234567890123456789012345678901234567890\r\n";

    #[test]
    fn test_command_empty() {
        let mut state = POP3State::new();
        assert_eq!(AppLayerResult::ok(), state.parse_request(b""));
        assert_eq!(state.get_transaction_count(), 0);
    }

    #[test]
    fn test_command_unknown_keyword() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_UNKNOWN_KEYWORD)
        );

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::UnknownKeyword);

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::Unknown("HELLO".into()));
        assert_eq!(request.args.len(), 1);
        assert_eq!(&request.args[0], b"WORLD");
    }

    #[test]
    fn test_command_invalid_keyword() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::err(),
            state.parse_request(CLIENT_COMMAND_INVALID_KEYWORD)
        );
    }

    #[test]
    fn test_command_missing_argument() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_MISSING_ARGUMENT)
        );

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::IncorrectArgumentNum);

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::DELE);
        assert!(request.args.is_empty());
    }

    #[test]
    fn test_command_invalid_argument() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_INVALID_ARGUMENT)
        );

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::IncorrectArgumentNum);

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::CAPA);
        assert_eq!(request.args.len(), 2);
        assert_eq!(&request.args[0], b"HELLO");
        assert_eq!(&request.args[1], b"WORLD");
    }

    #[test]
    fn test_command_too_long() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_TOO_LONG)
        );

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::CommandTooLong);

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::PASS);
        assert_eq!(request.args.len(), 1);
    }

    #[test]
    fn test_command_no_args() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_NO_ARGS)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::CAPA);
        assert!(request.args.is_empty());
    }

    #[test]
    fn test_command_one_arg() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_ONE_ARG)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::DELE);
        assert_eq!(request.args.len(), 1);
        assert_eq!(&request.args[0], b"52");
    }

    #[test]
    fn test_command_two_args() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_TWO_ARGS)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::APOP);
        assert_eq!(request.args.len(), 2);
        assert_eq!(&request.args[0], b"sawp");
        assert_eq!(&request.args[1], b"05aaf79d37225973a0r0cddaaf568eb96");
    }

    const SERVER_RESPONSE: &[u8] = b"+OK 2 200\r\n";
    const SERVER_RESPONSE_MULTILINE: &[u8] =
        b"+OK Capability list follows\r\nTOP\r\nUSER\r\nUIDL\r\n.\r\n";
    const SERVER_RESPONSE_MULTILINE_BYTE_STUFFING: &[u8] = b"+OK 120 octets\r\n\
    Grocery list:\r\n\
    ..6kg of flour\r\n\
    .\r\n";
    const SERVER_RESPONSE_TOO_LONG: &[u8] =
        b"-ERR 12345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890 \
    123456789012345678901234567890123456789012345678901234567890\r\n";
    const SERVER_RESPONSE_INVALID_STATUS: &[u8] = b"+SUCCESS 2 200\r\n";

    #[test]
    fn test_server_response() {
        let mut state = POP3State::new();
        assert_eq!(AppLayerResult::ok(), state.parse_response(SERVER_RESPONSE));
        assert_eq!(state.transactions.len(), 1);

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.response.is_some());
        let response = &tx.response.as_ref().unwrap();
        assert_eq!(response.status, sawp_pop3::Status::OK);
        assert_eq!(&response.header, b"2 200");
        assert!(&response.data.is_empty());
    }

    #[test]
    fn test_server_response_multiline() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_response(SERVER_RESPONSE_MULTILINE)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.response.is_some());
        let response = &tx.response.as_ref().unwrap();
        assert_eq!(response.status, sawp_pop3::Status::OK);
        assert_eq!(&response.header, b"Capability list follows");
        assert_eq!(response.data.len(), 3);
        assert_eq!(&response.data[0], b"TOP");
        assert_eq!(&response.data[1], b"USER");
        assert_eq!(&response.data[2], b"UIDL");
    }

    #[test]
    fn test_server_response_multline_byte_stuffing() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_response(SERVER_RESPONSE_MULTILINE_BYTE_STUFFING)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.response.is_some());
        let response = &tx.response.as_ref().unwrap();
        assert_eq!(response.status, sawp_pop3::Status::OK);
        assert_eq!(&response.header, b"120 octets");
        assert_eq!(response.data.len(), 2);
        assert_eq!(&response.data[0], b"Grocery list:");
        assert_eq!(&response.data[1], b".6kg of flour");
    }

    #[test]
    fn test_server_response_too_long() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_response(SERVER_RESPONSE_TOO_LONG)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::ResponseTooLong);

        assert!(tx.response.is_some());
        let response = &tx.response.as_ref().unwrap();
        assert_eq!(response.status, sawp_pop3::Status::ERR);
        assert_eq!(
            &response.header,
            b"12345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890 \
        123456789012345678901234567890123456789012345678901234567890"
        );
        assert!(response.data.is_empty());
    }

    #[test]
    fn test_server_invalid_status() {
        let mut state = POP3State::new();
        assert_eq!(
            AppLayerResult::err(),
            state.parse_response(SERVER_RESPONSE_INVALID_STATUS)
        );
    }

    #[test]
    fn test_request_response_matching() {
        let mut state = POP3State::new();
        assert_eq!(AppLayerResult::ok(), state.parse_response(SERVER_RESPONSE));
        assert_eq!(state.transactions.len(), 1);
        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.request.is_none());
        assert!(tx.response.is_some());
        let response = &tx.response.as_ref().unwrap();
        assert_eq!(response.status, sawp_pop3::Status::OK);
        assert_eq!(&response.header, b"2 200");
        assert!(&response.data.is_empty());

        assert_eq!(
            AppLayerResult::ok(),
            state.parse_request(CLIENT_COMMAND_NO_ARGS)
        );
        assert_eq!(
            AppLayerResult::ok(),
            state.parse_response(SERVER_RESPONSE_MULTILINE)
        );
        assert_eq!(state.transactions.len(), 2);
        let tx = state.get_tx(1).unwrap();
        assert_eq!(tx.error_flags, ErrorFlag::none());

        assert!(tx.request.is_some());
        let request = &tx.request.as_ref().unwrap();
        assert_eq!(request.keyword, Keyword::CAPA);

        assert!(tx.response.is_some());
        let response = &tx.response.as_ref().unwrap();
        assert_eq!(response.status, sawp_pop3::Status::OK);
        assert_eq!(&response.header, b"Capability list follows");
        assert_eq!(response.data.len(), 3);
        assert_eq!(&response.data[0], b"TOP");
        assert_eq!(&response.data[1], b"USER");
        assert_eq!(&response.data[2], b"UIDL");
    }
}
