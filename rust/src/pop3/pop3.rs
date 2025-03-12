/* Copyright (C) 2025 Open Information Security Foundation
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

use crate::applayer::{self, *};
use crate::conf::conf_get;
use crate::core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::flow::Flow;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::AppProto;

use sawp::error::Error as SawpError;
use sawp::error::ErrorKind as SawpErrorKind;
use sawp::parser::Direction;
use sawp::parser::Parse;
use sawp::probe::Probe;
use sawp::probe::Status;
use sawp_pop3::{self, Command, ErrorFlag, Flag, Flags, InnerMessage, Response};

static mut POP3_MAX_TX: usize = 256;

pub(super) static mut ALPROTO_POP3: AppProto = ALPROTO_UNKNOWN;
const POP3_PARSER: sawp_pop3::POP3 = sawp_pop3::POP3 {};

#[derive(AppLayerEvent)]
enum POP3Event {
    TooManyTransactions,
}

pub struct POP3Transaction {
    tx_id: u64,
    pub error_flags: Flags<ErrorFlag>,
    pub request: Option<Command>,
    pub response: Option<Response>,

    tx_data: AppLayerTxData,
}

impl POP3Transaction {
    pub fn new(tx_id: u64) -> POP3Transaction {
        Self {
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

#[derive(Default)]
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
        Default::default()
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self.transactions.iter().position(|tx| tx.id() == tx_id + 1) {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&POP3Transaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut POP3Transaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.tx_id == tx_id + 1)
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
                    // of how much data is missing so just ask for one more byte so
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

    fn parse_response(&mut self, input: &[u8], flow: *const Flow) -> AppLayerResult {
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
                    if let InnerMessage::Response(mut response) = msg.inner {
                        let tx = if let Some(tx) = self.find_request() {
                            tx
                        } else {
                            // Server sends banner before any requests
                            let tx = self.new_tx();
                            let tx_id = tx.id();
                            self.transactions.push_back(tx);
                            self.get_tx_mut(tx_id - 1).unwrap()
                        };

                        tx.error_flags |= msg.error_flags;

                        if response.status == sawp_pop3::Status::OK && tx.request.is_some() {
                            let request = tx.request.as_ref().unwrap();
                            match &request.keyword {
                                sawp_pop3::Keyword::STLS => {
                                    unsafe { AppLayerRequestProtocolTLSUpgrade(flow) };
                                }
                                sawp_pop3::Keyword::RETR => {
                                    // Don't hold onto the whole email body

                                    // TODO: pass off to mime parser
                                    response.data.clear();
                                }
                                _ => {}
                            }
                        }
                        tx.response = Some(response);
                    }
                    start = rem;
                }
                Ok((rem, None)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so
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

/// Reasonably need at least 5 bytes to determine
/// 3 bytes for short commands like 'TOP' or response '+OK'
/// and 2 bytes for the CRLF.
static MIN_PROBE_LEN: u32 = 5;

/// Probe for a command or response
fn probe(input: &[u8]) -> AppProto {
    // TODO: sawp_pop3 needs to be updated
    match POP3_PARSER.probe(input, Direction::Unknown) {
        Status::Recognized => unsafe { ALPROTO_POP3 },
        Status::Incomplete => ALPROTO_UNKNOWN,
        Status::Unrecognized => ALPROTO_FAILED,
    }
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn rs_pop3_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len < MIN_PROBE_LEN {
        ALPROTO_UNKNOWN
    } else {
        let slice = build_slice!(input, input_len as usize);
        probe(slice)
    }
}

extern "C" fn rs_pop3_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = POP3State::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_pop3_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut POP3State));
}

unsafe extern "C" fn rs_pop3_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, POP3State);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_pop3_parse_request(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
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

unsafe extern "C" fn rs_pop3_parse_response(
    flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
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
        state.parse_response(buf, flow)
    }
}

unsafe extern "C" fn rs_pop3_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
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

unsafe extern "C" fn rs_pop3_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, POP3State);
    return state.tx_id;
}

unsafe extern "C" fn rs_pop3_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, POP3Transaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(pop3_get_tx_data, POP3Transaction);
export_state_data_get!(pop3_get_state_data, POP3State);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"pop3\0";

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_register_parser() {
    let default_port = CString::new("[110]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
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
        get_tx_data: pop3_get_tx_data,
        get_state_data: pop3_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
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
        if let Some(val) = conf_get("app-layer.protocols.pop3.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                POP3_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for pop3.max-tx");
            }
        }
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_POP3);
        SCLogNotice!("Rust pop3 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for POP3.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe() {
        assert!(probe(b"1").is_err());
        assert!(probe(b"1:").is_ok());
        assert!(probe(b"123456789:").is_ok());
        assert!(probe(b"0123456789:").is_err());
    }

    #[test]
    fn test_incomplete() {
        let mut state = POP3State::new();
        let buf = b"5:Hello3:bye";

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

        // This is the first message and only the first message.
        let r = state.parse_request(&buf[0..7]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        // The first message and a portion of the second.
        let r = state.parse_request(&buf[0..9]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 7,
                needed: 3
            }
        );
    }
}
