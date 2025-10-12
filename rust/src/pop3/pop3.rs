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

// Author: Alex Savage <exlavasage@gmail.com>

//! POP3 parser

use crate::applayer::*;
use crate::conf::{conf_get, get_memval};
use crate::core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP, sc_app_layer_parser_trigger_raw_stream_inspection};
use crate::flow::Flow;
use crate::direction;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserSetStreamDepth, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled, SCAppLayerRequestProtocolTLSUpgrade,
};

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
    /// Command + space + argument + CRLF must not exceed 255 octets (RFC 2449)
    RequestTooLong,
    /// Number of arguments doesn't match the command
    IncorrectArgumentCount,
    /// Correct command format, but unknown value
    UnknownCommand,
    /// First line of server response + CRLF must not exceed 512 octets (RFC 2449)
    ResponseTooLong,
}

impl From<ErrorFlag> for POP3Event {
    fn from(flag: ErrorFlag) -> Self {
        match flag {
            ErrorFlag::CommandTooLong => POP3Event::RequestTooLong,
            ErrorFlag::IncorrectArgumentNum => POP3Event::IncorrectArgumentCount,
            ErrorFlag::UnknownKeyword => POP3Event::UnknownCommand,
            ErrorFlag::ResponseTooLong => POP3Event::ResponseTooLong,
        }
    }
}

pub struct POP3Transaction {
    tx_id: u64,
    pub request: Option<Command>,
    pub response: Option<Response>,
    complete: bool,

    tx_data: AppLayerTxData,
}

impl POP3Transaction {
    pub fn new(tx_id: u64) -> POP3Transaction {
        Self {
            tx_id,
            request: None,
            response: None,
            complete: false,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn error_flags_to_events(&mut self, flags: Flags<ErrorFlag>) {
        for val in ErrorFlag::ITEMS
            .iter()
            .filter(move |&flag| flags.contains(*flag))
        {
            self.tx_data.set_event(POP3Event::from(*val) as u8);
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
    retr_data: u32,
}

impl State<POP3Transaction> for POP3State {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&POP3Transaction> {
        self.transactions.get(index)
    }
}

use nom7::{
    bytes::streaming::{tag, take_until},
    IResult,
};

fn parse_unknown_message(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, value) = take_until("\r\n")(input)?;
    let (input, _) = tag("\r\n")(input)?;
    return Ok((input, value));
}

fn find_end_of_header(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, value) = take_until("\r\n")(input)?;
    let (input, _) = tag("\r\n")(input)?;
    return Ok((input, value));
}

fn find_end_of_message(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, value) = take_until(".\r\n")(input)?;
    let (input, _) = tag(".\r\n")(input)?;
    return Ok((input, value));
}

fn parse_response_header_with_octets(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, size) = nom7::combinator::map_res(
        nom7::bytes::complete::take_while_m_n(1, 10, |b: u8| b.is_ascii_digit()),
        std::str::from_utf8,
    )(input)?;
    let size: u32 = size.parse::<u32>().unwrap_or_default();
    SCLogDebug!("size {}", size);
    return Ok((input, size));
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

    pub fn get_tx(&self, tx_id: u64) -> Option<&POP3Transaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut POP3Transaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> Option<POP3Transaction> {
        if self.transactions.len() > unsafe { POP3_MAX_TX } {
            for tx_old in &mut self.transactions {
                if !tx_old.complete {
                    tx_old.tx_data.updated_tc = true;
                    tx_old.tx_data.updated_ts = true;
                    tx_old.complete = true;
                    tx_old
                        .tx_data
                        .set_event(POP3Event::TooManyTransactions as u8);
                }
            }
            return None;
        }

        self.tx_id += 1;
        Some(POP3Transaction::new(self.tx_id))
    }

    fn find_request(&mut self) -> Option<&mut POP3Transaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, flow: *mut Flow, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            unsafe {
                if probe(input, Direction::ToServer) != ALPROTO_POP3 {
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
                    if let InnerMessage::Command(command) = msg.inner {
                        let mut tx = match self.new_tx() {
                            Some(tx) => tx,
                            None => return AppLayerResult::err(),
                        };
                        SCLogDebug!("tx created");

                        tx.error_flags_to_events(msg.error_flags);
                        tx.request = Some(command);
                        self.transactions.push_back(tx);
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, direction::Direction::ToServer as i32);
                    }

                    SCLogDebug!("request done");
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
                Err(SawpError {
                    kind: SawpErrorKind::Incomplete(sawp::error::Needed::Unknown),
                }) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_e) => {
                    SCLogDebug!("request error {:?}", _e);

                    // check for base64 SASL data
                    if let Ok((rem, _value)) =  parse_unknown_message(start) {
                        let mut tx = match self.new_tx() {
                            Some(tx) => tx,
                            None => return AppLayerResult::err(),
                        };
                        SCLogDebug!("tx created");

                        let keyword = sawp_pop3::Keyword::Unknown("<SASL DATA>".to_string());
                        tx.request = Some(Command { keyword, args: Vec::new(), });
                        self.transactions.push_back(tx);
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, direction::Direction::ToServer as i32);
                        start = rem;
                    } else {
                        return AppLayerResult::err();
                    }
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8], flow: *mut Flow) -> AppLayerResult {
        // skip RETR data
        let mut start = if self.retr_data > 0 {
            SCLogDebug!("input {} retr_data {}", input.len(), self.retr_data);
            if input.len() >= self.retr_data as usize {
                let input = &input[self.retr_data as usize..];
                self.retr_data = 0;
                if let Some(tx) = self.find_request() {
                    tx.complete = true;
                }
                input
            } else {
                self.retr_data -= input.len() as u32;
                &[]
            }
        } else {
            input
        };
        // We're not interested in empty responses.
        if start.is_empty() {
            return AppLayerResult::ok();
        }
        SCLogDebug!("input {} retr_data {}", start.len(), self.retr_data);

        if self.response_gap {
            unsafe {
                if probe(start, Direction::ToClient) != ALPROTO_POP3 {
                    // The parser now needs to decide what to do as we are not in sync.
                    // For this pop3, we'll just try again next time.
                    return AppLayerResult::ok();
                }
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        while !start.is_empty() {
            // empty server challenge is not handled by sawp-pop3. Simply skip past it.
            if start.starts_with(b"+ \r\n") {
                SCLogDebug!("empty server challenge");
                if let Some(tx) = self.find_request() {
                    SCLogDebug!("found tx request:{:?} response:{:?}", tx.request, tx.response);
                    let response = { Response { status: sawp_pop3::Status::OK, header: Vec::new(), data: Vec::new() }};
                    tx.response = Some(response);
                    tx.complete = true;
                }
                start = &start[4..];
                continue;
            }
            // since sawp-pop3 won't tell us if a command needs a multiline response, and if
            // it saw the full multiline response, we have to check for it here.
            let (mut multiline, is_retr) = if let Some(tx) = self.find_request() {
                let command = tx.request.as_ref().unwrap();
                SCLogDebug!("command {:?}", command);
                match command.keyword {
                    sawp_pop3::Keyword::LIST|sawp_pop3::Keyword::UIDL => {
                        // LIST and UIDL are in single line mode if they
                        // have a argument
                        if !command.args.is_empty() {
                            (false, false)
                        } else {
                            (true, false)
                        }
                    }
                    sawp_pop3::Keyword::TOP => (true, false),
                    sawp_pop3::Keyword::RETR => (true, true),
                    _ => (false, false),
                }
            } else {
                (false, false)
            };
            SCLogDebug!("multiline {}", multiline);

            match find_end_of_header(start) {
                Ok((body, header)) => {
                    SCLogDebug!("end of header found");

                    // get the RETR octet size so we don't FP on the RETR data
                    // when looking for the end of message marker
                    if is_retr && !header.is_empty() && header.starts_with(b"+OK ") && header.ends_with(b"octets") {
                        let header_args = &header[4..];
                        SCLogDebug!("octets line");

                        let size = match parse_response_header_with_octets(header_args) {
                            Ok((_, size)) => size,
                            Err(_e) => {
                                SCLogDebug!("header parsing error! {:?}", _e);
                                0
                            }
                        };

                        let retr_octets_requested = size;
                        let retr_octets_processed = if body.len() < size as usize {
                            SCLogDebug!("incomplete RETR data: {} < {}", body.len(), size);
                            body.len() as u32
                        } else {
                            retr_octets_requested
                        };
                        self.retr_data = retr_octets_requested - retr_octets_processed;
                        start = &body[retr_octets_processed as usize..];

                    // multiline no longer applies for errors
                    } else if header.starts_with(b"-ERR") {
                        multiline = false;
                    }
                }
                // partial header, lets return incomplete
                Err(nom7::Err::Incomplete(needed)) => {
                    if let nom7::Needed::Size(n) = needed {
                        SCLogDebug!("needed {}", n);
                        let consumed = input.len() - start.len();
                        let needed = start.len() + n.get();
                        return AppLayerResult::incomplete(consumed as u32, needed as u32);
                    }
                    return AppLayerResult::err();
                }
                _ => {
                    return AppLayerResult::err();
                }
            }

            // sawp-pop3 doesn't give us enough info about multiline parsing, so
            // look for the end of message marker ourselves. Except for the RETR
            // data, which can get too large, we just return incomplete until we
            // have all data.
            if multiline {
                match find_end_of_message(start) {
                    Ok((rem, _eom)) => {
                        SCLogDebug!("end of multiline message found: message size {}", start.len() - rem.len());

                        // for RETR, search for the final multiline end marker to skip past it
                        if is_retr && self.retr_data == 0 {
                            SCLogDebug!("command is RETR, all data processed, skip past EOM marker");
                            start = rem;
                            SCLogDebug!("start len {}", start.len());

                            // mark as complete
                            if let Some(tx) = self.find_request() {
                                tx.complete = true;
                            }
                        }
                    }
                    _ => {
                        SCLogDebug!("no multiline response, consider incomplete");
                        let consumed = input.len() - start.len();
                        let needed = start.len() + 1;
                        return AppLayerResult::incomplete(consumed as u32, needed as u32);
                    }
                }
            }
            // we may have consumed all data by now
            if start.is_empty() {
                return AppLayerResult::ok();
            }

            match POP3_PARSER.parse(start, Direction::ToClient) {
                Ok((rem, Some(msg))) => {
                    SCLogDebug!("msg {:?} start:{} rem:{}", msg, start.len(), rem.len());
                    if let InnerMessage::Response(mut response) = msg.inner {
                        let tx = if let Some(tx) = self.find_request() {
                            tx
                        } else {
                            // Server sends banner before any requests
                            let tx = match self.new_tx() {
                                Some(tx) => tx,
                                None => return AppLayerResult::err(),
                            };

                            let tx_id = tx.id();
                            self.transactions.push_back(tx);
                            self.get_tx_mut(tx_id - 1).unwrap()
                        };

                        tx.error_flags_to_events(msg.error_flags);
                        tx.complete = true;
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, direction::Direction::ToClient as i32);
                        if response.status == sawp_pop3::Status::OK && tx.request.is_some() {
                            let command = tx.request.as_ref().unwrap();
                            SCLogDebug!("command {:?}", command);
                            match &command.keyword {
                                sawp_pop3::Keyword::STLS => {
                                    unsafe {
                                        SCAppLayerRequestProtocolTLSUpgrade(flow);
                                    };
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
                    SCLogDebug!("updated: start:{} rem:{}", start.len(), rem.len());
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
                Err(SawpError {
                    kind: SawpErrorKind::Incomplete(sawp::error::Needed::Unknown),
                }) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_e) => {
                    SCLogDebug!("response error {:?}", _e);
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self) {
        self.response_gap = true;
    }
}

/// Reasonably need at least 5 bytes to determine
/// 3 bytes for short commands like 'TOP' or response '+OK'
/// and 2 bytes for the CRLF.
static MIN_PROBE_LEN: u32 = 5;

/// Probe for a command or response
fn probe(input: &[u8], direction: Direction) -> AppProto {
    match POP3_PARSER.probe(input, direction) {
        Status::Recognized => unsafe { ALPROTO_POP3 },
        Status::Incomplete => ALPROTO_UNKNOWN,
        Status::Unrecognized => ALPROTO_FAILED,
    }
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn pop3_probe_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len < MIN_PROBE_LEN {
        ALPROTO_UNKNOWN
    } else {
        let slice = build_slice!(input, input_len as usize);
        probe(slice, Direction::ToClient)
    }
}

unsafe extern "C" fn pop3_probe_ts(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len < MIN_PROBE_LEN {
        ALPROTO_UNKNOWN
    } else {
        let slice = build_slice!(input, input_len as usize);
        probe(slice, Direction::ToServer)
    }
}

extern "C" fn pop3_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = POP3State::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn pop3_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut POP3State));
}

unsafe extern "C" fn pop3_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, POP3State);
    state.free_tx(tx_id);
}

unsafe extern "C" fn pop3_parse_request(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, POP3State);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap();
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(flow, buf)
    }
}

unsafe extern "C" fn pop3_parse_response(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, POP3State);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap();
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf, flow)
    }
}

unsafe extern "C" fn pop3_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
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

unsafe extern "C" fn pop3_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, POP3State);
    return state.tx_id;
}

unsafe extern "C" fn pop3_tx_get_alstate_progress(tx: *mut c_void, direction: u8) -> c_int {
    let tx = cast_pointer!(tx, POP3Transaction);
    if direction == u8::from(direction::Direction::ToServer) {
        (tx.request.is_some() || tx.complete) as c_int
    } else {
        (tx.response.is_some() || tx.complete) as c_int
    }
}

export_tx_data_get!(pop3_get_tx_data, POP3Transaction);
export_state_data_get!(pop3_get_state_data, POP3State);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"pop3\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterPop3Parser() {
    let default_port = CString::new("[110]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(pop3_probe_ts),
        probe_tc: Some(pop3_probe_tc),
        min_depth: 0,
        max_depth: 16,
        state_new: pop3_state_new,
        state_free: pop3_state_free,
        tx_free: pop3_state_tx_free,
        parse_ts: pop3_parse_request,
        parse_tc: pop3_parse_response,
        get_tx_count: pop3_state_get_tx_count,
        get_tx: pop3_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: pop3_tx_get_alstate_progress,
        get_eventinfo: Some(POP3Event::get_event_info),
        get_eventinfo_byid: Some(POP3Event::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<POP3State, POP3Transaction>),
        get_tx_data: pop3_get_tx_data,
        get_state_data: pop3_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_POP3 = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        let retval = conf_get("app-layer.protocols.pop3.stream-depth");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => {
                    let stream_depth = retval as u32;
                    SCAppLayerParserSetStreamDepth(IPPROTO_TCP, ALPROTO_POP3, stream_depth);
                }
                Err(_) => {
                    SCLogError!("Invalid depth value");
                }
            }
        }
        if let Some(val) = conf_get("app-layer.protocols.pop3.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                POP3_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for pop3.max-tx");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_POP3);
        SCLogDebug!("Rust pop3 parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for POP3.");
    }
}
