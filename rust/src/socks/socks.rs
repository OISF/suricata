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

use super::parser;
use crate::applayer::{self, *};
use crate::conf::conf_get;
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use nom7 as nom;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::{self, fmt};

static mut SOCKS_MAX_TX: usize = 256;

pub(super) static mut ALPROTO_SOCKS: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum SocksEvent {
    TooManyTransactions,
}

pub struct SocksTransactionAuthMethods {
    pub request_methods: Vec<u8>,
    pub response_method: u8,
}

pub struct SocksTransactionAuth {
    pub subver: u8,
    pub user: Vec<u8>,
    pub pass: Vec<u8>,
    pub response: Option<u8>,
}

pub struct SocksTransactionConnect {
    pub domain: Option<Vec<u8>>,
    pub ipv4: Option<Vec<u8>>,
    pub port: u16,
    pub response: Option<u8>,
}

pub struct SocksTransaction {
    tx_id: u64,
    tx_data: AppLayerTxData,
    complete: bool,
    pub connect: Option<SocksTransactionConnect>,
    pub auth_userpass: Option<SocksTransactionAuth>,
    pub auth_methods: Option<SocksTransactionAuthMethods>,
}

impl Default for SocksTransaction {
    fn default() -> Self {
        SCLogDebug!("new tx! default");
        Self::new()
    }
}

impl SocksTransaction {
    pub fn new() -> SocksTransaction {
        SCLogDebug!("new tx!");
        Self {
            tx_id: 0,
            tx_data: AppLayerTxData::new(),
            complete: false,
            connect: None,
            auth_userpass: None,
            auth_methods: None,
        }
    }
}

impl Transaction for SocksTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(PartialEq, Eq, Debug)]
enum SocksConnectionState {
    New = 0,
    AuthMethodSent = 1,
    AuthMethodResponded = 2,
    AuthDataSent = 3,
    AuthDataResponded = 4,
    ConnectSent = 5,
    ConnectResponded = 6,
}
impl Default for SocksConnectionState {
    fn default() -> Self {
        SocksConnectionState::New
    }
}
impl fmt::Display for SocksConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Default)]
pub struct SocksState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<SocksTransaction>,
    request_gap: bool,
    response_gap: bool,
    state: SocksConnectionState,
    connect_port: Option<u16>,
}

impl State<SocksTransaction> for SocksState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&SocksTransaction> {
        self.transactions.get(index)
    }
}

impl SocksState {
    pub fn new() -> Self {
        Default::default()
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&SocksTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> SocksTransaction {
        SCLogDebug!("new tx!");
        let mut tx = SocksTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut SocksTransaction> {
        self.transactions.iter_mut().find(|tx| !tx.complete)
    }

    fn parse_request_data<'a>(
        &mut self, tinput: &'a [u8], rinput: &'a [u8],
    ) -> (AppLayerResult, &'a [u8]) {
        match self.state {
            SocksConnectionState::New => {
                let r = parser::parse_connect_request(rinput);
                match r {
                    Ok((rem, request)) => {
                        let mut tx = self.new_tx();
                        tx.auth_methods = Some(SocksTransactionAuthMethods {
                            request_methods: request.auth_methods,
                            response_method: 0,
                        });
                        if self.transactions.len() >= unsafe { SOCKS_MAX_TX } {
                            tx.tx_data.set_event(SocksEvent::TooManyTransactions as u8);
                        }
                        self.transactions.push_back(tx);
                        if self.transactions.len() >= unsafe { SOCKS_MAX_TX } {
                            return (AppLayerResult::err(), &[]);
                        }
                        self.state = SocksConnectionState::AuthMethodSent;
                        SCLogDebug!("> state now {}", self.state);
                        return (AppLayerResult::ok(), rem);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        // Not enough data. This parser doesn't give us a good indication
                        // of how much data is missing so just ask for one more byte so the
                        // parse is called as soon as more data is received.
                        let consumed = tinput.len() - rinput.len();
                        let needed = rinput.len() + 1;
                        return (
                            AppLayerResult::incomplete(consumed as u32, needed as u32),
                            &[],
                        );
                    }
                    Err(_) => {
                        return (AppLayerResult::err(), &[]);
                    }
                }
            }
            SocksConnectionState::AuthMethodResponded => {
                let r = parser::parse_auth_request(rinput);
                match r {
                    Ok((rem, request)) => {
                        let mut tx = self.new_tx();
                        tx.auth_userpass = Some(SocksTransactionAuth {
                            subver: request.subver,
                            user: request.user.to_vec(),
                            pass: request.pass.to_vec(),
                            response: None,
                        });
                        if self.transactions.len() >= unsafe { SOCKS_MAX_TX } {
                            tx.tx_data.set_event(SocksEvent::TooManyTransactions as u8);
                        }
                        self.transactions.push_back(tx);
                        if self.transactions.len() >= unsafe { SOCKS_MAX_TX } {
                            return (AppLayerResult::err(), &[]);
                        }
                        self.state = SocksConnectionState::AuthDataSent;
                        SCLogDebug!("> state now {}", self.state);
                        return (AppLayerResult::ok(), rem);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        // Not enough data. This parser doesn't give us a good indication
                        // of how much data is missing so just ask for one more byte so the
                        // parse is called as soon as more data is received.
                        let consumed = tinput.len() - rinput.len();
                        let needed = rinput.len() + 1;
                        return (
                            AppLayerResult::incomplete(consumed as u32, needed as u32),
                            &[],
                        );
                    }
                    Err(_) => {
                        return (AppLayerResult::err(), &[]);
                    }
                }
            }
            SocksConnectionState::AuthDataResponded => {
                SCLogDebug!("connect request!");
                let r = parser::parse_connect_command_request(rinput);
                match r {
                    Ok((rem, request)) => {
                        let mut tx = self.new_tx();
                        tx.connect = Some(SocksTransactionConnect {
                            domain: request.domain,
                            ipv4: request.ipv4,
                            port: request.port,
                            response: None,
                        });
                        self.connect_port = Some(request.port);
                        if self.transactions.len() >= unsafe { SOCKS_MAX_TX } {
                            tx.tx_data.set_event(SocksEvent::TooManyTransactions as u8);
                        }
                        self.transactions.push_back(tx);
                        if self.transactions.len() >= unsafe { SOCKS_MAX_TX } {
                            return (AppLayerResult::err(), &[]);
                        }
                        self.state = SocksConnectionState::ConnectSent;
                        SCLogDebug!("> state now {}", self.state);
                        return (AppLayerResult::ok(), rem);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        // Not enough data. This parser doesn't give us a good indication
                        // of how much data is missing so just ask for one more byte so the
                        // parse is called as soon as more data is received.
                        let consumed = tinput.len() - rinput.len();
                        let needed = rinput.len() + 1;
                        return (
                            AppLayerResult::incomplete(consumed as u32, needed as u32),
                            &[],
                        );
                    }
                    Err(_) => {
                        return (AppLayerResult::err(), &[]);
                    }
                }
            }
            SocksConnectionState::AuthMethodSent => {}
            SocksConnectionState::AuthDataSent => {}
            SocksConnectionState::ConnectSent => {}
            SocksConnectionState::ConnectResponded => {}
        }
        return (AppLayerResult::err(), &[]);
    }

    fn parse_response_data<'a>(
        &mut self, tinput: &'a [u8], rinput: &'a [u8],
    ) -> (AppLayerResult, &'a [u8]) {
        SCLogDebug!("< state {}", self.state);
        match self.state {
            SocksConnectionState::AuthMethodSent => {
                let r = parser::parse_connect_response(rinput);
                match r {
                    Ok((rem, response)) => {
                        if let Some(tx) = self.find_request() {
                            SCLogDebug!("< tx {} found", tx.tx_id);
                            tx.tx_data.updated_tc = true;
                            tx.complete = true;

                            if let Some(ref mut am) = tx.auth_methods {
                                am.response_method = response;
                            }
                        } else {
                            SCLogDebug!("< no tx found");
                        }

                        if response == 0 {
                            self.state = SocksConnectionState::AuthDataResponded;
                        } else {
                            self.state = SocksConnectionState::AuthMethodResponded;
                        }

                        SCLogDebug!("< state now {}", self.state);
                        return (AppLayerResult::ok(), rem);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        // Not enough data. This parser doesn't give us a good indication
                        // of how much data is missing so just ask for one more byte so the
                        // parse is called as soon as more data is received.
                        let consumed = tinput.len() - rinput.len();
                        let needed = rinput.len() + 1;
                        SCLogDebug!("error incomplete");
                        return (
                            AppLayerResult::incomplete(consumed as u32, needed as u32),
                            &[],
                        );
                    }
                    Err(_) => {
                        SCLogDebug!("error");
                        return (AppLayerResult::err(), &[]);
                    }
                }
            }
            SocksConnectionState::AuthDataSent => {
                SCLogDebug!("auth response!");
                let r = parser::parse_auth_response(rinput);
                match r {
                    Ok((rem, response)) => {
                        if let Some(tx) = self.find_request() {
                            SCLogDebug!("< tx {} found", tx.tx_id);
                            tx.tx_data.updated_tc = true;
                            tx.complete = true;
                            if let Some(auth) = &mut tx.auth_userpass {
                                auth.response = Some(response);
                            }
                        } else {
                            SCLogDebug!("< no tx found");
                        }
                        self.state = SocksConnectionState::AuthDataResponded;

                        SCLogDebug!("< state now {}", self.state);
                        return (AppLayerResult::ok(), rem);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        // Not enough data. This parser doesn't give us a good indication
                        // of how much data is missing so just ask for one more byte so the
                        // parse is called as soon as more data is received.
                        let consumed = tinput.len() - rinput.len();
                        let needed = rinput.len() + 1;
                        return (
                            AppLayerResult::incomplete(consumed as u32, needed as u32),
                            &[],
                        );
                    }
                    Err(_) => {
                        return (AppLayerResult::err(), &[]);
                    }
                }
            }
            SocksConnectionState::ConnectSent => {
                SCLogDebug!("connect response!");
                let r = parser::parse_connect_command_response(rinput);
                match r {
                    Ok((rem, response)) => {
                        if let Some(tx) = self.find_request() {
                            SCLogDebug!("< tx {} found", tx.tx_id);
                            tx.tx_data.updated_tc = true;
                            tx.complete = true;
                            if let Some(connect) = &mut tx.connect {
                                connect.response = Some(response.results);
                            }
                        } else {
                            SCLogDebug!("< no tx found");
                        }
                        self.state = SocksConnectionState::ConnectResponded;

                        SCLogDebug!("< state now {}", self.state);
                        return (AppLayerResult::ok(), rem);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        // Not enough data. This parser doesn't give us a good indication
                        // of how much data is missing so just ask for one more byte so the
                        // parse is called as soon as more data is received.
                        let consumed = tinput.len() - rinput.len();
                        let needed = rinput.len() + 1;
                        return (
                            AppLayerResult::incomplete(consumed as u32, needed as u32),
                            &[],
                        );
                    }
                    Err(_) => {
                        return (AppLayerResult::err(), &[]);
                    }
                }
            }
            SocksConnectionState::New => {}
            SocksConnectionState::AuthMethodResponded => {}
            SocksConnectionState::AuthDataResponded => {}
            SocksConnectionState::ConnectResponded => {}
        }
        return (AppLayerResult::err(), &[]);
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        SCLogDebug!("> got {} bytes of SOCKS data", input.len());

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this socks, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut record = input;
        while !record.is_empty() {
            let (r, remaining) = self.parse_request_data(input, record);
            if r != AppLayerResult::ok() {
                SCLogDebug!("issue");
                return r;
            }
            record = remaining;
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, flow: *const Flow, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        SCLogDebug!("< got {} bytes of SOCKS data", input.len());

        if self.response_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this socks, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut record = input;
        while !record.is_empty() {
            let (r, remaining) = self.parse_response_data(input, record);
            if r != AppLayerResult::ok() {
                SCLogDebug!("issue {:?}", r);
                return r;
            }
            if self.state == SocksConnectionState::ConnectResponded {
                // TODO how does it work if we got more data in `input` here?
                break;
            }
            record = remaining;
        }
        if self.state == SocksConnectionState::ConnectResponded {
            SCLogDebug!("requesting upgrade");
            let port = self.connect_port.unwrap_or(0);
            unsafe {
                AppLayerRequestProtocolChange(flow, port, ALPROTO_UNKNOWN);
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
/// As this socks protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let (input, _) = nom7::combinator::verify(nom7::number::complete::be_u8, |&v| v == 5)(input)?;
    Ok((input, ()))
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn socks_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_SOCKS;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn socks_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = SocksState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn socks_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut SocksState));
}

unsafe extern "C" fn socks_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, SocksState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn socks_parse_request(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, SocksState);

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

unsafe extern "C" fn socks_parse_response(
    flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, SocksState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(flow, buf)
    }
}

unsafe extern "C" fn socks_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, SocksState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn socks_get_tx_maxid(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, SocksState);
    return state.tx_id;
}

unsafe extern "C" fn socks_get_tx_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, SocksTransaction);
    return tx.complete as c_int;
}

export_tx_data_get!(socks_get_tx_data, SocksTransaction);
export_state_data_get!(socks_get_state_data, SocksState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"socks\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterSocksParser() {
    let default_port = CString::new("[1080]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(socks_probing_parser),
        probe_tc: Some(socks_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: socks_state_new,
        state_free: socks_state_free,
        tx_free: socks_tx_free,
        parse_ts: socks_parse_request,
        parse_tc: socks_parse_response,
        get_tx_count: socks_get_tx_maxid,
        get_tx: socks_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: socks_get_tx_progress,
        get_eventinfo: Some(SocksEvent::get_event_info),
        get_eventinfo_byid: Some(SocksEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<SocksState, SocksTransaction>),
        get_tx_data: socks_get_tx_data,
        get_state_data: socks_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SOCKS = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.socks.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                SOCKS_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for socks.max-tx");
            }
        }
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SOCKS);
        SCLogDebug!("Rust socks parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for SOCKS.");
    }
}
