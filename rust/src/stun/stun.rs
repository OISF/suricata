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

use std;
use std::collections::VecDeque;
use crate::core::{ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_UDP};
use crate::applayer::{self, *};
use std::ffi::CString;
use nom7::Err;
use super::parser::{self, StunMessage};

static mut ALPROTO_STUN: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum StunEvent {}

/* STUN methods (aka message types): hex number range 0x000-0xFFF */
//pub const STUN_MESSAGE_TYPE_RESERVED                   : u16 = 0x0000;
//pub const STUN_MSG_TYPE_BINDING_REQUEST                : u16 = 0x0001;
//pub const STUN_MSG_TYPE_BINDING_RESPONSE               : u16 = 0x0101;
//pub const STUN_MSG_TYPE_BINDING_ERROR_RESPONSE         : u16 = 0x0111;
//pub const STUN_MSG_TYPE_SHARED_SECRET_REQUEST          : u16 = 0x0002; // Reserved (RFC 8489)
//pub const STUN_MSG_TYPE_SHARED_SECRET_RESPONSE         : u16 = 0x0102;
//pub const STUN_MSG_TYPE_SHARED_SECRET_ERROR_RESPONSE   : u16 = 0x0112;

/* STUN message attributes (aka STUN attributes): hex number range 0x0000-0xFFFF (RFC 5389) */
//pub const STUN_MSG_ATTRIBUTE_MAPPED_ADDRESS            : u16 = 0x0001;
//pub const STUN_MSG_ATTRIBUTE_RESPONSE_ADDRESS          : u16 = 0x0002; // deprecated. Now reserved
//pub const STUN_MSG_ATTRIBUTE_CHANGE_REQUEST            : u16 = 0x0003; // deprecated. Now reserved
//pub const STUN_MSG_ATTRIBUTE_SOURCE_ADDRESS            : u16 = 0x0004; // deprecated. Now reserved
//pub const STUN_MSG_ATTRIBUTE_CHANGED_ADDRESS           : u16 = 0x0005; // deprecated. Now reserved
//pub const STUN_MSG_ATTRIBUTE_USERNAME                  : u16 = 0x0006;
//pub const STUN_MSG_ATTRIBUTE_PASSWORD                  : u16 = 0x0007; // deprecated. Now reserved (RFC 5389)
//pub const STUN_MSG_ATTRIBUTE_MESSAGE_INTEGRITY         : u16 = 0x0008;
//pub const STUN_MSG_ATTRIBUTE_ERROR_CODE                : u16 = 0x0009;
//pub const STUN_MSG_ATTRIBUTE_UNKNOWN_ATTRIBUTES        : u16 = 0x000a;
//pub const STUN_MSG_ATTRIBUTE_REFLECTED_FROM            : u16 = 0x000b; // deprecated. Now reserved
//pub const STUN_MSG_ATTRIBUTE_REALM                     : u16 = 0x0014;
//pub const STUN_MSG_ATTRIBUTE_NONCE                     : u16 = 0x0015;
//pub const STUN_MSG_ATTRIBUTE_XOR_MAPPED_ADDRESS        : u16 = 0x0020;
/* comprehension-optional range */
//pub const STUN_MSG_ATTRIBUTE_SOFTWARE                  : u16 = 0x8022;
//pub const STUN_MSG_ATTRIBUTE_ALTERNATE_SERVER          : u16 = 0x8023;
//pub const STUN_MSG_ATTRIBUTE_FINGERPRINT               : u16 = 0x8028;
/* RFC 8489 - comprehension-required range */
// pub const STUN_MSG_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256  : u16 = 0x001c;
// pub const STUN_MSG_ATTRIBUTE_PASSWORD_ALGORITHM        : u16 = 0x001d;
// pub const STUN_MSG_ATTRIBUTE_USERHASH                  : u16 = 0x001e;
/* RFC 8489 - comprehension-optional range */
//pub const STUN_MSG_ATTRIBUTE_PASSWORD_ALGORITHMS       : u16 = 0x8001;
//pub const STUN_MSG_ATTRIBUTE_ALTERNATE_DOMAIN          : u16 = 0x8002;

// TODO add STUN password algorithms registry
// TODO check which message types are still valid?

// TODO add something about STUN error codes registry?


#[derive(Debug)]
pub struct StunTransaction {
    tx_id: u64,
    pub request: Option<StunMessage>,
    pub response: Option<StunMessage>,

    tx_data: AppLayerTxData,
}

impl Default for StunTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl StunTransaction {
    pub fn new() -> StunTransaction {
        StunTransaction {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for StunTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Debug)]
pub struct StunState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<StunTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<StunTransaction> for StunState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&StunTransaction> {
        self.transactions.get(index)
    }
}

impl Default for StunState {
    fn default() -> Self {
        Self::new()
    }
}

impl StunState {
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&StunTransaction> {
        self.transactions.iter().find(|&tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> StunTransaction {
        let mut tx = StunTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut StunTransaction> {
        self.transactions.iter_mut().find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if !probe(input) {
                // The parser now needs to decide what to do as we are not in sync.
                // For this stun, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogDebug!("Request: {:?}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    self.transactions.push_back(tx);
                },
                Err(Err::Incomplete(_)) => {
                    // TODO create events
                    // UDP doesn't allow for incomplete segments, so we return error
                    SCLogDebug!("Incomplete request.");
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
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if !probe(input) {
                // The parser now needs to decide what to do as we are not in sync.
                // For this stun, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    if let Some(tx) = self.find_request() {
                        tx.response = Some(response);
                        SCLogDebug!("Found response for request:");
                        SCLogDebug!("- Request: {:?}", tx.request);
                        SCLogDebug!("- Response: {:?}", tx.response);
                    }
                }
                Err(Err::Incomplete(_)) => {
                    // TODO implement events
                    // UDP doesn't allow for incomplete segments, so we return error
                    SCLogDebug!("Incomplete response");
                    return AppLayerResult::err();
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

/// Probe for a valid header.
///
/// As this stun protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> bool {
    if parser::parse_message(input).is_ok() {
        return true
    }
    false
}

// C exports.

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn SCStunProbingParser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return ALPROTO_STUN;
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn SCStunStateNew(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = StunState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut std::os::raw::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn SCStunStateFree(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut StunState));
}

#[no_mangle]
pub unsafe extern "C" fn SCStunStateTxFree(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, StunState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn SCStunParseRequest(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, StunState);

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
pub unsafe extern "C" fn SCStunParseResponse(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, StunState);

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
pub unsafe extern "C" fn SCStunStateGetTx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, StunState);
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
pub unsafe extern "C" fn SCStunStateGetTxCount(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, StunState);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn SCStunTxGetAlStateProgress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, StunTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(SCStunGetTxData, StunTransaction);
export_state_data_get!(SCStunGetStateData, StunState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"stun\0";

#[no_mangle]
pub unsafe extern "C" fn SCStunRegisterParser() {
    let default_port = CString::new("[3478]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(SCStunProbingParser),
        probe_tc: Some(SCStunProbingParser),
        min_depth: 0,
        max_depth: 20,
        state_new: SCStunStateNew,
        state_free: SCStunStateFree,
        tx_free: SCStunStateTxFree,
        parse_ts: SCStunParseRequest,
        parse_tc: SCStunParseResponse,
        get_tx_count: SCStunStateGetTxCount,
        get_tx: SCStunStateGetTx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: SCStunTxGetAlStateProgress,
        get_eventinfo: Some(StunEvent::get_event_info),
        get_eventinfo_byid : Some(StunEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<StunState, StunTransaction>),
        get_tx_data: SCStunGetTxData,
        get_state_data: SCStunGetStateData,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_STUN = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust stun parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for STUN.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe() {
        let buf1 = &[
            0x00, 0x01, 0x00, 0x00, 0xd2, 0x68, 0x29, 0x9d,
            0xe0, 0x7f, 0xd4, 0x36, 0xa1, 0xf1, 0xbb, 0xba,
            0x70, 0xfe, 0x4d, 0x75
        ];

        assert!(probe(buf1));

        let buf2 = &[
            0x01, 0x01, 0x00, 0x44, 0xd2, 0x68, 0x29, 0x9d,
            0xe0, 0x7f, 0xd4, 0x36, 0xa1, 0xf1, 0xbb, 0xba,
            0x70, 0xfe, 0x4d, 0x75, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x01, 0x1e, 0xdc, 0x8e, 0xa5, 0xcd, 0x87,
            0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x0d, 0x97,
            0xd4, 0xe3, 0x43, 0x22, 0x00, 0x05, 0x00, 0x08,
            0x00, 0x01, 0x0d, 0x96, 0xd4, 0xe3, 0x43, 0x21,
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xcc, 0xb4,
            0x5c, 0xcd, 0xe4, 0x1a, 0x80, 0x22, 0x00, 0x10,
            0x56, 0x6f, 0x76, 0x69, 0x64, 0x61, 0x2e, 0x6f,
            0x72, 0x67, 0x20, 0x30, 0x2e, 0x39, 0x37, 0x00
        ];
        assert!(probe(buf2));

        assert!(!probe(&buf2[0..5]));
    }
}
