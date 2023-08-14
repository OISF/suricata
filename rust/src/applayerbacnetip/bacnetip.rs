/* Copyright (C) 2023 Open Information Security Foundation
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
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_UDP};
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};


pub const BACNETIP_REQUEST_FLOOD: usize = 500;

static mut ALPROTO_BACNETIP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum BacNetIpEvent {
    InvalidFunctionCode,
    Flooded,
}

pub struct BacNetIpTransaction {
    tx_id: u64,
    pub request: Option<parser::BacNetPacket>,
    pub response: Option<parser::BacNetPacket>,

    pub tx_data: AppLayerTxData,
}

impl Default for BacNetIpTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl BacNetIpTransaction {
    pub fn new() -> BacNetIpTransaction {
        Self {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn set_event(&mut self, event: BacNetIpEvent) {
        self.tx_data.set_event(event as u8);
    }
}

impl Transaction for BacNetIpTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct BacNetIpState {
    state_data: AppLayerStateData,
    tx_id: u64,
    pub transactions: VecDeque<BacNetIpTransaction>,
    givenup: bool,
}

impl State<BacNetIpTransaction> for BacNetIpState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&BacNetIpTransaction> {
        self.transactions.get(index)
    }
}

impl BacNetIpState {
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&BacNetIpTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> Option<BacNetIpTransaction> {
        if self.givenup {
            return None;
        }

        let mut tx = BacNetIpTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;

        if BACNETIP_REQUEST_FLOOD != 0 && self.transactions.len() >= BACNETIP_REQUEST_FLOOD {
            tx.set_event(BacNetIpEvent::Flooded);
            self.givenup = true;
        }

        Some(tx)
    }

    fn find_request(&mut self) -> Option<&mut BacNetIpTransaction> {
        self.transactions.iter_mut().find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_bacnet_packet(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request: {}", request.to_string());
                    
                    let mut tx = match self.new_tx() {
                        Some(tx) => tx,
                        None => return AppLayerResult::ok(),
                    };

                    tx.request = Some(request);
                    self.transactions.push_back(tx);
                }
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
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

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_bacnet_packet(start) {
                Ok((rem, response)) => {
                    start = rem;

                    if let Some(tx) =  self.find_request() {
                        tx.response = Some(response);
                        SCLogNotice!("Found response for request:");
                        SCLogNotice!("- Request: {:?}", tx.request);
                        SCLogNotice!("- Response: {:?}", tx.response);
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
}

/// Probe for a valid header.
///
/// As this bacnetip protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let (rem, _) = (parser::parse_bacnet_packet)(input)?;
    Ok((rem, ()))
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn rs_bacnetip_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 3 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_BACNETIP;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn rs_bacnetip_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = BacNetIpState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_bacnetip_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut BacNetIpState));
}

unsafe extern "C" fn rs_bacnetip_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, BacNetIpState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_bacnetip_parse_request(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, BacNetIpState);

    let buf = stream_slice.as_slice();
    state.parse_request(buf)
}

unsafe extern "C" fn rs_bacnetip_parse_response(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, BacNetIpState);
    let buf = stream_slice.as_slice();
    state.parse_response(buf)
}

unsafe extern "C" fn rs_bacnetip_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, BacNetIpState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_bacnetip_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, BacNetIpState);
    return state.tx_id;
}

unsafe extern "C" fn rs_bacnetip_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, BacNetIpTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnetip_get_request_buffer(
    tx: *mut c_void, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, BacNetIpTransaction);
    if let Some(ref request) = tx.request {
        let request_str = request.to_string();
        *len = request_str.len() as u32;
        *buf = request_str.as_ptr();
        return 1;
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnetip_get_response_buffer(
    tx: *mut c_void, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, BacNetIpTransaction);
    if let Some(ref response) = tx.response {
        let response_str = response.to_string();
        *len = response_str.len() as u32;
        *buf = response_str.as_ptr();
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_bacnetip_get_tx_data, BacNetIpTransaction);
export_state_data_get!(rs_bacnetip_get_state_data, BacNetIpState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"bacnetip\0";

#[no_mangle]
pub unsafe extern "C" fn rs_bacnetip_register_parser() {

    let default_port = CString::new("[47808]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(rs_bacnetip_probing_parser),
        probe_tc: Some(rs_bacnetip_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_bacnetip_state_new,
        state_free: rs_bacnetip_state_free,
        tx_free: rs_bacnetip_state_tx_free,
        parse_ts: rs_bacnetip_parse_request,
        parse_tc: rs_bacnetip_parse_response,
        get_tx_count: rs_bacnetip_state_get_tx_count,
        get_tx: rs_bacnetip_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_bacnetip_tx_get_alstate_progress,
        get_eventinfo: Some(BacNetIpEvent::get_event_info),
        get_eventinfo_byid: Some(BacNetIpEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            applayer::state_get_tx_iterator::<BacNetIpState, BacNetIpTransaction>,
        ),
        get_tx_data: rs_bacnetip_get_tx_data,
        get_state_data: rs_bacnetip_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_BACNETIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust bacnetip parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for BACNETIP.");
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
        let mut state = BacNetIpState::new();
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
