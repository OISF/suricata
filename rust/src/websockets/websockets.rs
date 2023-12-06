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
use crate::core::{AppProto, Direction, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

static mut ALPROTO_WEBSOCKETS: AppProto = ALPROTO_UNKNOWN;

#[derive(Default)]
pub struct WebSocketsTransaction {
    tx_id: u64,
    pub pdu: parser::WebSocketsPdu,
    tx_data: AppLayerTxData,
}

impl WebSocketsTransaction {
    pub fn new(direction: Direction) -> WebSocketsTransaction {
        Self {
            tx_data: AppLayerTxData::for_direction(direction),
            ..Default::default()
        }
    }
}

impl Transaction for WebSocketsTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct WebSocketsState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<WebSocketsTransaction>,
}

impl State<WebSocketsTransaction> for WebSocketsState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&WebSocketsTransaction> {
        self.transactions.get(index)
    }
}

impl WebSocketsState {
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&WebSocketsTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self, direction: Direction) -> WebSocketsTransaction {
        let mut tx = WebSocketsTransaction::new(direction);
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn parse(&mut self, input: &[u8], direction: Direction) -> AppLayerResult {
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, pdu)) => {
                    start = rem;
                    let mut tx = self.new_tx(direction);
                    tx.pdu = pdu;
                    //TODOws should we reassemble/stream payload data ?
                    self.transactions.push_back(tx);
                }
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. just ask for one more byte.
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
}

// C exports.

extern "C" fn rs_websockets_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = WebSocketsState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_websockets_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut WebSocketsState));
}

unsafe extern "C" fn rs_websockets_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, WebSocketsState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_websockets_parse_request(
    _flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, WebSocketsState);
    let buf = stream_slice.as_slice();
    state.parse(buf, Direction::ToServer)
}

unsafe extern "C" fn rs_websockets_parse_response(
    _flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, WebSocketsState);
    let buf = stream_slice.as_slice();
    state.parse(buf, Direction::ToClient)
}

unsafe extern "C" fn rs_websockets_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, WebSocketsState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_websockets_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, WebSocketsState);
    return state.tx_id;
}

unsafe extern "C" fn rs_websockets_tx_get_alstate_progress(
    _tx: *mut c_void, _direction: u8,
) -> c_int {
    return 1;
}

export_tx_data_get!(rs_websockets_get_tx_data, WebSocketsTransaction);
export_state_data_get!(rs_websockets_get_state_data, WebSocketsState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"websockets\0";

#[no_mangle]
pub unsafe extern "C" fn rs_websockets_register_parser() {
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_websockets_state_new,
        state_free: rs_websockets_state_free,
        tx_free: rs_websockets_state_tx_free,
        parse_ts: rs_websockets_parse_request,
        parse_tc: rs_websockets_parse_response,
        get_tx_count: rs_websockets_state_get_tx_count,
        get_tx: rs_websockets_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_websockets_tx_get_alstate_progress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            applayer::state_get_tx_iterator::<WebSocketsState, WebSocketsTransaction>,
        ),
        get_tx_data: rs_websockets_get_tx_data,
        get_state_data: rs_websockets_get_state_data,
        apply_tx_config: None,
        flags: 0, // do not accept gaps as there is no good way to resync
        truncate: None,
        get_frame_id_by_name: None, //TODOws
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_WEBSOCKETS = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust websockets parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for WEBSOCKETS.");
    }
}
