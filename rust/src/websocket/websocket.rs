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
use crate::frames::Frame;
use nom7 as nom;
use nom7::Needed;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

static mut ALPROTO_WEBSOCKET: AppProto = ALPROTO_UNKNOWN;

// app-layer-frame-documentation tag start: FrameType enum
#[derive(AppLayerFrameType)]
pub enum WebSocketFrameType {
    Header,
    Pdu,
}

#[derive(Default)]
pub struct WebSocketTransaction {
    tx_id: u64,
    pub pdu: parser::WebSocketPdu,
    tx_data: AppLayerTxData,
}

impl WebSocketTransaction {
    pub fn new(direction: Direction) -> WebSocketTransaction {
        Self {
            tx_data: AppLayerTxData::for_direction(direction),
            ..Default::default()
        }
    }
}

impl Transaction for WebSocketTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct WebSocketState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<WebSocketTransaction>,
}

impl State<WebSocketTransaction> for WebSocketState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&WebSocketTransaction> {
        self.transactions.get(index)
    }
}

impl WebSocketState {
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&WebSocketTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self, direction: Direction) -> WebSocketTransaction {
        let mut tx = WebSocketTransaction::new(direction);
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn parse(
        &mut self, stream_slice: StreamSlice, direction: Direction, flow: *const Flow,
    ) -> AppLayerResult {
        let input = stream_slice.as_slice();
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, pdu)) => {
                    let _pdu = Frame::new(
                        flow,
                        &stream_slice,
                        start,
                        (start.len() - rem.len() - pdu.payload.len()) as i64,
                        WebSocketFrameType::Header as u8,
                    );
                    let _pdu = Frame::new(
                        flow,
                        &stream_slice,
                        start,
                        (start.len() - rem.len()) as i64,
                        WebSocketFrameType::Pdu as u8,
                    );
                    start = rem;
                    let mut tx = self.new_tx(direction);
                    tx.pdu = pdu;
                    //TODOws detection on payload buffer
                    //TODOws should we reassemble/stream payload data ?
                    self.transactions.push_back(tx);
                }
                Err(nom::Err::Incomplete(needed)) => {
                    if let Needed::Size(n) = needed {
                        let n = usize::from(n);
                        // Not enough data. just ask for one more byte.
                        let consumed = input.len() - start.len();
                        let needed = start.len() + n;
                        return AppLayerResult::incomplete(consumed as u32, needed as u32);
                    }
                    return AppLayerResult::err();
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

extern "C" fn rs_websocket_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = WebSocketState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_websocket_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut WebSocketState));
}

unsafe extern "C" fn rs_websocket_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, WebSocketState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_websocket_parse_request(
    flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, WebSocketState);
    state.parse(stream_slice, Direction::ToServer, flow)
}

unsafe extern "C" fn rs_websocket_parse_response(
    flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, WebSocketState);
    state.parse(stream_slice, Direction::ToClient, flow)
}

unsafe extern "C" fn rs_websocket_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, WebSocketState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_websocket_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, WebSocketState);
    return state.tx_id;
}

unsafe extern "C" fn rs_websocket_tx_get_alstate_progress(
    _tx: *mut c_void, _direction: u8,
) -> c_int {
    return 1;
}

export_tx_data_get!(rs_websocket_get_tx_data, WebSocketTransaction);
export_state_data_get!(rs_websocket_get_state_data, WebSocketState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"websocket\0";

#[no_mangle]
pub unsafe extern "C" fn rs_websocket_register_parser() {
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_websocket_state_new,
        state_free: rs_websocket_state_free,
        tx_free: rs_websocket_state_tx_free,
        parse_ts: rs_websocket_parse_request,
        parse_tc: rs_websocket_parse_response,
        get_tx_count: rs_websocket_state_get_tx_count,
        get_tx: rs_websocket_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_websocket_tx_get_alstate_progress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            applayer::state_get_tx_iterator::<WebSocketState, WebSocketTransaction>,
        ),
        get_tx_data: rs_websocket_get_tx_data,
        get_state_data: rs_websocket_get_state_data,
        apply_tx_config: None,
        flags: 0, // do not accept gaps as there is no good way to resync
        truncate: None,
        get_frame_id_by_name: Some(WebSocketFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(WebSocketFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_WEBSOCKET = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
            AppLayerRegisterExpectationProto(IPPROTO_TCP, ALPROTO_WEBSOCKET);
        }
        SCLogDebug!("Rust websocket parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for WEBSOCKET.");
    }
}
