/* Copyright (C) 2023-2025 Open Information Security Foundation
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
use crate::core::{
    sc_app_layer_parser_trigger_raw_stream_inspection, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP,
};
use crate::direction::Direction;
use crate::flow::Flow;
use crate::frames::Frame;

use nom8 as nom;
use nom8::Needed;

use flate2::Decompress;
use flate2::FlushDecompress;
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

pub(super) static mut ALPROTO_WEBSOCKET: AppProto = ALPROTO_UNKNOWN;

static mut WEBSOCKET_MAX_PAYLOAD_SIZE: u32 = 0xFFFF;

const WEBSOCKET_DECOMPRESS_BUF_SIZE: usize = 8192;

#[derive(AppLayerFrameType)]
pub enum WebSocketFrameType {
    Header,
    Pdu,
    Data,
}

#[derive(AppLayerEvent)]
pub enum WebSocketEvent {
    SkipEndOfPayload,
    ReassemblyLimitReached,
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
struct WebSocketReassemblyBuffer {
    data: Vec<u8>,
    compress: bool,
}

#[derive(Default)]
pub struct WebSocketState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<WebSocketTransaction>,

    c2s_dec: Option<flate2::Decompress>,
    s2c_dec: Option<flate2::Decompress>,

    c2s_buf: WebSocketReassemblyBuffer,
    s2c_buf: WebSocketReassemblyBuffer,

    to_skip_tc: u64,
    to_skip_ts: u64,
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
        &mut self, stream_slice: StreamSlice, direction: Direction, flow: *mut Flow,
    ) -> AppLayerResult {
        let to_skip = if direction == Direction::ToClient {
            &mut self.to_skip_tc
        } else {
            &mut self.to_skip_ts
        };
        let input = stream_slice.as_slice();
        let mut start = input;
        if *to_skip > 0 {
            if *to_skip >= input.len() as u64 {
                *to_skip -= input.len() as u64;
                return AppLayerResult::ok();
            } else {
                start = &input[*to_skip as usize..];
                *to_skip = 0;
            }
        }

        let max_pl_size = unsafe { WEBSOCKET_MAX_PAYLOAD_SIZE };
        while !start.is_empty() {
            match parser::parse_message(start, max_pl_size) {
                Ok((rem, pdu)) => {
                    let mut tx = self.new_tx(direction);
                    let _pdu = Frame::new(
                        flow,
                        &stream_slice,
                        start,
                        (start.len() - rem.len() - pdu.payload.len()) as i64,
                        WebSocketFrameType::Header as u8,
                        Some(tx.tx_id),
                    );
                    let _pdu = Frame::new(
                        flow,
                        &stream_slice,
                        start,
                        (start.len() - rem.len()) as i64,
                        WebSocketFrameType::Pdu as u8,
                        Some(tx.tx_id),
                    );
                    let _pdu = Frame::new(
                        flow,
                        &stream_slice,
                        &start[(start.len() - rem.len() - pdu.payload.len())..],
                        pdu.payload.len() as i64,
                        WebSocketFrameType::Data as u8,
                        Some(tx.tx_id),
                    );
                    start = rem;
                    if pdu.to_skip > 0 {
                        if direction == Direction::ToClient {
                            self.to_skip_tc = pdu.to_skip;
                        } else {
                            self.to_skip_ts = pdu.to_skip;
                        }
                        tx.tx_data.set_event(WebSocketEvent::SkipEndOfPayload as u8);
                    }
                    if pdu.compress {
                        // RFC 7692 section 7.1.2 states that
                        // absence of precision means LZ77 sliding window of up to 2^15 bytes
                        if direction == Direction::ToClient && self.s2c_dec.is_none() {
                            self.s2c_dec = Some(Decompress::new_with_window_bits(false, 15));
                        } else if direction == Direction::ToServer && self.c2s_dec.is_none() {
                            self.c2s_dec = Some(Decompress::new_with_window_bits(false, 15));
                        }
                    }
                    let (buf, dec) = if direction == Direction::ToClient {
                        (&mut self.s2c_buf, &mut self.s2c_dec)
                    } else {
                        (&mut self.c2s_buf, &mut self.c2s_dec)
                    };
                    let mut compress = pdu.compress;
                    if !buf.data.is_empty() || !pdu.fin {
                        if buf.data.is_empty() {
                            buf.compress = pdu.compress;
                        }
                        if buf.data.len() + pdu.payload.len() < max_pl_size as usize {
                            buf.data.extend(&pdu.payload);
                        } else if buf.data.len() < max_pl_size as usize {
                            buf.data
                                .extend(&pdu.payload[..max_pl_size as usize - buf.data.len()]);
                            tx.tx_data
                                .set_event(WebSocketEvent::ReassemblyLimitReached as u8);
                        }
                    }
                    tx.pdu = pdu;
                    if tx.pdu.fin && !buf.data.is_empty() {
                        // the final PDU gets the full reassembled payload
                        compress = buf.compress;
                        std::mem::swap(&mut tx.pdu.payload, &mut buf.data);
                        buf.data.clear();
                    }
                    if compress && tx.pdu.fin {
                        buf.compress = false;
                        // cf RFC 7692 section-7.2.2
                        tx.pdu.payload.extend_from_slice(&[0, 0, 0xFF, 0xFF]);
                        let mut v = Vec::with_capacity(std::cmp::min(
                            WEBSOCKET_DECOMPRESS_BUF_SIZE,
                            // Do not allocate 8kbytes for a small size.
                            // Numbers here may be optimized.
                            256 + 16 * tx.pdu.payload.len(),
                        ));
                        if let Some(dec) = dec {
                            let expect = dec.total_in() + tx.pdu.payload.len() as u64;
                            let start = dec.total_in();
                            let mut e = dec.decompress_vec(
                                &tx.pdu.payload,
                                &mut v,
                                FlushDecompress::Finish,
                            );
                            while e.is_ok() && dec.total_in() < expect {
                                let mut s = vec![0u8; WEBSOCKET_DECOMPRESS_BUF_SIZE];
                                let before = dec.total_out();
                                let check = dec.total_in();
                                e = dec.decompress(
                                    &tx.pdu.payload[(dec.total_in() - start) as usize..],
                                    &mut s,
                                    FlushDecompress::Finish,
                                );
                                if v.len() < max_pl_size as usize {
                                    let end = if v.len() + (dec.total_out() - before) as usize
                                        > max_pl_size as usize
                                    {
                                        max_pl_size as usize - v.len()
                                    } else {
                                        (dec.total_out() - before) as usize
                                    };
                                    v.extend_from_slice(&s[..end]);
                                }
                                if check >= dec.total_in() {
                                    // safety check against infinite loop : dec.total_in() should increase
                                    break;
                                }
                            }
                            if !v.is_empty() {
                                std::mem::swap(&mut tx.pdu.payload, &mut v);
                            }
                        }
                    }
                    if tx.pdu.fin {
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, direction as i32);
                    }
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

unsafe extern "C" fn websocket_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if !slice.is_empty() {
            // just check reserved bits are zeroed, except RSV1
            // as RSV1 is used for compression cf RFC 7692
            if slice[0] & 0x30 == 0 {
                return ALPROTO_WEBSOCKET;
            }
            return ALPROTO_FAILED;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn websocket_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = WebSocketState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn websocket_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut WebSocketState));
}

unsafe extern "C" fn websocket_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, WebSocketState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn websocket_parse_request(
    flow: *mut Flow, state: *mut c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, WebSocketState);
    state.parse(stream_slice, Direction::ToServer, flow)
}

unsafe extern "C" fn websocket_parse_response(
    flow: *mut Flow, state: *mut c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, WebSocketState);
    state.parse(stream_slice, Direction::ToClient, flow)
}

unsafe extern "C" fn websocket_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
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

unsafe extern "C" fn websocket_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, WebSocketState);
    return state.tx_id;
}

unsafe extern "C" fn websocket_tx_get_alstate_progress(_tx: *mut c_void, _direction: u8) -> c_int {
    return 1;
}

export_tx_data_get!(websocket_get_tx_data, WebSocketTransaction);
export_state_data_get!(websocket_get_state_data, WebSocketState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"websocket\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterWebSocketParser() {
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(websocket_probing_parser),
        probe_tc: Some(websocket_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: websocket_state_new,
        state_free: websocket_state_free,
        tx_free: websocket_state_tx_free,
        parse_ts: websocket_parse_request,
        parse_tc: websocket_parse_response,
        get_tx_count: websocket_state_get_tx_count,
        get_tx: websocket_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: websocket_tx_get_alstate_progress,
        get_eventinfo: Some(WebSocketEvent::get_event_info),
        get_eventinfo_byid: Some(WebSocketEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            applayer::state_get_tx_iterator::<WebSocketState, WebSocketTransaction>,
        ),
        get_tx_data: websocket_get_tx_data,
        get_state_data: websocket_get_state_data,
        apply_tx_config: None,
        flags: 0, // do not accept gaps as there is no good way to resync
        get_frame_id_by_name: Some(WebSocketFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(WebSocketFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_WEBSOCKET = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust websocket parser registered.");
        if let Some(val) = conf_get("app-layer.protocols.websocket.max-payload-size") {
            if let Ok(v) = val.parse::<u32>() {
                WEBSOCKET_MAX_PAYLOAD_SIZE = v;
            } else {
                SCLogError!("Invalid value for websocket.max-payload-size");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_WEBSOCKET);
    } else {
        SCLogDebug!("Protocol detector and parser disabled for WEBSOCKET.");
    }
}
