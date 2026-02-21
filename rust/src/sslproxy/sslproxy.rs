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

use super::parser;
use crate::applayer::*;
use crate::core::{ALPROTO_UNKNOWN, IPPROTO_TCP, sc_app_layer_parser_trigger_raw_stream_inspection};
use crate::flow::Flow;
use crate::direction::Direction;
use nom7 as nom;
use std;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::net::{IpAddr};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
    SCAppLayerProtoDetectPMRegisterPatternCS,
    SCAppLayerRequestProtocolChangeUnknown,
    SCFlowSetDecrypted,
};

pub(super) static mut ALPROTO_SSLPROXY: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum SSLProxyEvent {
    TooManyTransactions,
}

pub struct SSLProxyTransaction {
    tx_id: u64,
    tx_data: AppLayerTxData,
}

impl Default for SSLProxyTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl SSLProxyTransaction {
    pub fn new() -> SSLProxyTransaction {
        Self {
            tx_id: 0,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for SSLProxyTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct SSLProxyState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transaction: SSLProxyTransaction,
}

impl State<SSLProxyTransaction> for SSLProxyState {
    fn get_transaction_count(&self) -> usize {
        1_usize
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&SSLProxyTransaction> {
        if index == 0 {
            return Some(&self.transaction);
        }
        None
    }
}

impl SSLProxyState {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&SSLProxyTransaction> {
        if tx_id == 0 {
            return Some(&self.transaction);
        }
        return None;
    }

    fn parse_request(&mut self, flow: *mut Flow, input: &[u8]) -> AppLayerResult {

        SCLogDebug!("input {}", input.len());
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        match parser::parse_message(input) {
            Ok((rem, request)) => {
                SCLogDebug!("Request: {:?}", request);
                let mut _tx = self.get_tx(0);

                let proto = 6;
                let sp = request.port2;
                let dp = request.port3;

                if let IpAddr::V4(src_ip_v4) = request.ip2 {
                    let src_ip : u32 = src_ip_v4.into();
                    let src_ip = src_ip.to_be();
                    if let IpAddr::V4(dst_ip_v4) = request.ip3 {
                        let dest_ip : u32 = dst_ip_v4.into();
                        let dest_ip = dest_ip.to_be();
                        unsafe {
                            SCAppLayerRequestProtocolChangeUnknown(flow, request.port3);
                            sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToServer as i32);
                            SCFlowSetDecrypted(flow, proto, src_ip, sp, dest_ip, dp);
                        }

                        if !rem.is_empty() {
                            SCLogDebug!("returning partial");
                            let consumed = (input.len() - rem.len()) + 2;
                            return AppLayerResult::ok_partial_continue(consumed as u32);
                        }
                    }
                }
                SCLogDebug!("malformed proxy line");
                return AppLayerResult::err();
            }
            Err(nom::Err::Incomplete(_)) => {
                SCLogDebug!("incomplete");
                // Not enough data. This parser doesn't give us a good indication
                // of how much data is missing so just ask for one more byte so the
                // parse is called as soon as more data is received.
                let consumed = input.len();
                let needed = consumed + 1;
                return AppLayerResult::incomplete(consumed as u32, needed as u32);
            }
            Err(_e) => {
                SCLogDebug!("e {:?}", _e);
                return AppLayerResult::err();
            }
        }
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        /* this parser should never get response data */
        if !input.is_empty() {
            return AppLayerResult::err();
        }
        return AppLayerResult::ok();
    }
}

// C exports.

extern "C" fn sslproxy_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = SSLProxyState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn sslproxy_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut SSLProxyState));
}

unsafe extern "C" fn sslproxy_state_tx_free(_state: *mut c_void, _tx_id: u64) {
}

unsafe extern "C" fn sslproxy_parse_request(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, SSLProxyState);

    let buf = stream_slice.as_slice();
    state.parse_request(flow, buf)
}

unsafe extern "C" fn sslproxy_parse_response(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, SSLProxyState);

    let buf = stream_slice.as_slice();
    state.parse_response(buf)
}

unsafe extern "C" fn sslproxy_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, SSLProxyState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn sslproxy_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, SSLProxyState);
    return state.tx_id;
}

unsafe extern "C" fn sslproxy_tx_get_alstate_progress(_tx: *mut c_void, _direction: u8) -> c_int {
    return 1;
}

export_tx_data_get!(sslproxy_get_tx_data, SSLProxyTransaction);
export_state_data_get!(sslproxy_get_state_data, SSLProxyState);

fn register_pattern_probe(proto: u8) -> i8 {
    let methods: Vec<&str> = vec![
        "SSLproxy:\0",
    ];
    let mut r = 0;
    unsafe {
        for method in methods {
            let depth = (method.len() - 1) as u16;
            r |= SCAppLayerProtoDetectPMRegisterPatternCS(
                proto,
                ALPROTO_SSLPROXY,
                method.as_ptr() as *const std::os::raw::c_char,
                depth,
                0,
                Direction::ToServer as u8,
            );
        }
    }

    if r == 0 {
        return 0;
    } else {
        return -1;
    }
}

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"sslproxy\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterSSLProxyParser() {
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: sslproxy_state_new,
        state_free: sslproxy_state_free,
        tx_free: sslproxy_state_tx_free,
        parse_ts: sslproxy_parse_request,
        parse_tc: sslproxy_parse_response,
        get_tx_count: sslproxy_state_get_tx_count,
        get_tx: sslproxy_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: sslproxy_tx_get_alstate_progress,
        get_eventinfo: Some(SSLProxyEvent::get_event_info),
        get_eventinfo_byid: Some(SSLProxyEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<SSLProxyState, SSLProxyTransaction>),
        get_tx_data: sslproxy_get_tx_data,
        get_state_data: sslproxy_get_state_data,
        apply_tx_config: None,
        flags: 0, // no GAPS
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_SSLPROXY = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if register_pattern_probe(IPPROTO_TCP) < 0 {
            return;
        }
        SCLogDebug!("Rust sslproxy parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for SSLPROXY.");
    }
}
