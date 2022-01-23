/* Copyright (C) 2019-2022 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::applayer::{self, *};
use crate::core;
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN};
use crate::sip::parser::*;
use nom7::Err;
use std;
use std::ffi::CString;

#[derive(AppLayerFrameType)]
pub enum SIPFrameType {
    Pdu,
    RequestLine,
    ResponseLine,
    RequestHeaders,
    ResponseHeaders,
    RequestBody,
    ResponseBody,
}

#[derive(AppLayerEvent)]
pub enum SIPEvent {
    IncompleteData,
    InvalidData,
}

pub struct SIPState {
    transactions: Vec<SIPTransaction>,
    tx_id: u64,
}

impl State<SIPTransaction> for SIPState {
    fn get_transactions(&self) -> &[SIPTransaction] {
        &self.transactions
    }
}

pub struct SIPTransaction {
    id: u64,
    pub request: Option<Request>,
    pub response: Option<Response>,
    pub request_line: Option<String>,
    pub response_line: Option<String>,
    tx_data: applayer::AppLayerTxData,
}

impl Transaction for SIPTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl SIPState {
    pub fn new() -> SIPState {
        SIPState {
            transactions: Vec::new(),
            tx_id: 0,
        }
    }

    pub fn free(&mut self) {
        self.transactions.clear();
    }

    fn new_tx(&mut self) -> SIPTransaction {
        self.tx_id += 1;
        SIPTransaction::new(self.tx_id)
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&SIPTransaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self
            .transactions
            .iter()
            .position(|tx| tx.id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    fn set_event(&mut self, event: SIPEvent) {
        if let Some(tx) = self.transactions.last_mut() {
            tx.tx_data.set_event(event as u8);
        }
    }

    fn parse_request(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
        match sip_parse_request_frames(flow, &stream_slice) {
            Ok((_, request)) => {
                let mut tx = self.new_tx();
                tx.request = Some(request);
                if let Ok((_, req_line)) = sip_take_line(stream_slice.as_slice()) {
                    tx.request_line = req_line;
                }
                self.transactions.push(tx);
                return true;
            }
            Err(Err::Incomplete(_)) => {
                self.set_event(SIPEvent::IncompleteData);
                return false;
            }
            Err(_) => {
                self.set_event(SIPEvent::InvalidData);
                return false;
            }
        }
    }

    fn parse_response(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
        match sip_parse_response_frames(flow, &stream_slice) {
            Ok((_, response)) => {
                let mut tx = self.new_tx();
                tx.response = Some(response);
                if let Ok((_, resp_line)) = sip_take_line(stream_slice.as_slice()) {
                    tx.response_line = resp_line;
                }
                self.transactions.push(tx);
                return true;
            }
            Err(Err::Incomplete(_)) => {
                self.set_event(SIPEvent::IncompleteData);
                return false;
            }
            Err(_) => {
                self.set_event(SIPEvent::InvalidData);
                return false;
            }
        }
    }
}

impl SIPTransaction {
    pub fn new(id: u64) -> SIPTransaction {
        SIPTransaction {
            id,
            request: None,
            response: None,
            request_line: None,
            response_line: None,
            tx_data: applayer::AppLayerTxData::new(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_sip_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = SIPState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_sip_state_free(state: *mut std::os::raw::c_void) {
    let mut state = unsafe { Box::from_raw(state as *mut SIPState) };
    state.free();
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, SIPState);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, SIPState);
    state.tx_id
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, SIPState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_sip_tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    1
}

static mut ALPROTO_SIP: AppProto = ALPROTO_UNKNOWN;

#[no_mangle]
pub unsafe extern "C" fn rs_sip_probing_parser_ts(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    if sip_parse_request(buf).is_ok() {
        return ALPROTO_SIP;
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_probing_parser_tc(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    if sip_parse_response(buf).is_ok() {
        return ALPROTO_SIP;
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_parse_request(
    flow: *const core::Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, SIPState);
    state.parse_request(flow, stream_slice).into()
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_parse_response(
    flow: *const core::Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, SIPState);
    state.parse_response(flow, stream_slice).into()
}

export_tx_data_get!(rs_sip_get_tx_data, SIPTransaction);

const PARSER_NAME: &'static [u8] = b"sip\0";

#[no_mangle]
pub unsafe extern "C" fn rs_sip_register_parser() {
    let default_port = CString::new("[5060,5061]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: core::IPPROTO_UDP,
        probe_ts: Some(rs_sip_probing_parser_ts),
        probe_tc: Some(rs_sip_probing_parser_tc),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_sip_state_new,
        state_free: rs_sip_state_free,
        tx_free: rs_sip_state_tx_free,
        parse_ts: rs_sip_parse_request,
        parse_tc: rs_sip_parse_response,
        get_tx_count: rs_sip_state_get_tx_count,
        get_tx: rs_sip_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_sip_tx_get_alstate_progress,
        get_eventinfo: Some(SIPEvent::get_event_info),
        get_eventinfo_byid: Some(SIPEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<SIPState, SIPTransaction>),
        get_tx_data: rs_sip_get_tx_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate: None,
        get_frame_id_by_name: Some(SIPFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(SIPFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detecter and parser disabled for SIP/UDP.");
    }
}
