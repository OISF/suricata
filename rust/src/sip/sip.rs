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
use crate::core::{AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN};
use crate::frames::*;
use crate::sip::parser::*;
use nom7::Err;
use std;
use std::ffi::CString;

// app-layer-frame-documentation tag start: FrameType enum
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
// app-layer-frame-documentation tag end: FrameType enum

#[derive(AppLayerEvent)]
pub enum SIPEvent {
    IncompleteData,
    InvalidData,
}

#[derive(Default)]
pub struct SIPState {
    state_data: AppLayerStateData,
    transactions: Vec<SIPTransaction>,
    tx_id: u64,
}

impl State<SIPTransaction> for SIPState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&SIPTransaction> {
        self.transactions.get(index)
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
        Default::default()
    }

    pub fn free(&mut self) {
        self.transactions.clear();
    }

    fn new_tx(&mut self, direction: crate::core::Direction) -> SIPTransaction {
        self.tx_id += 1;
        SIPTransaction::new(self.tx_id, direction)
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&SIPTransaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self.transactions.iter().position(|tx| tx.id == tx_id + 1);
        debug_assert!(tx.is_some());
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    fn set_event(&mut self, event: SIPEvent) {
        if let Some(tx) = self.transactions.last_mut() {
            tx.tx_data.set_event(event as u8);
        }
    }

    fn build_tx_request(&mut self, input: &[u8], request: Request) {
        let mut tx = self.new_tx(crate::core::Direction::ToServer);
        tx.request = Some(request);
        if let Ok((_, req_line)) = sip_take_line(input) {
            tx.request_line = req_line;
        }
        self.transactions.push(tx);
    }

    // app-layer-frame-documentation tag start: parse_request
    fn parse_request(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let _pdu = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            SIPFrameType::Pdu as u8,
        );
        SCLogDebug!("ts: pdu {:?}", _pdu);

        match sip_parse_request(input) {
            Ok((_, request)) => {
                sip_frames_ts(flow, &stream_slice, &request);
                self.build_tx_request(input, request);
                return true;
            }
            // app-layer-frame-documentation tag end: parse_request
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

    fn parse_request_tcp(
        &mut self, flow: *const core::Flow, stream_slice: StreamSlice,
    ) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }
        let _pdu = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            SIPFrameType::Pdu as u8,
        );
        SCLogDebug!("ts: pdu {:?}", _pdu);

        let mut start = input;
        while !start.is_empty() {
            match sip_parse_request(input) {
                Ok((rem, request)) => {
                    start = rem;
                    sip_frames_ts(flow, &stream_slice, &request);
                    self.build_tx_request(input, request);
                }
                Err(Err::Incomplete(_needed)) => {
                    let consumed = input.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogDebug!(
                        "Needed: {:?}, estimated needed: {:?}",
                        _needed,
                        needed_estimation
                    );
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                }
                Err(_) => {
                    self.set_event(SIPEvent::InvalidData);
                    return AppLayerResult::err();
                }
            }
        }

        // input fully consumed.
        return AppLayerResult::ok();
    }

    fn build_tx_response(&mut self, input: &[u8], response: Response) {
        let mut tx = self.new_tx(crate::core::Direction::ToClient);
        tx.response = Some(response);
        if let Ok((_, resp_line)) = sip_take_line(input) {
            tx.response_line = resp_line;
        }
        self.transactions.push(tx);
    }

    fn parse_response(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let _pdu = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            SIPFrameType::Pdu as u8,
        );
        SCLogDebug!("tc: pdu {:?}", _pdu);

        match sip_parse_response(input) {
            Ok((_, response)) => {
                sip_frames_tc(flow, &stream_slice, &response);
                self.build_tx_response(input, response);
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

    fn parse_response_tcp(
        &mut self, flow: *const core::Flow, stream_slice: StreamSlice,
    ) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }
        let _pdu = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            SIPFrameType::Pdu as u8,
        );
        SCLogDebug!("tc: pdu {:?}", _pdu);

        let mut start = input;
        while !start.is_empty() {
            match sip_parse_response(input) {
                Ok((rem, response)) => {
                    start = rem;
                    sip_frames_tc(flow, &stream_slice, &response);
                    self.build_tx_response(input, response);
                }
                Err(Err::Incomplete(_needed)) => {
                    let consumed = input.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogDebug!(
                        "Needed: {:?}, estimated needed: {:?}",
                        _needed,
                        needed_estimation
                    );
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                }
                Err(_) => {
                    self.set_event(SIPEvent::InvalidData);
                    return AppLayerResult::err();
                }
            }
        }

        // input fully consumed.
        return AppLayerResult::ok();
    }
}

impl SIPTransaction {
    pub fn new(id: u64, direction: crate::core::Direction) -> SIPTransaction {
        SIPTransaction {
            id,
            request: None,
            response: None,
            request_line: None,
            response_line: None,
            tx_data: applayer::AppLayerTxData::for_direction(direction),
        }
    }
}

// app-layer-frame-documentation tag start: function to add frames
fn sip_frames_ts(flow: *const core::Flow, stream_slice: &StreamSlice, r: &Request) {
    let oi = stream_slice.as_slice();
    let _f = Frame::new(
        flow,
        stream_slice,
        oi,
        r.request_line_len as i64,
        SIPFrameType::RequestLine as u8,
    );
    SCLogDebug!("ts: request_line {:?}", _f);
    let hi = &oi[r.request_line_len as usize..];
    let _f = Frame::new(
        flow,
        stream_slice,
        hi,
        r.headers_len as i64,
        SIPFrameType::RequestHeaders as u8,
    );
    SCLogDebug!("ts: request_headers {:?}", _f);
    if r.body_len > 0 {
        let bi = &oi[r.body_offset as usize..];
        let _f = Frame::new(
            flow,
            stream_slice,
            bi,
            r.body_len as i64,
            SIPFrameType::RequestBody as u8,
        );
        SCLogDebug!("ts: request_body {:?}", _f);
    }
}
// app-layer-frame-documentation tag end: function to add frames

fn sip_frames_tc(flow: *const core::Flow, stream_slice: &StreamSlice, r: &Response) {
    let oi = stream_slice.as_slice();
    let _f = Frame::new(
        flow,
        stream_slice,
        oi,
        r.response_line_len as i64,
        SIPFrameType::ResponseLine as u8,
    );
    let hi = &oi[r.response_line_len as usize..];
    SCLogDebug!("tc: response_line {:?}", _f);
    let _f = Frame::new(
        flow,
        stream_slice,
        hi,
        r.headers_len as i64,
        SIPFrameType::ResponseHeaders as u8,
    );
    SCLogDebug!("tc: response_headers {:?}", _f);
    if r.body_len > 0 {
        let bi = &oi[r.body_offset as usize..];
        let _f = Frame::new(
            flow,
            stream_slice,
            bi,
            r.body_len as i64,
            SIPFrameType::ResponseBody as u8,
        );
        SCLogDebug!("tc: response_body {:?}", _f);
    }
}

#[no_mangle]
pub extern "C" fn rs_sip_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
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
    state: *mut std::os::raw::c_void, tx_id: u64,
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
    _tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    1
}

static mut ALPROTO_SIP: AppProto = ALPROTO_UNKNOWN;

#[no_mangle]
pub unsafe extern "C" fn rs_sip_probing_parser_ts(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    if sip_parse_request(buf).is_ok() {
        return ALPROTO_SIP;
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_probing_parser_tcp_ts(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if !input.is_null() {
        let buf = build_slice!(input, input_len as usize);
        match sip_parse_request(buf) {
            Ok((_, _request)) => {
                return ALPROTO_SIP;
            }
            Err(Err::Incomplete(_)) => {
                return ALPROTO_UNKNOWN;
            }
            Err(_e) => {
                return ALPROTO_FAILED;
            }
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_probing_parser_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    if sip_parse_response(buf).is_ok() {
        return ALPROTO_SIP;
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_probing_parser_tcp_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if !input.is_null() {
        let buf = build_slice!(input, input_len as usize);
        match sip_parse_response(buf) {
            Ok((_, _response)) => {
                return ALPROTO_SIP;
            }
            Err(Err::Incomplete(_)) => {
                return ALPROTO_UNKNOWN;
            }
            Err(_e) => {
                return ALPROTO_FAILED;
            }
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_parse_request(
    flow: *const core::Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, SIPState);
    state.parse_request(flow, stream_slice).into()
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_parse_request_tcp(
    flow: *const core::Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }

    let state = cast_pointer!(state, SIPState);
    state.parse_request_tcp(flow, stream_slice)
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_parse_response(
    flow: *const core::Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, SIPState);
    state.parse_response(flow, stream_slice).into()
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_parse_response_tcp(
    flow: *const core::Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }

    let state = cast_pointer!(state, SIPState);
    state.parse_response_tcp(flow, stream_slice)
}

fn register_pattern_probe(proto: u8) -> i8 {
    let methods: Vec<&str> = vec![
        "REGISTER\0",
        "INVITE\0",
        "ACK\0",
        "BYE\0",
        "CANCEL\0",
        "UPDATE\0",
        "REFER\0",
        "PRACK\0",
        "SUBSCRIBE\0",
        "NOTIFY\0",
        "PUBLISH\0",
        "MESSAGE\0",
        "INFO\0",
        "OPTIONS\0",
    ];
    let mut r = 0;
    unsafe {
        for method in methods {
            let depth = (method.len() - 1) as u16;
            r |= AppLayerProtoDetectPMRegisterPatternCSwPP(
                proto,
                ALPROTO_SIP,
                method.as_ptr() as *const std::os::raw::c_char,
                depth,
                0,
                core::Direction::ToServer as u8,
                rs_sip_probing_parser_tcp_ts,
                0,
                0,
            );
        }
        r |= AppLayerProtoDetectPMRegisterPatternCSwPP(
            proto,
            ALPROTO_SIP,
            b"SIP/2.0\0".as_ptr() as *const std::os::raw::c_char,
            8,
            0,
            core::Direction::ToClient as u8,
            rs_sip_probing_parser_tcp_tc,
            0,
            0,
        );
    }

    if r == 0 {
        return 0;
    } else {
        return -1;
    }
}

export_tx_data_get!(rs_sip_get_tx_data, SIPTransaction);
export_state_data_get!(rs_sip_get_state_data, SIPState);

const PARSER_NAME: &[u8] = b"sip\0";

#[no_mangle]
pub unsafe extern "C" fn rs_sip_register_parser() {
    let default_port = CString::new("[5060,5061]").unwrap();
    let mut parser = RustParser {
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
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<SIPState, SIPTransaction>),
        get_tx_data: rs_sip_get_tx_data,
        get_state_data: rs_sip_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: Some(SIPFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(SIPFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SIP = alproto;
        if register_pattern_probe(core::IPPROTO_UDP) < 0 {
            return;
        }
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detection and parsing disabled for UDP SIP.");
    }

    // register TCP parser
    parser.ipproto = core::IPPROTO_TCP;
    parser.probe_ts = Some(rs_sip_probing_parser_tcp_ts);
    parser.probe_tc = Some(rs_sip_probing_parser_tcp_tc);
    parser.parse_ts = rs_sip_parse_request_tcp;
    parser.parse_tc = rs_sip_parse_response_tcp;

    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SIP = alproto;
        if register_pattern_probe(core::IPPROTO_TCP) < 0 {
            return;
        }
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detection and parsing disabled for TCP SIP.");
    }
}
