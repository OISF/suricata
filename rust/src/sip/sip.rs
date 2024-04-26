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
use crate::core::{AppProto, ALPROTO_UNKNOWN, IPPROTO_TCP, IPPROTO_UDP};
use crate::frames::*;
use crate::sip::parser::*;
use nom7::Err;
use std;
use std::collections::VecDeque;
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
    transactions: VecDeque<SIPTransaction>,
    tx_id: u64,
    request_frame: Option<Frame>,
    response_frame: Option<Frame>,
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
        if let Some(tx) = self.transactions.back_mut() {
            tx.tx_data.set_event(event as u8);
        }
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
            None,
        );
        SCLogDebug!("ts: pdu {:?}", _pdu);

        match sip_parse_request(input) {
            Ok((_, request)) => {
                let mut tx = self.new_tx(crate::core::Direction::ToServer);
                sip_frames_ts(flow, &stream_slice, &request, tx.id);
                tx.request = Some(request);
                if let Ok((_, req_line)) = sip_take_line(input) {
                    tx.request_line = req_line;
                }
                self.transactions.push_back(tx);
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

        let mut start = input;
        while !start.is_empty() {
            if self.request_frame.is_none() {
                self.request_frame = Frame::new(
                    flow,
                    &stream_slice,
                    start,
                    -1_i64,
                    SIPFrameType::Pdu as u8,
                    None,
                );
                SCLogDebug!("ts: pdu {:?}", self.request_frame);
            }
            match sip_parse_request(start) {
                Ok((rem, request)) => {
                    let mut tx = self.new_tx(crate::core::Direction::ToServer);
                    let tx_id = tx.id;
                    sip_frames_ts(flow, &stream_slice, &request, tx_id);
                    tx.request = Some(request);
                    if let Ok((_, req_line)) = sip_take_line(input) {
                        tx.request_line = req_line;
                    }
                    self.transactions.push_back(tx);
                    let consumed = start.len() - rem.len();
                    start = rem;

                    if let Some(frame) = &self.request_frame {
                        frame.set_len(flow, consumed as i64);
                        frame.set_tx(flow, tx_id);
                        self.request_frame = None;
                    }
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

    fn parse_response(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let _pdu = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            SIPFrameType::Pdu as u8,
            None,
        );
        SCLogDebug!("tc: pdu {:?}", _pdu);

        match sip_parse_response(input) {
            Ok((_, response)) => {
                let mut tx = self.new_tx(crate::core::Direction::ToClient);
                sip_frames_tc(flow, &stream_slice, &response, tx.id);
                tx.response = Some(response);
                if let Ok((_, resp_line)) = sip_take_line(input) {
                    tx.response_line = resp_line;
                }
                self.transactions.push_back(tx);
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

        let mut start = input;
        while !start.is_empty() {
            if self.response_frame.is_none() {
                self.response_frame = Frame::new(
                    flow,
                    &stream_slice,
                    start,
                    -1_i64,
                    SIPFrameType::Pdu as u8,
                    None,
                );
                SCLogDebug!("tc: pdu {:?}", self.request_frame);
            }
            match sip_parse_response(start) {
                Ok((rem, response)) => {
                    let mut tx = self.new_tx(crate::core::Direction::ToClient);
                    let tx_id = tx.id;
                    sip_frames_tc(flow, &stream_slice, &response, tx_id);
                    tx.response = Some(response);
                    if let Ok((_, resp_line)) = sip_take_line(input) {
                        tx.response_line = resp_line;
                    }
                    self.transactions.push_back(tx);
                    let consumed = start.len() - rem.len();
                    start = rem;

                    if let Some(frame) = &self.response_frame {
                        frame.set_len(flow, consumed as i64);
                        frame.set_tx(flow, tx_id);
                        self.response_frame = None;
                    }
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
fn sip_frames_ts(flow: *const core::Flow, stream_slice: &StreamSlice, r: &Request, tx_id: u64) {
    let oi = stream_slice.as_slice();
    let _f = Frame::new(
        flow,
        stream_slice,
        oi,
        r.request_line_len as i64,
        SIPFrameType::RequestLine as u8,
        Some(tx_id),
    );
    SCLogDebug!("ts: request_line {:?}", _f);
    let hi = &oi[r.request_line_len as usize..];
    let _f = Frame::new(
        flow,
        stream_slice,
        hi,
        r.headers_len as i64,
        SIPFrameType::RequestHeaders as u8,
        Some(tx_id),
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
            Some(tx_id),
        );
        SCLogDebug!("ts: request_body {:?}", _f);
    }
}
// app-layer-frame-documentation tag end: function to add frames

fn sip_frames_tc(flow: *const core::Flow, stream_slice: &StreamSlice, r: &Response, tx_id: u64) {
    let oi = stream_slice.as_slice();
    let _f = Frame::new(
        flow,
        stream_slice,
        oi,
        r.response_line_len as i64,
        SIPFrameType::ResponseLine as u8,
        Some(tx_id),
    );
    let hi = &oi[r.response_line_len as usize..];
    SCLogDebug!("tc: response_line {:?}", _f);
    let _f = Frame::new(
        flow,
        stream_slice,
        hi,
        r.headers_len as i64,
        SIPFrameType::ResponseHeaders as u8,
        Some(tx_id),
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
            Some(tx_id),
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
    ];
    let mut r = 0;
    unsafe {
        for method in methods {
            let depth = (method.len() - 1) as u16;
            r |= AppLayerProtoDetectPMRegisterPatternCS(
                proto,
                ALPROTO_SIP,
                method.as_ptr() as *const std::os::raw::c_char,
                depth,
                0,
                core::Direction::ToServer as u8,
            );
        }
        r |= AppLayerProtoDetectPMRegisterPatternCS(
            proto,
            ALPROTO_SIP,
            b"SIP/2.0\0".as_ptr() as *const std::os::raw::c_char,
            8,
            0,
            core::Direction::ToClient as u8,
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
    let mut parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: core::IPPROTO_UDP,
        probe_ts: None,
        probe_tc: None,
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
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if register_pattern_probe(core::IPPROTO_UDP) < 0 {
            return;
        }
        AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SIP);
    } else {
        SCLogDebug!("Protocol detection and parsing disabled for UDP SIP.");
    }

    // register TCP parser
    parser.ipproto = core::IPPROTO_TCP;
    parser.probe_ts = None;
    parser.probe_tc = None;
    parser.parse_ts = rs_sip_parse_request_tcp;
    parser.parse_tc = rs_sip_parse_response_tcp;

    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if register_pattern_probe(core::IPPROTO_TCP) < 0 {
            return;
        }
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SIP);
    } else {
        SCLogDebug!("Protocol detection and parsing disabled for TCP SIP.");
    }
}
