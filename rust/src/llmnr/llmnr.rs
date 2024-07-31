/* Copyright (C) 2026 Open Information Security Foundation
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

use std;
use std::collections::VecDeque;
use std::ffi::CString;

use crate::applayer::*;
use crate::core::{self, *};
use crate::direction::Direction;
use crate::direction::DIR_BOTH;
use crate::dns::dns::{DNSHeader, DNSMessage};
use crate::dns::*;
use crate::flow::Flow;
use crate::frames::Frame;

use nom8::number::streaming::be_u16;
use nom8::{Err, IResult};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

static mut ALPROTO_LLMNR: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerFrameType)]
enum LLMNRFrameType {
    Pdu,
}

#[derive(Debug, PartialEq, Eq, AppLayerEvent)]
pub enum LLMNREvent {
    MalformedData,
    NotRequest,
    NotResponse,
    ZFlagSet,
    InvalidOpcode,
}

#[derive(Debug, Default)]
pub struct LLMNRTransaction {
    pub id: u64,
    pub request: Option<DNSMessage>,
    pub response: Option<DNSMessage>,
    pub tx_data: AppLayerTxData,
}

impl Transaction for LLMNRTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl LLMNRTransaction {
    fn new(direction: Direction) -> Self {
        Self {
            tx_data: AppLayerTxData::for_direction(direction),
            ..Default::default()
        }
    }

    /// Get the LLMNR transactions ID (not the internal tracking ID).
    pub fn tx_id(&self) -> u16 {
        if let Some(request) = &self.request {
            return request.header.tx_id;
        }
        if let Some(response) = &self.response {
            return response.header.tx_id;
        }

        // Shouldn't happen.
        return 0;
    }
}

#[derive(Default)]
pub struct LLMNRState {
    state_data: AppLayerStateData,

    // Internal transaction ID.
    tx_id: u64,

    // Transactions.
    transactions: VecDeque<LLMNRTransaction>,

    // TCP gap tracking.
    gap: bool,
}

impl State<LLMNRTransaction> for LLMNRState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&LLMNRTransaction> {
        self.transactions.get(index)
    }
}

impl LLMNRState {
    fn new() -> Self {
        Default::default()
    }

    fn new_tx(&mut self, direction: Direction) -> LLMNRTransaction {
        let mut tx = LLMNRTransaction::new(direction);
        self.tx_id += 1;
        tx.id = self.tx_id;
        return tx;
    }

    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    fn get_tx(&mut self, tx_id: u64) -> Option<&LLMNRTransaction> {
        return self.transactions.iter().find(|&tx| tx.id == tx_id + 1);
    }

    /// Set an event. The event is set on the most recent transaction.
    fn set_event(&mut self, event: LLMNREvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let tx = &mut self.transactions[len - 1];
        tx.tx_data.set_event(event as u8);
    }

    fn validate_header<'a>(&self, input: &'a [u8]) -> Option<(&'a [u8], DNSHeader)> {
        if let Ok((body, header)) = crate::dns::parser::dns_parse_header(input) {
            if crate::dns::dns::probe_header_validity(&header, input.len()).0 {
                return Some((body, header));
            }
        }
        None
    }

    fn parse_request(
        &mut self, input: &[u8], is_tcp: bool, frame: Option<Frame>, flow: *mut Flow,
    ) -> bool {
        let (body, header) = if let Some((body, header)) = self.validate_header(input) {
            (body, header)
        } else {
            return !is_tcp;
        };

        match crate::dns::parser::dns_parse_body(body, input, header) {
            Ok((_, (request, _parse_flags))) => {
                if request.header.flags & 0x8000 != 0 {
                    SCLogDebug!("LLMNR message is not a request");
                    self.set_event(LLMNREvent::NotRequest);
                    return false;
                }

                let flags = request.header.flags;
                let opcode = ((flags >> 11) & 0xf) as u8;

                let mut tx = self.new_tx(Direction::ToServer);
                if let Some(frame) = frame {
                    frame.set_tx(flow, tx.id);
                }
                tx.request = Some(request);
                self.transactions.push_back(tx);

                if opcode != 0 {
                    self.set_event(LLMNREvent::InvalidOpcode);
                }

                if flags & 0x00F0 != 0 {
                    self.set_event(LLMNREvent::ZFlagSet);
                }

                return true;
            }
            Err(Err::Incomplete(_)) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing LLMNR request");
                self.set_event(LLMNREvent::MalformedData);
                return false;
            }
            Err(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing LLMNR request");
                self.set_event(LLMNREvent::MalformedData);
                return false;
            }
        }
    }

    fn parse_request_udp(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let frame = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            LLMNRFrameType::Pdu as u8,
            None,
        );
        self.parse_request(input, false, frame, flow)
    }

    fn request_gap(&mut self, gap: u32) {
        if gap > 0 {
            self.gap = true;
        }
    }

    fn response_gap(&mut self, gap: u32) {
        if gap > 0 {
            self.gap = true;
        }
    }

    fn parse_request_tcp(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if self.gap {
            let (is_llmnr, _, is_incomplete) = probe_tcp(input);
            if is_llmnr || is_incomplete {
                self.gap = false;
            } else {
                return AppLayerResult::ok();
            }
        }

        let mut cur_i = input;
        let mut consumed = 0;
        while !cur_i.is_empty() {
            if cur_i.len() == 1 {
                return AppLayerResult::incomplete(consumed as u32, 2_u32);
            }
            let size = match be_u16(cur_i) as IResult<&[u8], u16> {
                Ok((_, len)) => len,
                _ => 0,
            } as usize;
            if size > 0 && cur_i.len() >= size + 2 {
                let msg = &cur_i[2..(size + 2)];
                sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToServer as i32);
                let frame = Frame::new(
                    flow,
                    &stream_slice,
                    msg,
                    msg.len() as i64,
                    LLMNRFrameType::Pdu as u8,
                    None,
                );
                if self.parse_request(msg, true, frame, flow) {
                    cur_i = &cur_i[(size + 2)..];
                    consumed += size + 2;
                } else {
                    return AppLayerResult::err();
                }
            } else if size == 0 {
                cur_i = &cur_i[2..];
                consumed += 2;
            } else {
                return AppLayerResult::incomplete(consumed as u32, (size + 2) as u32);
            }
        }
        AppLayerResult::ok()
    }

    fn parse_response_tcp(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if self.gap {
            let (is_llmnr, _, is_incomplete) = probe_tcp(input);
            if is_llmnr || is_incomplete {
                self.gap = false;
            } else {
                return AppLayerResult::ok();
            }
        }

        let mut cur_i = input;
        let mut consumed = 0;
        while !cur_i.is_empty() {
            if cur_i.len() == 1 {
                return AppLayerResult::incomplete(consumed as u32, 2_u32);
            }
            let size = match be_u16(cur_i) as IResult<&[u8], u16> {
                Ok((_, len)) => len,
                _ => 0,
            } as usize;
            if size > 0 && cur_i.len() >= size + 2 {
                let msg = &cur_i[2..(size + 2)];
                sc_app_layer_parser_trigger_raw_stream_inspection(flow, Direction::ToClient as i32);
                let frame = Frame::new(
                    flow,
                    &stream_slice,
                    msg,
                    msg.len() as i64,
                    LLMNRFrameType::Pdu as u8,
                    None,
                );
                if self.parse_response(msg, true, frame, flow) {
                    cur_i = &cur_i[(size + 2)..];
                    consumed += size + 2;
                } else {
                    return AppLayerResult::err();
                }
            } else if size == 0 {
                cur_i = &cur_i[2..];
                consumed += 2;
            } else {
                return AppLayerResult::incomplete(consumed as u32, (size + 2) as u32);
            }
        }
        AppLayerResult::ok()
    }

    fn parse_response_udp(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> bool {
        let input = stream_slice.as_slice();
        let frame = Frame::new(
            flow,
            &stream_slice,
            input,
            input.len() as i64,
            LLMNRFrameType::Pdu as u8,
            None,
        );
        self.parse_response(input, false, frame, flow)
    }

    fn parse_response(
        &mut self, input: &[u8], is_tcp: bool, frame: Option<Frame>, flow: *mut Flow,
    ) -> bool {
        let (body, header) = if let Some((body, header)) = self.validate_header(input) {
            (body, header)
        } else {
            return !is_tcp;
        };

        match crate::dns::parser::dns_parse_body(body, input, header) {
            Ok((_, (response, _parse_flags))) => {
                SCLogDebug!("Response header flags: {}", response.header.flags);

                if response.header.flags & 0x8000 == 0 {
                    SCLogDebug!("LLMNR message is not a response");
                    self.set_event(LLMNREvent::NotResponse);
                    return false;
                }

                let flags = response.header.flags;
                let opcode = ((flags >> 11) & 0xf) as u8;

                let mut tx = self.new_tx(Direction::ToClient);
                if let Some(frame) = frame {
                    frame.set_tx(flow, tx.id);
                }

                tx.response = Some(response);
                self.transactions.push_back(tx);

                if opcode != 0 {
                    self.set_event(LLMNREvent::InvalidOpcode);
                }

                if flags & 0x00F0 != 0 {
                    self.set_event(LLMNREvent::ZFlagSet);
                }

                return true;
            }
            Err(Err::Incomplete(_)) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing LLMNR response");
                self.set_event(LLMNREvent::MalformedData);
                return false;
            }
            Err(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing LLMNR response");
                self.set_event(LLMNREvent::MalformedData);
                return false;
            }
        }
    }
}

/// Probe input to see if it looks like LLMNR.
///
/// Returns a tuple of booleans: (is_llmnr, is_request, incomplete)
fn probe(input: &[u8], dlen: usize) -> (bool, bool, bool) {
    // Trim input to dlen if larger.
    let input = if input.len() <= dlen {
        input
    } else {
        &input[..dlen]
    };

    // If input is less than dlen then we know we don't have enough data to
    // parse a complete message, so perform header validation only.
    if input.len() < dlen {
        if let Ok((_, header)) = crate::dns::parser::dns_parse_header(input) {
            return crate::dns::dns::probe_header_validity(&header, dlen);
        } else {
            return (false, false, false);
        }
    }

    match parser::dns_parse_header(input) {
        Ok((body, header)) => match crate::dns::parser::dns_parse_body(body, input, header) {
            Ok((_, (request, _flags))) => {
                crate::dns::dns::probe_header_validity(&request.header, dlen)
            }
            Err(Err::Incomplete(_)) => (false, false, true),
            Err(_) => (false, false, false),
        },
        Err(_) => (false, false, false),
    }
}

unsafe extern "C" fn probe_udp(
    _flow: *const Flow, _dir: u8, input: *const u8, len: u32, rdir: *mut u8,
) -> AppProto {
    if input.is_null() || len < std::mem::size_of::<DNSHeader>() as u32 {
        return core::ALPROTO_UNKNOWN;
    }
    let slice: &[u8] = std::slice::from_raw_parts(input as *mut u8, len as usize);
    let (is_dns, is_request, _) = probe(slice, slice.len());
    if is_dns {
        let dir = if is_request {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        *rdir = dir as u8;
        return ALPROTO_LLMNR;
    }
    return 0;
}

/// Probe TCP input to see if it looks like LLMNR.
fn probe_tcp(input: &[u8]) -> (bool, bool, bool) {
    match be_u16(input) as IResult<&[u8], u16> {
        Ok((rem, dlen)) => {
            return probe(rem, dlen as usize);
        }
        Err(Err::Incomplete(_)) => {
            return (false, false, true);
        }
        _ => {}
    }
    return (false, false, false);
}

unsafe extern "C" fn probe_tcp_c(
    _flow: *const Flow, direction: u8, input: *const u8, len: u32, rdir: *mut u8,
) -> AppProto {
    if input.is_null() || len < std::mem::size_of::<DNSHeader>() as u32 + 2 {
        return core::ALPROTO_UNKNOWN;
    }
    let slice: &[u8] = std::slice::from_raw_parts(input as *mut u8, len as usize);
    let (is_llmnr, is_request, _) = probe_tcp(slice);
    if is_llmnr {
        let dir = if is_request {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        if (direction & DIR_BOTH) != u8::from(dir) {
            *rdir = dir as u8;
        }
        return ALPROTO_LLMNR;
    }
    return 0;
}

/// Returns *mut LLMNRState
unsafe extern "C" fn state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = LLMNRState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

/// Params:
/// - state: *mut LLMNRState as void pointer
extern "C" fn state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(unsafe { Box::from_raw(state as *mut LLMNRState) });
}

unsafe extern "C" fn state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, LLMNRState);
    state.free_tx(tx_id);
}

extern "C" fn tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    // This is a stateless parser, just the existence of a transaction
    // means its complete.
    SCLogDebug!("rs_llmnr_tx_get_alstate_progress");
    return 1;
}

unsafe extern "C" fn state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, LLMNRState);
    SCLogDebug!("rs_llmnr_state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

unsafe extern "C" fn state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, LLMNRState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

/// C binding parse a LLMNR request. Returns 1 on success, -1 on failure.
unsafe extern "C" fn parse_request(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, LLMNRState);
    state.parse_request_udp(flow, stream_slice);
    AppLayerResult::ok()
}

unsafe extern "C" fn parse_response(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, LLMNRState);
    state.parse_response_udp(flow, stream_slice);
    AppLayerResult::ok()
}

unsafe extern "C" fn parse_request_tcp_c(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, LLMNRState);
    if stream_slice.is_gap() {
        state.request_gap(stream_slice.gap_size());
    } else if !stream_slice.is_empty() {
        return state.parse_request_tcp(flow, stream_slice);
    }
    AppLayerResult::ok()
}

unsafe extern "C" fn parse_response_tcp_c(
    flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, LLMNRState);
    if stream_slice.is_gap() {
        state.response_gap(stream_slice.gap_size());
    } else if !stream_slice.is_empty() {
        return state.parse_response_tcp(flow, stream_slice);
    }
    AppLayerResult::ok()
}

unsafe extern "C" fn state_get_tx_data(
    tx: *mut std::os::raw::c_void,
) -> *mut suricata_sys::sys::AppLayerTxData {
    let tx = cast_pointer!(tx, LLMNRTransaction);
    return &mut tx.tx_data.0;
}

#[no_mangle]
pub extern "C" fn SCLLMNRTxIsRequest(tx: &mut LLMNRTransaction) -> bool {
    tx.request.is_some()
}

#[no_mangle]
pub extern "C" fn SCLLMNRTxIsResponse(tx: &mut LLMNRTransaction) -> bool {
    tx.response.is_some()
}

export_state_data_get!(rs_llmnr_get_state_data, LLMNRState);

#[no_mangle]
pub unsafe extern "C" fn SCRegisterLLMNRUdpParser() {
    let default_port = std::ffi::CString::new("5355").unwrap();
    let parser = RustParser {
        name: b"llmnr\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(probe_udp),
        probe_tc: Some(probe_udp),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16,
        state_new,
        state_free,
        tx_free: state_tx_free,
        parse_ts: parse_request,
        parse_tc: parse_response,
        get_tx_count: state_get_tx_count,
        get_tx: state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: tx_get_alstate_progress,
        get_eventinfo: Some(LLMNREvent::get_event_info),
        get_eventinfo_byid: Some(LLMNREvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<LLMNRState, LLMNRTransaction>,
        ),
        get_tx_data: state_get_tx_data,
        get_state_data: rs_llmnr_get_state_data,
        apply_tx_config: None,
        flags: 0,
        get_frame_id_by_name: Some(LLMNRFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(LLMNRFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_LLMNR = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterLLMNRTcpParser() {
    let default_port = std::ffi::CString::new("5355").unwrap();
    let parser = RustParser {
        name: b"llmnr\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(probe_tcp_c),
        probe_tc: Some(probe_tcp_c),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16 + 2,
        state_new,
        state_free,
        tx_free: state_tx_free,
        parse_ts: parse_request_tcp_c,
        parse_tc: parse_response_tcp_c,
        get_tx_count: state_get_tx_count,
        get_tx: state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: tx_get_alstate_progress,
        get_eventinfo: Some(LLMNREvent::get_event_info),
        get_eventinfo_byid: Some(LLMNREvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<LLMNRState, LLMNRTransaction>,
        ),
        get_tx_data: state_get_tx_data,
        get_state_data: rs_llmnr_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(LLMNRFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(LLMNRFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_LLMNR = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}
