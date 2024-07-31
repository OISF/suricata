/* Copyright (C) 2024 Open Information Security Foundation
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
use std::ffi::CString;

use crate::applayer::*;
use crate::core::{self, *};
use crate::dns::dns::{DNSHeader, DNSMessage};
use crate::dns::*;
use crate::frames::Frame;

use nom7::Err;

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
        &mut self, input: &[u8], is_tcp: bool, frame: Option<Frame>, flow: *const core::Flow,
    ) -> bool {
        let (body, header) = if let Some((body, header)) = self.validate_header(input) {
            (body, header)
        } else {
            return !is_tcp;
        };

        match crate::dns::parser::dns_parse_body(body, input, header) {
            Ok((_, request)) => {
                if request.header.flags & 0x8000 != 0 {
                    SCLogDebug!("LLMNR message is not a request");
                    self.set_event(LLMNREvent::NotRequest);
                    return false;
                }

                let opcode = ((request.header.flags >> 11) & 0xf) as u8;

                let mut tx = self.new_tx(Direction::ToServer);
                if let Some(frame) = frame {
                    frame.set_tx(flow, tx.id);
                }
                tx.request = Some(request);
                self.transactions.push_back(tx);

                if opcode >= 7 {
                    self.set_event(LLMNREvent::InvalidOpcode);
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

    fn parse_request_udp(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
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

    fn parse_response_udp(&mut self, flow: *const core::Flow, stream_slice: StreamSlice) -> bool {
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
        &mut self, input: &[u8], is_tcp: bool, frame: Option<Frame>, flow: *const core::Flow,
    ) -> bool {
        let (body, header) = if let Some((body, header)) = self.validate_header(input) {
            (body, header)
        } else {
            return !is_tcp;
        };

        match crate::dns::parser::dns_parse_body(body, input, header) {
            Ok((_, response)) => {
                SCLogDebug!("Response header flags: {}", response.header.flags);

                if response.header.flags & 0x8000 == 0 {
                    SCLogDebug!("DNS message is not a response");
                    self.set_event(LLMNREvent::NotResponse);
                }

                let opcode = ((response.header.flags >> 11) & 0xf) as u8;

                let mut tx = self.new_tx(Direction::ToClient);
                if let Some(frame) = frame {
                    frame.set_tx(flow, tx.id);
                }

                tx.response = Some(response);
                self.transactions.push_back(tx);

                if opcode >= 7 {
                    self.set_event(LLMNREvent::InvalidOpcode);
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

/// Probe input to see if it looks like DNS.
///
/// Returns a tuple of booleans: (is_dns, is_request, incomplete)
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
            Ok((_, request)) => crate::dns::dns::probe_header_validity(&request.header, dlen),
            Err(Err::Incomplete(_)) => (false, false, true),
            Err(_) => (false, false, false),
        },
        Err(_) => (false, false, false),
    }
}

unsafe extern "C" fn probe_udp(
    _flow: *const core::Flow, _dir: u8, input: *const u8, len: u32, rdir: *mut u8,
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

/// Returns *mut LLMNRState
extern "C" fn state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = LLMNRState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

/// Params:
/// - state: *mut DNSState as void pointer
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
    flow: *const core::Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, LLMNRState);
    state.parse_request_udp(flow, stream_slice);
    AppLayerResult::ok()
}

unsafe extern "C" fn parse_response(
    flow: *const core::Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, LLMNRState);
    state.parse_response_udp(flow, stream_slice);
    AppLayerResult::ok()
}

unsafe extern "C" fn state_get_tx_data(tx: *mut std::os::raw::c_void) -> *mut AppLayerTxData {
    let tx = cast_pointer!(tx, LLMNRTransaction);
    return &mut tx.tx_data;
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
pub unsafe extern "C" fn SCRegisterLLMNRParser() {
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
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_LLMNR = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}
