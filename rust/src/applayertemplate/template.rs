/* Copyright (C) 2018-2022 Open Information Security Foundation
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
use crate::core::{ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};
use crate::applayer::{self, *};
use std::ffi::CString;
use nom7 as nom;
use super::parser;

static mut ALPROTO_TEMPLATE: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum TemplateEvent {}

pub struct TemplateTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,

    tx_data: AppLayerTxData,
}

impl TemplateTransaction {
    pub fn new() -> TemplateTransaction {
        TemplateTransaction {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for TemplateTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

pub struct TemplateState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<TemplateTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<TemplateTransaction> for TemplateState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&TemplateTransaction> {
        self.transactions.get(index)
    }
}

impl TemplateState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            request_gap: false,
            response_gap: false,
        }
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&TemplateTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        None
    }

    fn new_tx(&mut self) -> TemplateTransaction {
        let mut tx = TemplateTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        tx
    }

    fn find_request(&mut self) -> Option<&mut TemplateTransaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this template, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request: {}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    self.transactions.push_back(tx);
                },
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                },
                Err(_) => {
                    return AppLayerResult::err();
                },
            }
        }

        // Input was fully consumed.
        AppLayerResult::ok()
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this template, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    match self.find_request() {
                        Some(tx) => {
                            tx.response = Some(response);
                            SCLogNotice!("Found response for request:");
                            SCLogNotice!("- Request: {:?}", tx.request);
                            SCLogNotice!("- Response: {:?}", tx.response);
                        }
                        None => {}
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
        AppLayerResult::ok()
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/// Probe for a valid header.
///
/// As this template protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let size = std::cmp::min(10, input.len());
    let (rem, prefix) = nom::bytes::complete::take(size)(input)?;
    nom::sequence::terminated(
        nom::bytes::complete::take_while1(nom::character::is_digit),
        nom::bytes::complete::tag(":"),
    )(prefix)?;
    Ok((rem, ()))
}

// C exports.

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_template_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_TEMPLATE;
        }
    }
    ALPROTO_UNKNOWN
}

#[no_mangle]
pub extern "C" fn rs_template_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = TemplateState::new();
    let boxed = Box::new(state);
    Box::into_raw(boxed) as *mut std::os::raw::c_void
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut TemplateState));
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, TemplateState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let eof = if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
        true
    } else {
        false
    };

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, TemplateState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let _eof = if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
        true
    } else {
        false
    };
    let state = cast_pointer!(state, TemplateState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, TemplateState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            tx as *const _ as *mut _
        }
        None => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, TemplateState);
    state.tx_id
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, TemplateTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    0
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub unsafe extern "C" fn rs_template_get_request_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, TemplateTransaction);
    if let Some(ref request) = tx.request {
        if !request.is_empty() {
            *len = request.len() as u32;
            *buf = request.as_ptr();
            return 1;
        }
    }
    0
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub unsafe extern "C" fn rs_template_get_response_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, TemplateTransaction);
    if let Some(ref response) = tx.response {
        if !response.is_empty() {
            *len = response.len() as u32;
            *buf = response.as_ptr();
            return 1;
        }
    }
    0
}

export_tx_data_get!(rs_template_get_tx_data, TemplateTransaction);
export_state_data_get!(rs_template_get_state_data, TemplateState);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"template-rust\0";

#[no_mangle]
pub unsafe extern "C" fn rs_template_register_parser() {
    let default_port = CString::new("[7000]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_template_probing_parser),
        probe_tc: Some(rs_template_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_template_state_new,
        state_free: rs_template_state_free,
        tx_free: rs_template_state_tx_free,
        parse_ts: rs_template_parse_request,
        parse_tc: rs_template_parse_response,
        get_tx_count: rs_template_state_get_tx_count,
        get_tx: rs_template_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_template_tx_get_alstate_progress,
        get_eventinfo: Some(TemplateEvent::get_event_info),
        get_eventinfo_byid : Some(TemplateEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<TemplateState, TemplateTransaction>),
        get_tx_data: rs_template_get_tx_data,
        get_state_data: rs_template_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_TEMPLATE = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust template parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for TEMPLATE.");
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
        let mut state = TemplateState::new();
        let buf = b"5:Hello3:bye";

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 2});

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 3});

        // This is the first message and only the first message.
        let r = state.parse_request(&buf[0..7]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        // The first message and a portion of the second.
        let r = state.parse_request(&buf[0..9]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 7, needed: 3});
    }
}
