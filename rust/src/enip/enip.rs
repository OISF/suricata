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

use super::constant::{EnipCommand, EnipStatus};
use super::parser;
use crate::applayer::{self, *};
use crate::conf::conf_get;
use crate::core::{
    AppProto, Direction, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP, IPPROTO_UDP,
    STREAM_TOCLIENT, STREAM_TOSERVER,
};
use crate::detect::EnumString;
use crate::frames::Frame;
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

static mut ALPROTO_ENIP: AppProto = ALPROTO_UNKNOWN;

static mut ENIP_MAX_TX: usize = 1024;

#[derive(AppLayerEvent)]
enum EnipEvent {
    TooManyTransactions,
    InvalidPdu,
}

#[derive(Default)]
pub struct EnipTransaction {
    tx_id: u64,
    pub request: Option<parser::EnipPdu>,
    pub response: Option<parser::EnipPdu>,
    pub done: bool,

    tx_data: AppLayerTxData,
}

impl Transaction for EnipTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct EnipState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<EnipTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<EnipTransaction> for EnipState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&EnipTransaction> {
        self.transactions.get(index)
    }
}

fn process_frames(
    pdu: &parser::EnipPdu, stream_slice: &StreamSlice, flow: *const Flow, input: &[u8],
    tx_id: Option<u64>,
) {
    let _pdu = Frame::new(
        flow,
        stream_slice,
        input,
        ENIP_HEADER_LEN as i64,
        EnipFrameType::Hdr as u8,
        tx_id,
    );
    let _pdu = Frame::new(
        flow,
        stream_slice,
        &input[ENIP_HEADER_LEN as usize..],
        pdu.header.pdulen as i64,
        EnipFrameType::Data as u8,
        tx_id,
    );
    let _pdu = Frame::new(
        flow,
        stream_slice,
        input,
        ENIP_HEADER_LEN as i64 + pdu.header.pdulen as i64,
        EnipFrameType::Pdu as u8,
        tx_id,
    );
    let items = parser::enip_pdu_get_items(pdu);
    for item in items.iter() {
        let _pdu = Frame::new(
            flow,
            stream_slice,
            &input[item.start..],
            4 + item.item_length as i64,
            EnipFrameType::EnipItem as u8,
            tx_id,
        );
    }
    if let parser::EnipPayload::Cip(c) = &pdu.payload {
        for item in c.items.iter() {
            if let parser::EnipItemPayload::Data(d) = &item.payload {
                let _pdu = Frame::new(
                    flow,
                    stream_slice,
                    &input[item.cip_offset..],
                    item.item_length as i64,
                    EnipFrameType::Cip as u8,
                    tx_id,
                );
                match &d.cip.cipdir {
                    parser::CipDir::Request(req) => {
                        if let parser::EnipCipRequestPayload::Multiple(m) = &req.payload {
                            for i in 0..m.packet_list.len() {
                                let _pdu = Frame::new(
                                    flow,
                                    stream_slice,
                                    &input[item.cip_offset
                                        + m.offset_from_cip
                                        + (m.offset_list[i] as usize)..],
                                    m.size_list[i] as i64,
                                    EnipFrameType::Cip as u8,
                                    tx_id,
                                );
                            }
                        }
                    }
                    parser::CipDir::Response(resp) => {
                        if let parser::EnipCipResponsePayload::Multiple(m) = &resp.payload {
                            for i in 0..m.packet_list.len() {
                                let _pdu = Frame::new(
                                    flow,
                                    stream_slice,
                                    &input[item.cip_offset
                                        + m.offset_from_cip
                                        + (m.offset_list[i] as usize)..],
                                    m.size_list[i] as i64,
                                    EnipFrameType::Cip as u8,
                                    tx_id,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

impl EnipState {
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&EnipTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> EnipTransaction {
        let mut tx = EnipTransaction::default();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn purge_tx_flood(&mut self) {
        let mut event_set = false;
        for tx in self.transactions.iter_mut() {
            tx.done = true;
            if !event_set {
                tx.tx_data.set_event(EnipEvent::TooManyTransactions as u8);
                event_set = true;
            }
        }
    }

    fn find_request(&mut self, pdu: &parser::EnipPdu) -> Option<&mut EnipTransaction> {
        for tx in self.transactions.iter_mut() {
            if let Some(req) = &tx.request {
                if tx.response.is_none() {
                    tx.done = true;
                    if response_matches_request(req, pdu) {
                        return Some(tx);
                    }
                }
            }
        }
        None
    }

    fn parse_udp(
        &mut self, stream_slice: StreamSlice, request: bool, flow: *const Flow,
    ) -> AppLayerResult {
        let input = stream_slice.as_slice();
        match parser::parse_enip_pdu(input) {
            Ok((_, pdu)) => {
                if !request {
                    if let Some(tx) = self.find_request(&pdu) {
                        process_frames(&pdu, &stream_slice, flow, input, Some(tx.tx_id - 1));
                        if pdu.invalid {
                            tx.tx_data.set_event(EnipEvent::InvalidPdu as u8);
                        }
                        tx.response = Some(pdu);
                        return AppLayerResult::ok();
                    }
                }
                if self.transactions.len() >= unsafe { ENIP_MAX_TX } {
                    process_frames(&pdu, &stream_slice, flow, input, None);
                    self.purge_tx_flood();
                } else {
                    let mut tx = self.new_tx();
                    if pdu.invalid {
                        tx.tx_data.set_event(EnipEvent::InvalidPdu as u8);
                    }
                    process_frames(&pdu, &stream_slice, flow, input, Some(tx.tx_id - 1));
                    if request {
                        tx.request = Some(pdu);
                    } else {
                        tx.response = Some(pdu);
                    }
                    self.transactions.push_back(tx);
                }
                return AppLayerResult::ok();
            }
            Err(_) => {
                return AppLayerResult::err();
            }
        }
    }
    fn parse_tcp(
        &mut self, stream_slice: StreamSlice, request: bool, flow: *const Flow,
    ) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if request {
            if self.request_gap {
                if !probe(input) {
                    return AppLayerResult::ok();
                }
                self.request_gap = false;
            }
        } else if self.response_gap {
            if !probe(input) {
                return AppLayerResult::ok();
            }
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_enip_pdu(start) {
                Ok((rem, pdu)) => {
                    if !request {
                        if let Some(tx) = self.find_request(&pdu) {
                            process_frames(&pdu, &stream_slice, flow, start, Some(tx.tx_id - 1));
                            if pdu.invalid {
                                tx.tx_data.set_event(EnipEvent::InvalidPdu as u8);
                            }
                            tx.response = Some(pdu);
                            start = rem;
                            continue;
                        }
                    }
                    if self.transactions.len() >= unsafe { ENIP_MAX_TX } {
                        process_frames(&pdu, &stream_slice, flow, start, None);
                        self.purge_tx_flood();
                    } else {
                        let mut tx = self.new_tx();
                        process_frames(&pdu, &stream_slice, flow, start, Some(tx.tx_id - 1));
                        if pdu.invalid {
                            tx.tx_data.set_event(EnipEvent::InvalidPdu as u8);
                        }
                        if request {
                            tx.request = Some(pdu);
                        } else {
                            tx.response = Some(pdu);
                        }
                        self.transactions.push_back(tx);
                    }
                    start = rem;
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
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

fn response_matches_request(req: &parser::EnipPdu, resp: &parser::EnipPdu) -> bool {
    if req.header.cmd != resp.header.cmd {
        return false;
    }
    if req.header.session != resp.header.session
        && req.header.cmd != EnipCommand::RegisterSession.into_u()
    {
        // register session response has session hanbdle when request has 0
        return false;
    }
    if let parser::EnipPayload::Cip(c1) = &req.payload {
        if let parser::EnipPayload::Cip(c2) = &resp.payload {
            // connection ids are different in each direction
            // and need to see beginning of stream to catch it
            if c1.items.len() >= 2
                && c2.items.len() >= 2
                && c1.items[1].item_type == parser::ENIP_ITEM_TYPE_CONNECTED_DATA
                && c2.items[1].item_type == parser::ENIP_ITEM_TYPE_CONNECTED_DATA
            {
                if let parser::EnipItemPayload::Data(d1) = &c1.items[1].payload {
                    if let parser::EnipItemPayload::Data(d2) = &c2.items[1].payload {
                        if d1.seq_num.is_some() && d1.seq_num == d2.seq_num {
                            return true;
                        }
                    }
                }
                // sequences number did not match even if they were present
                return false;
            }
            // we do not have CIP sequence numbers
            return true;
        } // else default to false
    } else {
        if let parser::EnipPayload::Cip(_c2) = &resp.payload {
            // request has no cip but response has it
            return false;
        }
        // no cip in either
        return true;
    }
    return false;
}

/// Probe for a valid header.
///
/// As this enip protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> bool {
    match parser::parse_enip_header(input) {
        Ok((rem, header)) => {
            if EnipStatus::from_u(header.status).is_none() {
                return false;
            }

            match EnipCommand::from_u(header.cmd) {
                Some(EnipCommand::Nop) => {
                    if header.options != 0 {
                        return false;
                    }
                }
                Some(EnipCommand::RegisterSession) => {
                    if header.pdulen != 4 {
                        return false;
                    }
                }
                Some(EnipCommand::UnregisterSession) => {
                    if header.pdulen != 4 && header.pdulen != 0 {
                        return false;
                    }
                }
                Some(EnipCommand::ListInterfaces) => {
                    if parser::parse_enip_list_interfaces(rem).is_err() {
                        return false;
                    }
                }
                Some(_) => {} // Ok so far, continue
                None => {
                    return false;
                }
            }
            return true;
        }
        _ => {
            return false;
        }
    }
}

// C exports.

unsafe extern "C" fn enip_probing_parser_udp(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 24 bytes.
    if input_len >= ENIP_HEADER_LEN && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return ALPROTO_ENIP;
        }
    }
    return ALPROTO_FAILED;
}

const ENIP_HEADER_LEN: u32 = 24;

unsafe extern "C" fn enip_probing_parser_tcp(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 24 bytes.
    if input.is_null() {
        return ALPROTO_UNKNOWN;
    }
    if input_len < ENIP_HEADER_LEN {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, input_len as usize);
    if probe(slice) {
        return ALPROTO_ENIP;
    }
    return ALPROTO_FAILED;
}

extern "C" fn rs_enip_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = EnipState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn enip_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut EnipState));
}

unsafe extern "C" fn enip_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, EnipState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn enip_parse_request_udp(
    flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, EnipState);
    state.parse_udp(stream_slice, true, flow)
}

unsafe extern "C" fn enip_parse_response_udp(
    flow: *const Flow, state: *mut c_void, _pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, EnipState);
    state.parse_udp(stream_slice, false, flow)
}

unsafe extern "C" fn enip_parse_request_tcp(
    flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, EnipState);
    if stream_slice.is_gap() {
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        debug_validate_bug_on!(stream_slice.is_empty());
        state.parse_tcp(stream_slice, true, flow)
    }
}

unsafe extern "C" fn enip_parse_response_tcp(
    flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, EnipState);
    if stream_slice.is_gap() {
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        debug_validate_bug_on!(stream_slice.is_empty());
        state.parse_tcp(stream_slice, false, flow)
    }
}

unsafe extern "C" fn rs_enip_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, EnipState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_enip_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, EnipState);
    return state.tx_id;
}

unsafe extern "C" fn rs_enip_tx_get_alstate_progress(tx: *mut c_void, direction: u8) -> c_int {
    let tx = cast_pointer!(tx, EnipTransaction);

    // Transaction is done if we have a response.
    if tx.done {
        return 1;
    }
    let dir: Direction = direction.into();
    if dir == Direction::ToServer {
        if tx.request.is_some() {
            return 1;
        }
    } else if tx.response.is_some() {
        return 1;
    }
    return 0;
}

// app-layer-frame-documentation tag start: FrameType enum
#[derive(AppLayerFrameType)]
pub enum EnipFrameType {
    Hdr,
    Data,
    Pdu,
    Cip,
    EnipItem,
}

export_tx_data_get!(rs_enip_get_tx_data, EnipTransaction);
export_state_data_get!(SCEnipTxGetState_data, EnipState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"enip\0";

#[no_mangle]
pub unsafe extern "C" fn SCEnipRegisterParsers() {
    let default_port = CString::new("[44818]").unwrap();
    let mut parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(enip_probing_parser_udp),
        probe_tc: Some(enip_probing_parser_udp),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_enip_state_new,
        state_free: enip_state_free,
        tx_free: enip_state_tx_free,
        parse_ts: enip_parse_request_udp,
        parse_tc: enip_parse_response_udp,
        get_tx_count: rs_enip_state_get_tx_count,
        get_tx: rs_enip_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_enip_tx_get_alstate_progress,
        get_eventinfo: Some(EnipEvent::get_event_info),
        get_eventinfo_byid: Some(EnipEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<EnipState, EnipTransaction>),
        get_tx_data: rs_enip_get_tx_data,
        get_state_data: SCEnipTxGetState_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: Some(EnipFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(EnipFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if let Some(val) = conf_get("app-layer.protocols.enip.max-tx") {
        if let Ok(v) = val.parse::<usize>() {
            ENIP_MAX_TX = v;
        } else {
            SCLogError!("Invalid value for enip.max-tx");
        }
    }

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_ENIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust enip parser registered for UDP.");
        AppLayerParserRegisterParserAcceptableDataDirection(
            IPPROTO_UDP,
            ALPROTO_ENIP,
            STREAM_TOSERVER | STREAM_TOCLIENT,
        );
        AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_ENIP);
    } else {
        SCLogDebug!("Protocol detector and parser disabled for ENIP on UDP.");
    }

    parser.ipproto = IPPROTO_TCP;
    parser.probe_ts = Some(enip_probing_parser_tcp);
    parser.probe_tc = Some(enip_probing_parser_tcp);
    parser.parse_ts = enip_parse_request_tcp;
    parser.parse_tc = enip_parse_response_tcp;
    parser.flags = APP_LAYER_PARSER_OPT_ACCEPT_GAPS;

    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_ENIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust enip parser registered for TCP.");
        AppLayerParserRegisterParserAcceptableDataDirection(
            IPPROTO_TCP,
            ALPROTO_ENIP,
            STREAM_TOSERVER | STREAM_TOCLIENT,
        );
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_ENIP);
    } else {
        SCLogDebug!("Protocol detector and parser disabled for ENIP on TCP.");
    }
}
