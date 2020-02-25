/* Copyright (C) 2020 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>

use std;
use crate::core::{self, ALPROTO_UNKNOWN, AppProto, Flow, STREAM_TOSERVER, STREAM_TOCLIENT};
use crate::log::*;
use std::mem::transmute;
use crate::applayer;
use crate::applayer::*;
use std::ffi::CString;
use nom;
use crate::ikev1::parser::*;
use std::collections::HashSet;

static mut ALPROTO_IKEV1: AppProto = ALPROTO_UNKNOWN;

pub struct IKEV1Transaction {
    tx_id: u64,
    progress: i32,
    pub request: Option<String>,
    pub response: Option<String>,

    pub spi_initiator: Option<u64>,
    pub spi_responder: Option<u64>,
    pub maj_ver: Option<u8>,
    pub min_ver: Option<u8>,
    pub exchange_type: Option<u8>,
    pub payload_types: Option<HashSet<u8>>,
    pub encrypted_payloads: bool,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    detect_flags: applayer::TxDetectFlags,
}

impl IKEV1Transaction {
    pub fn new() -> IKEV1Transaction {
        IKEV1Transaction {
            tx_id: 0,
            progress: 0,
            request: None,
            response: None,
            spi_initiator: None,
            spi_responder: None,
            maj_ver: None,
            min_ver: None,
            exchange_type: None,
            payload_types: None,
            encrypted_payloads: false,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            detect_flags: applayer::TxDetectFlags::default(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for IKEV1Transaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct IKEV1State {
    tx_id: u64,
    transactions: Vec<IKEV1Transaction>,

    pub domain_of_interpretation: Option<u32>,
    pub client_key_exchange: String,
    pub client_nonce: String,
    pub server_key_exchange: String,
    pub server_nonce: String,
    pub client_vendor_ids: HashSet<String>,
    pub server_vendor_ids: HashSet<String>,

    /// nested Vec, outer Vec per Proposal/Transform, inner Vec has the list of attributes.
    /// transforms proposed by the initiator
    pub client_transforms: Vec<Vec<SaAttribute>>,
    /// transforms selected by the responder
    pub server_transforms: Vec<Vec<SaAttribute>>,
}

impl IKEV1State{
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            domain_of_interpretation: None,
            client_key_exchange: String::new(),
            client_nonce: String::new(),
            server_key_exchange: String::new(),
            server_nonce: String::new(),
            client_vendor_ids: HashSet::new(),
            server_vendor_ids: HashSet::new(),
            client_transforms: Vec::new(),
            server_transforms: Vec::new()
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&mut IKEV1Transaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> IKEV1Transaction {
        let mut tx = IKEV1Transaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn set_progress(&mut self) {
        let mut progress = 1; // set to 1 to log and initiator_spi alert
        if self.client_key_exchange.len() > 0 {
            progress = 3;
        }
        if self.server_key_exchange.len() > 0 {
            progress = 4;
        }

        if let Some(transaction) = self.get_tx(self.tx_id - 1) {
            if transaction.encrypted_payloads {
                // for encrypted payloads we limit progress to 1
                progress = 1;
            }
            else if progress == 1 && transaction.spi_responder.is_some() {
                // response from server and no exchange data -> increase progress
                progress = 2;
            }
            transaction.progress = progress;
        }
    }

    fn handle_input(&mut self, input: &[u8], direction: u8) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut current = input;
        match parse_isakmp_header(current) {
            Ok((rem, isakmp_header)) => {
                current = rem;

                if isakmp_header.maj_ver != 1 {
                    return AppLayerResult::err();
                }

                let mut cur_payload_type = isakmp_header.next_payload;
                let mut payload_types: HashSet<u8> = HashSet::new();
                payload_types.insert(cur_payload_type);

                let mut encrypted_payloads = false;
                if isakmp_header.flags & 0x01 == 0x01 {
                    encrypted_payloads = true;
                } else {
                    match parse_ikev1_payload_list(current) {
                        Ok((_rem, payload_list)) => {
                            for isakmp_payload in payload_list {
                                if let Err(_) = parse_payload(
                                    cur_payload_type,
                                    isakmp_payload.data,
                                    isakmp_payload.data.len() as u16,
                                    &mut self.domain_of_interpretation,
                                    if direction == STREAM_TOSERVER { &mut self.client_key_exchange } else { &mut self.server_key_exchange },
                                    if direction == STREAM_TOSERVER { &mut self.client_nonce } else { &mut self.server_nonce },
                                    if direction == STREAM_TOSERVER { &mut self.client_transforms } else { &mut self.server_transforms },
                                    if direction == STREAM_TOSERVER { &mut self.client_vendor_ids } else { &mut self.server_vendor_ids },
                                    &mut payload_types
                                ) {
                                    SCLogDebug!("Error while parsing IKEV1 payloads");
                                    return AppLayerResult::err();
                                }

                                cur_payload_type = isakmp_payload.payload_header.next_payload;
                            }
                        },
                        Err(nom::Err::Incomplete(_)) => {
                            SCLogDebug!("Insufficient data while parsing IKEV1");
                            return AppLayerResult::err();
                        }
                        Err(_) => {
                            return AppLayerResult::err();
                        }
                    }
                }

                let mut tx = self.new_tx();
                tx.spi_initiator = Some(isakmp_header.init_spi);
                tx.spi_responder = Some(isakmp_header.resp_spi);
                tx.maj_ver = Some(isakmp_header.maj_ver);
                tx.min_ver = Some(isakmp_header.min_ver);
                tx.exchange_type = Some(isakmp_header.exch_type);
                tx.payload_types = Some(payload_types);
                tx.encrypted_payloads = encrypted_payloads;
                self.transactions.push(tx);
                self.set_progress();

                return AppLayerResult::ok(); // todo either remove outer loop or check header length-field if we have completely read everything
            }
            Err(nom::Err::Incomplete(_)) => {
                SCLogDebug!("Insufficient data while parsing IKEV1");
                return AppLayerResult::err();
            }
            Err(_) => {
                return AppLayerResult::err();
            }
        }
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&IKEV1Transaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;

            // return Some((tx, tx.tx_id - 1, (len - index) > 1)); <- original

            // todo: ask oisf next 4 lines! only return last transaction in iterator? seems to return correct number of alerts
            // detect.c: DetectRunTx (line 1283)
            if index >= len - 1 {
                return Some((tx, tx.tx_id - 1, (len - index) > 1));
            }
            index += 1;
        }

        return None;
    }
}

/// Probe to see if this input looks like a request or response.
fn probe(input: &[u8]) -> bool {
    match parse_isakmp_header(input) {
        Ok((_, isakmp_header)) => {
            if isakmp_header.maj_ver != 1 {
                SCLogDebug!("ipsec_probe: could be ipsec, but with unsupported/invalid version {}.{}",
                        isakmp_header.maj_ver, isakmp_header.min_ver);
                return false
            }

            return true
        },
        Err(_) => {
            return false
        },
    }
}

// C exports.
export_tx_get_detect_state!(
    rs_ikev1_tx_get_detect_state,
    IKEV1Transaction
);
export_tx_set_detect_state!(
    rs_ikev1_tx_set_detect_state,
    IKEV1Transaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_ikev1_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return unsafe { ALPROTO_IKEV1 };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_new() -> *mut std::os::raw::c_void {
    let state = IKEV1State::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<IKEV1State> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, IKEV1State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_ikev1_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, IKEV1State);
    let buf = build_slice!(input, input_len as usize);

    return state.handle_input(buf, STREAM_TOSERVER);
}

#[no_mangle]
pub extern "C" fn rs_ikev1_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, IKEV1State);
    let buf = build_slice!(input, input_len as usize);
    return state.handle_input(buf, STREAM_TOCLIENT);
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, IKEV1State);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, IKEV1State);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_progress_completion_status(
    _direction: u8,
) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, IKEV1Transaction);

    return tx.progress;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, IKEV1Transaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_ikev1_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, IKEV1Transaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_events(
    tx: *mut std::os::raw::c_void
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, IKEV1Transaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
                                                         _event_name: *mut *const std::os::raw::c_char,
                                                         _event_type: *mut core::AppLayerEventType
) -> i8 {
    return -1;
}
#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, IKEV1State);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(
                c_tx,
                out_tx_id,
                has_next,
            );
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub extern "C" fn rs_ikev1_get_request_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, IKEV1Transaction);
    if let Some(ref request) = tx.request {
        if request.len() > 0 {
            unsafe {
                *len = request.len() as u32;
                *buf = request.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub extern "C" fn rs_ikev1_get_response_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, IKEV1Transaction);
    if let Some(ref response) = tx.response {
        if response.len() > 0 {
            unsafe {
                *len = response.len() as u32;
                *buf = response.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"ikev1\0";

export_tx_detect_flags_set!(rs_ikev1_set_tx_detect_flags, IKEV1Transaction);
export_tx_detect_flags_get!(rs_ikev1_get_tx_detect_flags, IKEV1Transaction);

#[no_mangle]
pub unsafe extern "C" fn rs_ikev1_register_parser() {
    let default_port = CString::new("500").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: core::IPPROTO_UDP,
        probe_ts: Some(rs_ikev1_probing_parser),
        probe_tc: Some(rs_ikev1_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_ikev1_state_new,
        state_free: rs_ikev1_state_free,
        tx_free: rs_ikev1_state_tx_free,
        parse_ts: rs_ikev1_parse_request,
        parse_tc: rs_ikev1_parse_response,
        get_tx_count: rs_ikev1_state_get_tx_count,
        get_tx: rs_ikev1_state_get_tx,
        tx_get_comp_st: rs_ikev1_state_progress_completion_status,
        tx_get_progress: rs_ikev1_tx_get_alstate_progress,
        get_tx_logged: Some(rs_ikev1_tx_get_logged),
        set_tx_logged: Some(rs_ikev1_tx_set_logged),
        get_de_state: rs_ikev1_tx_get_detect_state,
        set_de_state: rs_ikev1_tx_set_detect_state,
        get_events: Some(rs_ikev1_state_get_events),
        get_eventinfo: Some(rs_ikev1_state_get_event_info),
        get_eventinfo_byid : Some(rs_ikev1_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_ikev1_state_get_tx_iterator),
        get_tx_detect_flags: Some(rs_ikev1_get_tx_detect_flags),
        set_tx_detect_flags: Some(rs_ikev1_set_tx_detect_flags),
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IKEV1 = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust IKEv1 parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for IKEv1.");
    }
}
