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

extern crate ipsec_parser;
use self::ipsec_parser::*;

use std;
use crate::core::{self, ALPROTO_UNKNOWN, ALPROTO_FAILED, AppProto, Flow, STREAM_TOSERVER, STREAM_TOCLIENT};
use crate::log::*;
use std::mem::transmute;
use crate::applayer;
use crate::applayer::*;
use std::ffi::{CString, CStr};
use nom;
use crate::ike::parser::*;
use crate::ike::ikev1::{handle_ikev1, IkeV1Header, Ikev1Container};
use crate::ike::ikev2::{handle_ikev2, IKEV2Event, Ikev2Container};
use std::collections::HashSet;

static mut ALPROTO_IKE: AppProto = ALPROTO_UNKNOWN;

pub struct IkeHeaderWrapper {
    pub spi_initiator: String,
    pub spi_responder: String,
    pub ikev1_transforms: Vec<Vec<SaAttribute>>,
    pub ikev2_transforms: Vec<Vec<IkeV2Transform>>,
    pub ikev1_header: IkeV1Header,
    pub ikev2_header: IkeV2Header,
}

impl IkeHeaderWrapper {
    pub fn new() -> IkeHeaderWrapper {
        IkeHeaderWrapper {
            spi_initiator: String::new(),
            spi_responder: String::new(),
            ikev1_transforms: Vec::new(),
            ikev2_transforms: Vec::new(),
            ikev1_header: IkeV1Header::default(),
            ikev2_header: IkeV2Header {
                init_spi: 0,
                resp_spi: 0,
                next_payload: IkePayloadType::NoNextPayload,
                maj_ver: 0,
                min_ver: 0,
                exch_type: IkeExchangeType(0),
                flags: 0,
                msg_id: 0,
                length: 0
            }
        }
    }
}

#[derive(Default)]
pub struct IkePayloadWrapper {
    pub ikev1_payload_types: Option<HashSet<u8>>,
    pub ikev2_payload_types: Vec<IkePayloadType>,
}

pub struct IKETransaction {
    tx_id: u64,
    progress: i32,

    pub ike_version: u8,
    pub hdr: IkeHeaderWrapper,
    pub payload_types: IkePayloadWrapper,
    pub notify_types: Vec<NotifyType>,

    /// errors seen during exchange
    pub errors: u32,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: applayer::AppLayerTxData,
}

impl IKETransaction {
    pub fn new() -> IKETransaction {
        IKETransaction {
            tx_id: 0,
            progress: 0,
            ike_version: 0,
            hdr: IkeHeaderWrapper::new(),
            payload_types: Default::default(),
            notify_types: vec![],
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: applayer::AppLayerTxData::new(),
            errors: 0
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

    pub fn set_progress(&mut self, direction: u8) {
        let mut progress = 1; // set to 1 to log and initiator_spi alert
        if self.hdr.ikev1_header.key_exchange.len() > 0 && direction == STREAM_TOSERVER {
            progress = 3;
        }
        if self.hdr.ikev1_header.key_exchange.len() > 0 && direction == STREAM_TOCLIENT {
            progress = 4;
        }

        if self.hdr.ikev1_header.encrypted_payloads {
            // for encrypted payloads we limit progress to 1
            progress = 1;
        }
        else if progress == 1 && !self.hdr.spi_responder.is_empty() {
            // response from server and no exchange data -> increase progress
            progress = 2;
        }
        self.progress = progress;
    }
}

impl Drop for IKETransaction {
    fn drop(&mut self) {
        self.free();
    }
}

#[derive(Default)]
pub struct IKEState {
    tx_id: u64,
    pub transactions: Vec<IKETransaction>,

    pub ikev1_container: Ikev1Container,
    pub ikev2_container: Ikev2Container
}

impl IKEState{
    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let tx = self.transactions.iter().position(|ref tx| tx.tx_id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&mut IKETransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    pub fn new_tx(&mut self) -> IKETransaction {
        let mut tx = IKETransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: IKEV2Event) {
        if let Some(tx) = self.transactions.last_mut() {
            let ev = event as u8;
            core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
        } else {
            SCLogDebug!("IKEv2: trying to set event {} on non-existing transaction", event as u32);
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

                if isakmp_header.maj_ver != 1 && isakmp_header.maj_ver != 2 {
                    SCLogDebug!("Unsupported ISAKMP major_version");
                    return AppLayerResult::err();
                }

                if isakmp_header.maj_ver == 1 {
                    handle_ikev1(self, current, isakmp_header, direction);
                } else if isakmp_header.maj_ver == 2 {
                    handle_ikev2(self, current, isakmp_header, direction);
                } else {
                    return AppLayerResult::err();
                }
                return AppLayerResult::ok(); // todo either remove outer loop or check header length-field if we have completely read everything
            }
            Err(nom::Err::Incomplete(_)) => {
                SCLogDebug!("Insufficient data while parsing IKE");
                return AppLayerResult::err();
            }
            Err(_) => {
                SCLogDebug!("Error while parsing IKE packet");
                return AppLayerResult::err();
            }
        }
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&IKETransaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;

            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

/// Probe to see if this input looks like a request or response.
fn probe(input: &[u8], rdir: *mut u8) -> bool {
    match parse_isakmp_header(input) {
        Ok((_, isakmp_header)) => {
            if isakmp_header.maj_ver == 1 {
                if isakmp_header.resp_spi == 0 {
                    unsafe {*rdir = STREAM_TOSERVER;}
                }
                return true
            } else if isakmp_header.maj_ver == 2 {
                if isakmp_header.min_ver != 0 {
                    SCLogDebug!("ipsec_probe: could be ipsec, but with unsupported/invalid version {}.{}",
                            isakmp_header.maj_ver, isakmp_header.min_ver);
                    return false
                }
                if isakmp_header.exch_type < 34 || isakmp_header.exch_type > 37 {
                    SCLogDebug!("ipsec_probe: could be ipsec, but with unsupported/invalid exchange type {}",
                           isakmp_header.exch_type);
                    return false
                }
                if isakmp_header.length as usize != input.len() {
                    SCLogDebug!("ipsec_probe: could be ipsec, but length does not match");
                    return false
                }

                if isakmp_header.resp_spi == 0 {
                    unsafe {*rdir = STREAM_TOSERVER;}
                }
                return true
            }

            return false
        },
        Err(_) => {
            return false
        },
    }
}

// C exports.
export_tx_get_detect_state!(
    rs_ike_tx_get_detect_state,
    IKETransaction
);
export_tx_set_detect_state!(
    rs_ike_tx_set_detect_state,
    IKETransaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_ike_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    rdir: *mut u8
) -> AppProto {
    if input_len < 28 {
        // at least the ISAKMP_HEADER must be there
        return unsafe { ALPROTO_FAILED };
    }

    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice, rdir) {
            return unsafe { ALPROTO_IKE };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_new() -> *mut std::os::raw::c_void {
    let state = IKEState::default();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_ike_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<IKEState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_ike_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, IKEState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_ike_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, IKEState);
    let buf = build_slice!(input, input_len as usize);

    return state.handle_input(buf, STREAM_TOSERVER);
}

#[no_mangle]
pub extern "C" fn rs_ike_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, IKEState);
    let buf = build_slice!(input, input_len as usize);
    return state.handle_input(buf, STREAM_TOCLIENT);
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, IKEState);
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
pub extern "C" fn rs_ike_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, IKEState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_progress_completion_status(
    _direction: u8,
) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ike_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, IKETransaction);

    return tx.progress;
}

#[no_mangle]
pub extern "C" fn rs_ike_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, IKETransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_ike_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, IKETransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_events(tx: *mut std::os::raw::c_void)
                                            -> *mut core::AppLayerDecoderEvents
{
    let tx = cast_pointer!(tx, IKETransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_event_info_by_id(event_id: std::os::raw::c_int,
                                                      event_name: *mut *const std::os::raw::c_char,
                                                      event_type: *mut core::AppLayerEventType)
                                                      -> i8
{
    if let Some(e) = IKEV2Event::from_i32(event_id as i32) {
        let estr = match e {
            IKEV2Event::MalformedData    => { "malformed_data\0" },
            IKEV2Event::NoEncryption     => { "no_encryption\0" },
            IKEV2Event::WeakCryptoEnc    => { "weak_crypto_enc\0" },
            IKEV2Event::WeakCryptoPRF    => { "weak_crypto_prf\0" },
            IKEV2Event::WeakCryptoDH     => { "weak_crypto_dh\0" },
            IKEV2Event::WeakCryptoAuth   => { "weak_crypto_auth\0" },
            IKEV2Event::WeakCryptoNoDH   => { "weak_crypto_nodh\0" },
            IKEV2Event::WeakCryptoNoAuth => { "weak_crypto_noauth\0" },
            IKEV2Event::InvalidProposal  => { "invalid_proposal\0" },
            IKEV2Event::UnknownProposal  => { "unknown_proposal\0" },
        };
        unsafe{
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_event_info(event_name: *const std::os::raw::c_char,
                                                event_id: *mut std::os::raw::c_int,
                                                event_type: *mut core::AppLayerEventType)
                                                -> std::os::raw::c_int
{
    if event_name == std::ptr::null() { return -1; }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "malformed_data"     => IKEV2Event::MalformedData as i32,
                "no_encryption"      => IKEV2Event::NoEncryption as i32,
                "weak_crypto_enc"    => IKEV2Event::WeakCryptoEnc as i32,
                "weak_crypto_prf"    => IKEV2Event::WeakCryptoPRF as i32,
                "weak_crypto_auth"   => IKEV2Event::WeakCryptoAuth as i32,
                "weak_crypto_dh"     => IKEV2Event::WeakCryptoDH as i32,
                "weak_crypto_nodh"   => IKEV2Event::WeakCryptoNoDH as i32,
                "weak_crypto_noauth" => IKEV2Event::WeakCryptoNoAuth as i32,
                "invalid_proposal"   => IKEV2Event::InvalidProposal as i32,
                "unknown_proposal"   => IKEV2Event::UnknownProposal as i32,
                _                    => -1, // unknown event
            }
        },
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe{
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, IKEState);
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

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"ike\0";

export_tx_data_get!(rs_ike_get_tx_data, IKETransaction);

#[no_mangle]
pub unsafe extern "C" fn rs_ike_register_parser() {
    let default_port = CString::new("500").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: core::IPPROTO_UDP,
        probe_ts: Some(rs_ike_probing_parser),
        probe_tc: Some(rs_ike_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_ike_state_new,
        state_free: rs_ike_state_free,
        tx_free: rs_ike_state_tx_free,
        parse_ts: rs_ike_parse_request,
        parse_tc: rs_ike_parse_response,
        get_tx_count: rs_ike_state_get_tx_count,
        get_tx: rs_ike_state_get_tx,
        tx_get_comp_st: rs_ike_state_progress_completion_status,
        tx_get_progress: rs_ike_tx_get_alstate_progress,
        get_de_state: rs_ike_tx_get_detect_state,
        set_de_state: rs_ike_tx_set_detect_state,
        get_events: Some(rs_ike_state_get_events),
        get_eventinfo: Some(rs_ike_state_get_event_info),
        get_eventinfo_byid : Some(rs_ike_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_ike_state_get_tx_iterator),
        get_tx_data: rs_ike_get_tx_data,
        apply_tx_config: None,
        flags: 0
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IKE = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust IKE parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for IKE.");
    }
}
