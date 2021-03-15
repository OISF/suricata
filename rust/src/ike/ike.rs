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

use crate::applayer;
use crate::applayer::*;
use crate::core::{
    self, AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, STREAM_TOCLIENT, STREAM_TOSERVER,
};
use crate::ike::ikev1::{handle_ikev1, IkeV1Header, Ikev1Container};
use crate::ike::ikev2::{handle_ikev2, Ikev2Container};
use crate::ike::parser::*;
use nom;
use std;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::mem::transmute;

#[repr(u32)]
pub enum IkeEvent {
    MalformedData = 0,
    NoEncryption,
    WeakCryptoEnc,
    WeakCryptoPRF,
    WeakCryptoDH,
    WeakCryptoAuth,
    WeakCryptoNoDH,
    WeakCryptoNoAuth,
    InvalidProposal,
    UnknownProposal,
    PayloadExtraData,
}

impl IkeEvent {
    pub fn from_i32(value: i32) -> Option<IkeEvent> {
        match value {
            0 => Some(IkeEvent::MalformedData),
            1 => Some(IkeEvent::NoEncryption),
            2 => Some(IkeEvent::WeakCryptoEnc),
            3 => Some(IkeEvent::WeakCryptoPRF),
            4 => Some(IkeEvent::WeakCryptoDH),
            5 => Some(IkeEvent::WeakCryptoAuth),
            6 => Some(IkeEvent::WeakCryptoNoDH),
            7 => Some(IkeEvent::WeakCryptoNoAuth),
            8 => Some(IkeEvent::InvalidProposal),
            9 => Some(IkeEvent::UnknownProposal),
            10 => Some(IkeEvent::PayloadExtraData),
            _ => None,
        }
    }
}

pub struct IkeHeaderWrapper {
    pub spi_initiator: String,
    pub spi_responder: String,
    pub maj_ver: u8,
    pub min_ver: u8,
    pub msg_id: u32,
    pub flags: u8,
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
            maj_ver: 0,
            min_ver: 0,
            msg_id: 0,
            flags: 0,
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
                length: 0,
            },
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
            ike_version: 0,
            hdr: IkeHeaderWrapper::new(),
            payload_types: Default::default(),
            notify_types: vec![],
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: applayer::AppLayerTxData::new(),
            errors: 0,
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
    pub ikev2_container: Ikev2Container,
}

impl IKEState {
    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let tx = self
            .transactions
            .iter()
            .position(|ref tx| tx.tx_id == tx_id + 1);
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
    pub fn set_event(&mut self, event: IkeEvent) {
        if let Some(tx) = self.transactions.last_mut() {
            let ev = event as u8;
            core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
        } else {
            SCLogDebug!(
                "IKE: trying to set event {} on non-existing transaction",
                event as u32
            );
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
        &mut self, min_tx_id: u64, state: &mut u64,
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
fn probe(input: &[u8], direction: u8, rdir: *mut u8) -> bool {
    match parse_isakmp_header(input) {
        Ok((_, isakmp_header)) => {
            if isakmp_header.maj_ver == 1 {
                if isakmp_header.resp_spi == 0 && direction != STREAM_TOSERVER {
                    unsafe {
                        *rdir = STREAM_TOSERVER;
                    }
                }
                return true;
            } else if isakmp_header.maj_ver == 2 {
                if isakmp_header.min_ver != 0 {
                    SCLogDebug!(
                        "ipsec_probe: could be ipsec, but with unsupported/invalid version {}.{}",
                        isakmp_header.maj_ver,
                        isakmp_header.min_ver
                    );
                    return false;
                }
                if isakmp_header.exch_type < 34 || isakmp_header.exch_type > 37 {
                    SCLogDebug!("ipsec_probe: could be ipsec, but with unsupported/invalid exchange type {}",
                           isakmp_header.exch_type);
                    return false;
                }
                if isakmp_header.length as usize != input.len() {
                    SCLogDebug!("ipsec_probe: could be ipsec, but length does not match");
                    return false;
                }

                if isakmp_header.resp_spi == 0 && direction != STREAM_TOSERVER {
                    unsafe {
                        *rdir = STREAM_TOSERVER;
                    }
                }
                return true;
            }

            return false;
        }
        Err(_) => return false,
    }
}

// C exports.
export_tx_get_detect_state!(rs_ike_tx_get_detect_state, IKETransaction);
export_tx_set_detect_state!(rs_ike_tx_set_detect_state, IKETransaction);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_ike_probing_parser(
    _flow: *const Flow, direction: u8, input: *const u8, input_len: u32, rdir: *mut u8,
) -> AppProto {
    if input_len < 28 {
        // at least the ISAKMP_HEADER must be there, not ALPROTO_UNKNOWN because over UDP
        return unsafe { ALPROTO_FAILED };
    }

    if input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice, direction, rdir) {
            return unsafe { ALPROTO_IKE };
        }
    }
    return unsafe { ALPROTO_FAILED };
}

#[no_mangle]
pub extern "C" fn rs_ike_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
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
pub extern "C" fn rs_ike_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, IKEState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_ike_parse_request(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, IKEState);
    let buf = build_slice!(input, input_len as usize);

    return state.handle_input(buf, STREAM_TOSERVER);
}

#[no_mangle]
pub extern "C" fn rs_ike_parse_response(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, IKEState);
    let buf = build_slice!(input, input_len as usize);
    return state.handle_input(buf, STREAM_TOCLIENT);
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
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
pub extern "C" fn rs_ike_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, IKEState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ike_tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ike_tx_get_logged(
    _state: *mut std::os::raw::c_void, tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, IKETransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_ike_tx_set_logged(
    _state: *mut std::os::raw::c_void, tx: *mut std::os::raw::c_void, logged: u32,
) {
    let tx = cast_pointer!(tx, IKETransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, IKETransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_event_info_by_id(
    event_id: std::os::raw::c_int, event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = IkeEvent::from_i32(event_id as i32) {
        let estr = match e {
            IkeEvent::MalformedData => "malformed_data\0",
            IkeEvent::NoEncryption => "no_encryption\0",
            IkeEvent::WeakCryptoEnc => "weak_crypto_enc\0",
            IkeEvent::WeakCryptoPRF => "weak_crypto_prf\0",
            IkeEvent::WeakCryptoDH => "weak_crypto_dh\0",
            IkeEvent::WeakCryptoAuth => "weak_crypto_auth\0",
            IkeEvent::WeakCryptoNoDH => "weak_crypto_nodh\0",
            IkeEvent::WeakCryptoNoAuth => "weak_crypto_noauth\0",
            IkeEvent::InvalidProposal => "invalid_proposal\0",
            IkeEvent::UnknownProposal => "unknown_proposal\0",
            IkeEvent::PayloadExtraData => "payload_extra_data\0",
        };
        unsafe {
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_event_info(
    event_name: *const std::os::raw::c_char, event_id: *mut std::os::raw::c_int,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if event_name == std::ptr::null() {
        return -1;
    }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "malformed_data" => IkeEvent::MalformedData as i32,
                "no_encryption" => IkeEvent::NoEncryption as i32,
                "weak_crypto_enc" => IkeEvent::WeakCryptoEnc as i32,
                "weak_crypto_prf" => IkeEvent::WeakCryptoPRF as i32,
                "weak_crypto_auth" => IkeEvent::WeakCryptoAuth as i32,
                "weak_crypto_dh" => IkeEvent::WeakCryptoDH as i32,
                "weak_crypto_nodh" => IkeEvent::WeakCryptoNoDH as i32,
                "weak_crypto_noauth" => IkeEvent::WeakCryptoNoAuth as i32,
                "invalid_proposal" => IkeEvent::InvalidProposal as i32,
                "unknown_proposal" => IkeEvent::UnknownProposal as i32,
                "payload_extra_data" => IkeEvent::PayloadExtraData as i32,
                _ => -1, // unknown event
            }
        }
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe {
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}

static mut ALPROTO_IKE : AppProto = ALPROTO_UNKNOWN;

#[no_mangle]
pub extern "C" fn rs_ike_state_get_tx_iterator(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, IKEState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(c_tx, out_tx_id, has_next);
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"ike\0";
const PARSER_ALIAS: &'static [u8] = b"ikev2\0";

export_tx_data_get!(rs_ike_get_tx_data, IKETransaction);

#[no_mangle]
pub unsafe extern "C" fn rs_ike_register_parser() {
    let default_port = CString::new("500").unwrap();
    let parser = RustParser {
        name               : PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port       : default_port.as_ptr(),
        ipproto            : core::IPPROTO_UDP,
        probe_ts           : Some(rs_ike_probing_parser),
        probe_tc           : Some(rs_ike_probing_parser),
        min_depth          : 0,
        max_depth          : 16,
        state_new          : rs_ike_state_new,
        state_free         : rs_ike_state_free,
        tx_free            : rs_ike_state_tx_free,
        parse_ts           : rs_ike_parse_request,
        parse_tc           : rs_ike_parse_response,
        get_tx_count       : rs_ike_state_get_tx_count,
        get_tx             : rs_ike_state_get_tx,
        tx_comp_st_ts      : 1,
        tx_comp_st_tc      : 1,
        tx_get_progress    : rs_ike_tx_get_alstate_progress,
        get_de_state       : rs_ike_tx_get_detect_state,
        set_de_state       : rs_ike_tx_set_detect_state,
        get_events         : Some(rs_ike_state_get_events),
        get_eventinfo      : Some(rs_ike_state_get_event_info),
        get_eventinfo_byid : Some(rs_ike_state_get_event_info_by_id),
        localstorage_new   : None,
        localstorage_free  : None,
        get_files          : None,
        get_tx_iterator    : None,
        get_tx_data        : rs_ike_get_tx_data,
        apply_tx_config    : None,
        flags              : APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate           : None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IKE = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }

        AppLayerRegisterParserAlias(
            PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
            PARSER_ALIAS.as_ptr() as *const std::os::raw::c_char,
        );
        SCLogDebug!("Rust IKE parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for IKE.");
    }
}
