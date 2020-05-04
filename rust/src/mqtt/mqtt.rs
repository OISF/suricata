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

// written by Sascha Steinbiss <sascha@steinbiss.name>

use super::mqtt_message::*;
use super::parser::*;
use crate::applayer::{self, LoggerFlags};
use crate::applayer::*;
use crate::core::{self, AppProto, Flow, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::log::*;
use nom;
use std;
use std::ffi::CString;
use std::mem::transmute;

const MQTT_DEFAULT_PROTOCOL_VERSION: u8 = 3;

static mut ALPROTO_MQTT: AppProto = ALPROTO_UNKNOWN;

pub struct MQTTTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,
    pub msg: MQTTMessage,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    detect_flags: applayer::TxDetectFlags,
}

impl MQTTTransaction {
    pub fn new(msg: MQTTMessage) -> MQTTTransaction {
        MQTTTransaction {
            tx_id: 0,
            request: None,
            response: None,
            logged: LoggerFlags::new(),
            msg: msg,
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

impl Drop for MQTTTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct MQTTState {
    tx_id: u64,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    pub protocol_version: u8,
    transactions: Vec<MQTTTransaction>,
}

impl MQTTState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            protocol_version: 0,
            transactions: Vec::new(),
        }
    }

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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&MQTTTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self, msg: MQTTMessage) -> MQTTTransaction {
        let mut tx = MQTTTransaction::new(msg);
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        if input.len() == 0 {
            return true;
        }

        self.request_buffer.extend(input);
        let tmp: Vec<u8>;
        let mut current = {
            tmp = self.request_buffer.split_off(0);
            tmp.as_slice()
        };

        while current.len() > 0 {
            SCLogDebug!("request: handling {}", current.len());
            match parse_message(current, self.protocol_version) {
                Ok((rem, msg)) => {
                    SCLogDebug!("replacing current ({}) with rem ({} => '{:?}')", current.len(), rem.len(), rem);
                    current = rem;

                    if let MQTTOperation::CONNECT(ref conn) = msg.op {
                        self.protocol_version = conn.protocol_version;
                    }
                    let tx = self.new_tx(msg);
                    self.transactions.push(tx);
                }
                Err(nom::Err::Incomplete(v)) => {
                    if let nom::Needed::Size(s) = v {
                        SCLogDebug!("incomplete request: needed {}", s);
                    }
                    self.request_buffer.extend_from_slice(current);
                    break;
                }
                Err(_) => {
                    return false;
                }
            }
        }

        return true;
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        if input.len() == 0 {
            return true;
        }

        self.response_buffer.extend(input);
        let tmp: Vec<u8>;
        let mut current = {
            tmp = self.response_buffer.split_off(0);
            tmp.as_slice()
        };

        while current.len() > 0 {
            SCLogDebug!("response: handling {}", current.len());
            match parse_message(current, self.protocol_version) {
                Ok((rem, msg)) => {
                    SCLogDebug!("replacing current ({}) with rem ({})", current.len(), rem.len());
                    current = rem;
                    let tx = self.new_tx(msg);
                    self.transactions.push(tx);
                }
                Err(nom::Err::Incomplete(v)) => {
                    if let nom::Needed::Size(s) = v {
                        SCLogDebug!("incomplete response: needed {}", s);
                    }
                    self.response_buffer.extend_from_slice(current);
                    break;
                }
                Err(_) => {
                    return false;
                }
            }
        }

        return true;
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&MQTTTransaction, u64, bool)> {
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

// C exports.

export_tx_get_detect_state!(rs_mqtt_tx_get_detect_state, MQTTTransaction);
export_tx_set_detect_state!(rs_mqtt_tx_set_detect_state, MQTTTransaction);

#[no_mangle]
pub extern "C" fn rs_mqtt_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    if parse_message(buf, MQTT_DEFAULT_PROTOCOL_VERSION).is_ok() {
        return unsafe { ALPROTO_MQTT };
    }
    return unsafe { ALPROTO_FAILED };
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_new() -> *mut std::os::raw::c_void {
    let state = MQTTState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_free(state: *mut std::os::raw::c_void) {
    let _drop: Box<MQTTState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, MQTTState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_mqtt_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, MQTTState);
    let buf = build_slice!(input, input_len as usize);
    return state.parse_request(buf).into();
}

#[no_mangle]
pub extern "C" fn rs_mqtt_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, MQTTState);
    let buf = build_slice!(input, input_len as usize);
    return state.parse_response(buf).into();
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, MQTTState);
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
pub extern "C" fn rs_mqtt_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, MQTTState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, MQTTTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, MQTTTransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, MQTTTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_get_event_info_by_id(
    _event_id: std::os::raw::c_int,
    _event_name: *mut *const std::os::raw::c_char,
    _event_type: *mut core::AppLayerEventType,
) -> i8 {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, MQTTState);
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
const PARSER_NAME: &'static [u8] = b"mqtt\0";

export_tx_detect_flags_set!(rs_mqtt_set_tx_detect_flags, MQTTTransaction);
export_tx_detect_flags_get!(rs_mqtt_get_tx_detect_flags, MQTTTransaction);

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_register_parser() {
    let default_port = CString::new("[1883]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_mqtt_probing_parser),
        probe_tc: Some(rs_mqtt_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_mqtt_state_new,
        state_free: rs_mqtt_state_free,
        tx_free: rs_mqtt_state_tx_free,
        parse_ts: rs_mqtt_parse_request,
        parse_tc: rs_mqtt_parse_response,
        get_tx_count: rs_mqtt_state_get_tx_count,
        get_tx: rs_mqtt_state_get_tx,
        tx_get_comp_st: rs_mqtt_state_progress_completion_status,
        tx_get_progress: rs_mqtt_tx_get_alstate_progress,
        get_tx_logged: Some(rs_mqtt_tx_get_logged),
        set_tx_logged: Some(rs_mqtt_tx_set_logged),
        get_de_state: rs_mqtt_tx_get_detect_state,
        set_de_state: rs_mqtt_tx_set_detect_state,
        get_events: Some(rs_mqtt_state_get_events),
        get_eventinfo: Some(rs_mqtt_state_get_event_info),
        get_eventinfo_byid: Some(rs_mqtt_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: Some(rs_mqtt_state_get_tx_iterator),
        get_tx_detect_flags: Some(rs_mqtt_get_tx_detect_flags),
        set_tx_detect_flags: Some(rs_mqtt_set_tx_detect_flags),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MQTT = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for MQTT.");
    }
}
