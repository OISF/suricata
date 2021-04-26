/* Copyright (C) 2020-2022 Open Information Security Foundation
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
use crate::applayer::*;
use crate::applayer::{self, LoggerFlags};
use crate::conf::conf_get;
use crate::core::*;
use nom7::Err;
use std;
use std::collections::VecDeque;
use std::ffi::CString;

// Used as a special pseudo packet identifier to denote the first CONNECT
// packet in a connection. Note that there is no risk of collision with a
// parsed packet identifier because in the protocol these are only 16 bit
// unsigned.
const MQTT_CONNECT_PKT_ID: u32 = std::u32::MAX;
// Maximum message length in bytes. If the length of a message exceeds
// this value, it will be truncated. Default: 1MB.
static mut MAX_MSG_LEN: u32 = 1048576;

static mut MQTT_MAX_TX: usize = 1024;

static mut ALPROTO_MQTT: AppProto = ALPROTO_UNKNOWN;

#[derive(FromPrimitive, Debug, AppLayerEvent)]
pub enum MQTTEvent {
    MissingConnect,
    MissingPublish,
    MissingSubscribe,
    MissingUnsubscribe,
    DoubleConnect,
    UnintroducedMessage,
    InvalidQosLevel,
    MissingMsgId,
    UnassignedMsgType,
    TooManyTransactions,
    MalformedTraffic,
}

#[derive(Debug)]
pub struct MQTTTransaction {
    tx_id: u64,
    pkt_id: Option<u32>,
    pub msg: Vec<MQTTMessage>,
    complete: bool,
    toclient: bool,
    toserver: bool,

    logged: LoggerFlags,
    tx_data: applayer::AppLayerTxData,
}

impl MQTTTransaction {
    pub fn new(msg: MQTTMessage) -> MQTTTransaction {
        let mut m = MQTTTransaction::new_empty();
        m.msg.push(msg);
        return m;
    }

    pub fn new_empty() -> MQTTTransaction {
        return MQTTTransaction {
            tx_id: 0,
            pkt_id: None,
            complete: false,
            logged: LoggerFlags::new(),
            msg: Vec::new(),
            toclient: false,
            toserver: false,
            tx_data: applayer::AppLayerTxData::new(),
        };
    }
}

impl Transaction for MQTTTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

pub struct MQTTState {
    state_data: AppLayerStateData,
    tx_id: u64,
    pub protocol_version: u8,
    transactions: VecDeque<MQTTTransaction>,
    connected: bool,
    skip_request: usize,
    skip_response: usize,
    max_msg_len: usize,
    tx_index_completed: usize,
}

impl State<MQTTTransaction> for MQTTState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&MQTTTransaction> {
        self.transactions.get(index)
    }
}

impl MQTTState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            protocol_version: 0,
            transactions: VecDeque::new(),
            connected: false,
            skip_request: 0,
            skip_response: 0,
            max_msg_len: unsafe { MAX_MSG_LEN as usize },
            tx_index_completed: 0,
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
            self.tx_index_completed = 0;
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

    pub fn get_tx_by_pkt_id(&mut self, pkt_id: u32) -> Option<&mut MQTTTransaction> {
        for tx in &mut self.transactions {
            if !tx.complete {
                if let Some(mpktid) = tx.pkt_id {
                    if mpktid == pkt_id {
                        return Some(tx);
                    }
                }
            }
        }
        return None;
    }

    fn new_tx(&mut self, msg: MQTTMessage, toclient: bool) -> MQTTTransaction {
        let mut tx = MQTTTransaction::new(msg);
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        if toclient {
            tx.toclient = true;
        } else {
            tx.toserver = true;
        }
        if self.transactions.len() > unsafe { MQTT_MAX_TX } {
            let mut index = self.tx_index_completed;
            for tx_old in &mut self.transactions.range_mut(self.tx_index_completed..) {
                index = index + 1;
                if !tx_old.complete {
                    tx_old.complete = true;
                    MQTTState::set_event(tx_old, MQTTEvent::TooManyTransactions);
                    break;
                }
            }
            self.tx_index_completed = index;
        }
        return tx;
    }

    // Handle a MQTT message depending on the direction and state.
    // Note that we are trying to only have one mutable reference to msg
    // and its components, however, since we are in a large match operation,
    // we cannot pass around and/or store more references or move things
    // without having to introduce lifetimes etc.
    // This is the reason for the code duplication below. Maybe there is a
    // more concise way to do it, but this works for now.
    fn handle_msg(&mut self, msg: MQTTMessage, toclient: bool) {
        match msg.op {
            MQTTOperation::CONNECT(ref conn) => {
                self.protocol_version = conn.protocol_version;
                if self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::DoubleConnect);
                    self.transactions.push_back(tx);
                } else {
                    let mut tx = self.new_tx(msg, toclient);
                    tx.pkt_id = Some(MQTT_CONNECT_PKT_ID);
                    self.transactions.push_back(tx);
                }
            }
            MQTTOperation::PUBLISH(ref publish) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                match msg.header.qos_level {
                    0 => {
                        // with QOS level 0, we do not need to wait for a
                        // response
                        let mut tx = self.new_tx(msg, toclient);
                        tx.complete = true;
                        self.transactions.push_back(tx);
                    }
                    1..=2 => {
                        if let Some(pkt_id) = publish.message_id {
                            let mut tx = self.new_tx(msg, toclient);
                            tx.pkt_id = Some(pkt_id as u32);
                            self.transactions.push_back(tx);
                        } else {
                            let mut tx = self.new_tx(msg, toclient);
                            MQTTState::set_event(&mut tx, MQTTEvent::MissingMsgId);
                            self.transactions.push_back(tx);
                        }
                    }
                    _ => {
                        let mut tx = self.new_tx(msg, toclient);
                        MQTTState::set_event(&mut tx, MQTTEvent::InvalidQosLevel);
                        self.transactions.push_back(tx);
                    }
                }
            }
            MQTTOperation::SUBSCRIBE(ref subscribe) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                let pkt_id = subscribe.message_id as u32;
                match msg.header.qos_level {
                    0 => {
                        // with QOS level 0, we do not need to wait for a
                        // response
                        let mut tx = self.new_tx(msg, toclient);
                        tx.complete = true;
                        self.transactions.push_back(tx);
                    }
                    1..=2 => {
                        let mut tx = self.new_tx(msg, toclient);
                        tx.pkt_id = Some(pkt_id);
                        self.transactions.push_back(tx);
                    }
                    _ => {
                        let mut tx = self.new_tx(msg, toclient);
                        MQTTState::set_event(&mut tx, MQTTEvent::InvalidQosLevel);
                        self.transactions.push_back(tx);
                    }
                }
            }
            MQTTOperation::UNSUBSCRIBE(ref unsubscribe) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                let pkt_id = unsubscribe.message_id as u32;
                match msg.header.qos_level {
                    0 => {
                        // with QOS level 0, we do not need to wait for a
                        // response
                        let mut tx = self.new_tx(msg, toclient);
                        tx.complete = true;
                        self.transactions.push_back(tx);
                    }
                    1..=2 => {
                        let mut tx = self.new_tx(msg, toclient);
                        tx.pkt_id = Some(pkt_id);
                        self.transactions.push_back(tx);
                    }
                    _ => {
                        let mut tx = self.new_tx(msg, toclient);
                        MQTTState::set_event(&mut tx, MQTTEvent::InvalidQosLevel);
                        self.transactions.push_back(tx);
                    }
                }
            }
            MQTTOperation::CONNACK(ref _connack) => {
                if let Some(tx) = self.get_tx_by_pkt_id(MQTT_CONNECT_PKT_ID) {
                    (*tx).msg.push(msg);
                    (*tx).complete = true;
                    (*tx).pkt_id = None;
                    self.connected = true;
                } else {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::MissingConnect);
                    self.transactions.push_back(tx);
                }
            }
            MQTTOperation::PUBREC(ref v) | MQTTOperation::PUBREL(ref v) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                if let Some(tx) = self.get_tx_by_pkt_id(v.message_id as u32) {
                    (*tx).msg.push(msg);
                } else {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::MissingPublish);
                    self.transactions.push_back(tx);
                }
            }
            MQTTOperation::PUBACK(ref v) | MQTTOperation::PUBCOMP(ref v) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                if let Some(tx) = self.get_tx_by_pkt_id(v.message_id as u32) {
                    (*tx).msg.push(msg);
                    (*tx).complete = true;
                    (*tx).pkt_id = None;
                } else {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::MissingPublish);
                    self.transactions.push_back(tx);
                }
            }
            MQTTOperation::SUBACK(ref suback) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                if let Some(tx) = self.get_tx_by_pkt_id(suback.message_id as u32) {
                    (*tx).msg.push(msg);
                    (*tx).complete = true;
                    (*tx).pkt_id = None;
                } else {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::MissingSubscribe);
                    self.transactions.push_back(tx);
                }
            }
            MQTTOperation::UNSUBACK(ref unsuback) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                if let Some(tx) = self.get_tx_by_pkt_id(unsuback.message_id as u32) {
                    (*tx).msg.push(msg);
                    (*tx).complete = true;
                    (*tx).pkt_id = None;
                } else {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::MissingUnsubscribe);
                    self.transactions.push_back(tx);
                }
            }
            MQTTOperation::UNASSIGNED => {
                let mut tx = self.new_tx(msg, toclient);
                tx.complete = true;
                MQTTState::set_event(&mut tx, MQTTEvent::UnassignedMsgType);
                self.transactions.push_back(tx);
            }
            MQTTOperation::TRUNCATED(_) => {
                let mut tx = self.new_tx(msg, toclient);
                tx.complete = true;
                self.transactions.push_back(tx);
            }
            MQTTOperation::AUTH(_) | MQTTOperation::DISCONNECT(_) => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                let mut tx = self.new_tx(msg, toclient);
                tx.complete = true;
                self.transactions.push_back(tx);
            }
            MQTTOperation::PINGREQ | MQTTOperation::PINGRESP => {
                if !self.connected {
                    let mut tx = self.new_tx(msg, toclient);
                    MQTTState::set_event(&mut tx, MQTTEvent::UnintroducedMessage);
                    self.transactions.push_back(tx);
                    return;
                }
                let mut tx = self.new_tx(msg, toclient);
                tx.complete = true;
                self.transactions.push_back(tx);
            }
        }
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        let mut current = input;
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut consumed = 0;
        SCLogDebug!(
            "skip_request {} input len {}",
            self.skip_request,
            input.len()
        );
        if self.skip_request > 0 {
            if input.len() <= self.skip_request {
                SCLogDebug!("reducing skip_request by {}", input.len());
                self.skip_request -= input.len();
                return AppLayerResult::ok();
            } else {
                current = &input[self.skip_request..];
                SCLogDebug!(
                    "skip end reached, skipping {} :{:?}",
                    self.skip_request,
                    current
                );
                consumed = self.skip_request;
                self.skip_request = 0;
            }
        }

        while current.len() > 0 {
            SCLogDebug!("request: handling {}", current.len());
            match parse_message(current, self.protocol_version, self.max_msg_len) {
                Ok((rem, msg)) => {
                    SCLogDebug!("request msg {:?}", msg);
                    if let MQTTOperation::TRUNCATED(ref trunc) = msg.op {
                        SCLogDebug!(
                            "found truncated with skipped {} current len {}",
                            trunc.skipped_length,
                            current.len()
                        );
                        if trunc.skipped_length >= current.len() {
                            self.skip_request = trunc.skipped_length - current.len();
                            self.handle_msg(msg, true);
                            return AppLayerResult::ok();
                        } else {
                            consumed += trunc.skipped_length;
                            current = &current[trunc.skipped_length..];
                            self.handle_msg(msg, true);
                            self.skip_request = 0;
                            continue;
                        }
                    }
                    self.handle_msg(msg, false);
                    consumed += current.len() - rem.len();
                    current = rem;
                }
                Err(Err::Incomplete(_)) => {
                    SCLogDebug!(
                        "incomplete request: consumed {} needed {} (input len {})",
                        consumed,
                        (current.len() + 1),
                        input.len()
                    );
                    return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                }
                Err(_) => {
                    self.set_event_notx(MQTTEvent::MalformedTraffic, false);
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        let mut current = input;
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut consumed = 0;
        SCLogDebug!(
            "skip_response {} input len {}",
            self.skip_response,
            current.len()
        );
        if self.skip_response > 0 {
            if input.len() <= self.skip_response {
                self.skip_response -= current.len();
                return AppLayerResult::ok();
            } else {
                current = &input[self.skip_response..];
                SCLogDebug!(
                    "skip end reached, skipping {} :{:?}",
                    self.skip_request,
                    current
                );
                consumed = self.skip_response;
                self.skip_response = 0;
            }
        }

        while current.len() > 0 {
            SCLogDebug!("response: handling {}", current.len());
            match parse_message(current, self.protocol_version, self.max_msg_len as usize) {
                Ok((rem, msg)) => {
                    SCLogDebug!("response msg {:?}", msg);
                    if let MQTTOperation::TRUNCATED(ref trunc) = msg.op {
                        SCLogDebug!(
                            "found truncated with skipped {} current len {}",
                            trunc.skipped_length,
                            current.len()
                        );
                        if trunc.skipped_length >= current.len() {
                            self.skip_response = trunc.skipped_length - current.len();
                            self.handle_msg(msg, true);
                            SCLogDebug!("skip_response now {}", self.skip_response);
                            return AppLayerResult::ok();
                        } else {
                            consumed += trunc.skipped_length;
                            current = &current[trunc.skipped_length..];
                            self.handle_msg(msg, true);
                            self.skip_response = 0;
                            continue;
                        }
                    }
                    self.handle_msg(msg, true);
                    consumed += current.len() - rem.len();
                    current = rem;
                }
                Err(Err::Incomplete(_)) => {
                    SCLogDebug!(
                        "incomplete response: consumed {} needed {} (input len {})",
                        consumed,
                        (current.len() + 1),
                        input.len()
                    );
                    return AppLayerResult::incomplete(consumed as u32, (current.len() + 1) as u32);
                }
                Err(_) => {
                    self.set_event_notx(MQTTEvent::MalformedTraffic, true);
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }

    fn set_event(tx: &mut MQTTTransaction, event: MQTTEvent) {
        tx.tx_data.set_event(event as u8);
    }

    fn set_event_notx(&mut self, event: MQTTEvent, toclient: bool) {
        let mut tx = MQTTTransaction::new_empty();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        if toclient {
            tx.toclient = true;
        } else {
            tx.toserver = true;
        }
        tx.complete = true;
        tx.tx_data.set_event(event as u8);
        self.transactions.push_back(tx);
    }
}

// C exports.

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    match parse_fixed_header(buf) {
        Ok((_, hdr)) => {
            // reject unassigned message type
            if hdr.message_type == MQTTTypeCode::UNASSIGNED {
                return ALPROTO_FAILED;
            }
            // with 2 being the highest valid QoS level
            if hdr.qos_level > 2 {
                return ALPROTO_FAILED;
            }
            return ALPROTO_MQTT;
        }
        Err(Err::Incomplete(_)) => ALPROTO_UNKNOWN,
        Err(_) => ALPROTO_FAILED,
    }
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = MQTTState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(unsafe { Box::from_raw(state as *mut MQTTState) });
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, MQTTState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_parse_request(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, MQTTState);
    return state.parse_request(stream_slice.as_slice());
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_parse_response(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, MQTTState);
    return state.parse_response(stream_slice.as_slice());
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, MQTTState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, MQTTState);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_is_toclient(
    tx: *const std::os::raw::c_void,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    if tx.toclient {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    match direction.into() {
        Direction::ToServer => {
            if tx.complete || tx.toclient {
                return 1;
            }
        }
        Direction::ToClient => {
            if tx.complete || tx.toserver {
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_logged(
    _state: *mut std::os::raw::c_void, tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, MQTTTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_set_logged(
    _state: *mut std::os::raw::c_void, tx: *mut std::os::raw::c_void, logged: u32,
) {
    let tx = cast_pointer!(tx, MQTTTransaction);
    tx.logged.set(logged);
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"mqtt\0";

export_tx_data_get!(rs_mqtt_get_tx_data, MQTTTransaction);
export_state_data_get!(rs_mqtt_get_state_data, MQTTState);

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_register_parser(cfg_max_msg_len: u32) {
    let default_port = CString::new("[1883]").unwrap();
    let max_msg_len = &mut MAX_MSG_LEN;
    *max_msg_len = cfg_max_msg_len;
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
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_mqtt_tx_get_alstate_progress,
        get_eventinfo: Some(MQTTEvent::get_event_info),
        get_eventinfo_byid: Some(MQTTEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(crate::applayer::state_get_tx_iterator::<MQTTState, MQTTTransaction>),
        get_tx_data: rs_mqtt_get_tx_data,
        get_state_data: rs_mqtt_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MQTT = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.mqtt.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                MQTT_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for mqtt.max-tx");
            }
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for MQTT.");
    }
}
