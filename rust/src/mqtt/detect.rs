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

//use crate::log::*;
use crate::mqtt::mqtt::{MQTTTransaction, MQTTState};
use crate::mqtt::mqtt_message::MQTTOperation;
use std::ptr;

#[derive(FromPrimitive, Debug, Copy, Clone, PartialOrd, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum MQTTFlagState {
    MQTT_DONT_CARE = 0,
    MQTT_MUST_BE_SET = 1,
    MQTT_CANT_BE_SET = 2,
}

#[inline]
fn check_flag_state(
    flag_state: MQTTFlagState,
    flag_value: bool,
    ok: &mut bool,
) {
    match flag_state {
        MQTTFlagState::MQTT_MUST_BE_SET => {
            if !flag_value {
                *ok = false;
            }
        },
        MQTTFlagState::MQTT_CANT_BE_SET => {
            if flag_value {
                *ok = false;
            }
        },
        _ => {}
    }
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_has_type(
    tx: &MQTTTransaction,
    mtype: u8,
) -> u8 {
    for msg in tx.msg.iter() {
        if mtype == msg.header.message_type {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_has_flags(
    tx: &MQTTTransaction,
    qretain: MQTTFlagState,
    qdup: MQTTFlagState,
) -> u8 {
    for msg in tx.msg.iter() {
        let mut ok = true;
        check_flag_state(qretain, msg.header.retain, &mut ok);
        check_flag_state(qdup, msg.header.dup_flag, &mut ok);
        if ok {
            return 1;
        }
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_has_qos(
    tx: &MQTTTransaction,
    qos: u8,
) -> u8 {
    for msg in tx.msg.iter() {
        if qos == msg.header.qos_level {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_protocol_version(
    state: &MQTTState,
    version: *mut u8,
) -> u8 {
    unsafe {
        *version = state.protocol_version;
    }
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_has_connect_flags(
    tx: &MQTTTransaction,
    username: MQTTFlagState,
    password: MQTTFlagState,
    will: MQTTFlagState,
    will_retain: MQTTFlagState,
    clean_session: MQTTFlagState,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            let mut ok = true;
            check_flag_state(username, cv.username_flag, &mut ok);
            check_flag_state(password, cv.password_flag, &mut ok);
            check_flag_state(will, cv.will_flag, &mut ok);
            check_flag_state(will_retain, cv.will_retain, &mut ok);
            check_flag_state(clean_session, cv.clean_session, &mut ok);
            if ok {
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_connect_clientid(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            let p = &cv.client_id;
            if p.len() > 0 {
                unsafe {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                }
                return 1;
            }
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_connect_username(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.username {
                if p.len() > 0 {
                    unsafe {
                        *buffer = p.as_ptr();
                        *buffer_len = p.len() as u32;
                    }
                    return 1;
                }
            }
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_connect_password(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.password {
                if p.len() > 0 {
                    unsafe {
                        *buffer = p.as_ptr();
                        *buffer_len = p.len() as u32;
                    }
                    return 1;
                }
            }
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_connect_willtopic(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.will_topic {
                if p.len() > 0 {
                    unsafe {
                        *buffer = p.as_ptr();
                        *buffer_len = p.len() as u32;
                    }
                    return 1;
                }
            }
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_connect_willmessage(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.will_message {
                if p.len() > 0 {
                    unsafe {
                        *buffer = p.as_ptr();
                        *buffer_len = p.len() as u32;
                    }
                    return 1;
                }
            }
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_connack_sessionpresent(
    tx: &MQTTTransaction,
    session_present: *mut bool,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNACK(ref ca) = msg.op {
            unsafe {
                *session_present = ca.session_present;
            }
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_publish_topic(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::PUBLISH(ref pubv) = msg.op {
            let p = &pubv.topic;
            if p.len() > 0 {
                unsafe {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                }
                return 1;
            }
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_publish_message(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::PUBLISH(ref pubv) = msg.op {
            let p = &pubv.message;
            if p.len() > 0 {
                unsafe {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                }
                return 1;
            }
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_topic(tx: &MQTTTransaction,
                                       i: u16,
                                       buf: *mut *const u8,
                                       len: *mut u32)
                                       -> u8
{
    // This function works on both SUBSCRIBE and UNSUBSCRIBE to reduce code
    // duplication because both have multiple topics that need to be accessed
    // via index from Rust. It does not imply that we expect a TX to have both
    // SUBSCRIBE and UNSUBSCRIBE messages.
    for msg in tx.msg.iter() {
        match msg.op {
            MQTTOperation::SUBSCRIBE(ref subv) => {
                if (i as usize) < subv.topics.len() {
                    let topic = &subv.topics[i as usize];
                    if topic.topic_name.len() > 0 {
                        unsafe {
                            *len = topic.topic_name.len() as u32;
                            *buf = topic.topic_name.as_ptr();
                        }
                        return 1;
                    }
                }
            }
            MQTTOperation::UNSUBSCRIBE(ref unsubv) => {
                if (i as usize) < unsubv.topics.len() {
                    let topic = &unsubv.topics[i as usize];
                    if topic.len() > 0 {
                        unsafe {
                            *len = topic.len() as u32;
                            *buf = topic.as_ptr();
                        }
                        return 1;
                    }
                }
            }
            _ => {}
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_reason_code(
    tx: &MQTTTransaction,
    result: *mut u8,
) -> u8 {
    for msg in tx.msg.iter() {
        match msg.op {
            MQTTOperation::PUBACK(ref v)
            | MQTTOperation::PUBREL(ref v)
            | MQTTOperation::PUBREC(ref v)
            | MQTTOperation::PUBCOMP(ref v) => {
                if let Some(rcode) = v.reason_code {
                    unsafe {
                        *result = rcode;
                    }
                    return 1;
                }
            }
            MQTTOperation::AUTH(ref v) => {
                unsafe {
                    *result = v.reason_code;
                }
                return 1;
            }
            MQTTOperation::CONNACK(ref v) => {
                unsafe {
                    *result = v.return_code;
                }
                return 1;
            }
            MQTTOperation::DISCONNECT(ref v) => {
                if let Some(rcode) = v.reason_code {
                    unsafe {
                        *result = rcode;
                    }
                    return 1;
                }
            }
            _ => return 0
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_unsuback_has_reason_code(
    tx: &MQTTTransaction,
    code: u8,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::UNSUBACK(ref unsuback) = msg.op {
            if let Some(ref reason_codes) = unsuback.reason_codes {
                for rc in reason_codes.iter() {
                    if *rc == code {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}