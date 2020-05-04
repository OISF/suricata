/* Copyright (C) 2019 Open Information Security Foundation
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
use std::ffi::CStr;
use std::ptr;

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_type(
    tx: &MQTTTransaction,
    mtype: *mut u32,
) -> u8 {
    *mtype = tx.msg.message_type_id();
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_flags(
    tx: &MQTTTransaction,
    retain: *mut bool,
    dup: *mut bool,
) -> u8 {
    *retain = tx.msg.header.retain;
    *dup = tx.msg.header.dup_flag;
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_qos(
    tx: &MQTTTransaction,
    qos: *mut u8,
) -> u8 {
    *qos = tx.msg.header.qos_level;
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_protocol_version(
    state: &MQTTState,
    version: *mut u8,
) -> u8 {
    *version = state.protocol_version;
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_flags(
    tx: &MQTTTransaction,
    username: *mut bool,
    password: *mut bool,
    will: *mut bool,
    will_retain: *mut bool,
    clean_session: *mut bool,
) -> u8 {
    if let MQTTOperation::CONNECT(ref cv) = tx.msg.op {
        *username = cv.username_flag;
        *password = cv.password_flag;
        *will = cv.will_flag;
        *will_retain = cv.will_retain;
        *clean_session = cv.clean_session;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_clientid(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let MQTTOperation::CONNECT(ref cv) = tx.msg.op {
        let p = &cv.client_id;
        if p.len() > 0 {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_username(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let MQTTOperation::CONNECT(ref cv) = tx.msg.op {
        if let Some(p) = &cv.username {
            if p.len() > 0 {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return 1;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_password(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let MQTTOperation::CONNECT(ref cv) = tx.msg.op {
        if let Some(p) = &cv.password {
            if p.len() > 0 {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return 1;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_willtopic(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let MQTTOperation::CONNECT(ref cv) = tx.msg.op {
        if let Some(p) = &cv.will_topic {
            if p.len() > 0 {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return 1;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_willmessage(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let MQTTOperation::CONNECT(ref cv) = tx.msg.op {
        if let Some(p) = &cv.will_message {
            if p.len() > 0 {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return 1;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connack_sessionpresent(
    tx: &MQTTTransaction,
    session_present: *mut bool,
) -> u8 {
    if let MQTTOperation::CONNACK(ref ca) = tx.msg.op {
        *session_present = ca.session_present;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_publish_topic(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let MQTTOperation::PUBLISH(ref pubv) = tx.msg.op {
        let p = &pubv.topic;
        if p.len() > 0 {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_publish_message(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let MQTTOperation::PUBLISH(ref pubv) = tx.msg.op {
        let p = &pubv.message;
        if p.len() > 0 {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_has_topic(
    tx: &MQTTTransaction,
    result: *mut bool,
    topic: *const std::os::raw::c_char,
) -> u8 {
    *result = false;
    match tx.msg.op {
        MQTTOperation::SUBSCRIBE(ref subv) => {
            let c_topic = CStr::from_ptr(topic).to_str().unwrap();
            for topic in subv.topics.iter() {
                if topic.topic_name == c_topic {
                    *result = true;
                    return 1;
                }
            }
        }
        MQTTOperation::UNSUBSCRIBE(ref unsubv) => {
            let c_topic = CStr::from_ptr(topic).to_str().unwrap();
            for topic in unsubv.topics.iter() {
                if topic == c_topic {
                    *result = true;
                    return 1;
                }
            }
        }
        _ => return 0
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_reason_code(
    tx: &MQTTTransaction,
    result: *mut u8,
) -> u8 {
    match tx.msg.op {
        MQTTOperation::PUBACK(ref v)
        | MQTTOperation::PUBREL(ref v)
        | MQTTOperation::PUBREC(ref v)
        | MQTTOperation::PUBCOMP(ref v) => {
            if let Some(rcode) = v.reason_code {
                *result = rcode;
                return 1;
            }
        }
        MQTTOperation::AUTH(ref v) => {
            *result = v.reason_code;
            return 1;
        }
        MQTTOperation::CONNACK(ref v) => {
            *result = v.return_code;
            return 1;
        }
        MQTTOperation::DISCONNECT(ref v) => {
            if let Some(rcode) = v.reason_code {
                *result = rcode;
                return 1;
            }
        }
        _ => return 0
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_unsuback_has_reason_code(
    tx: &MQTTTransaction,
    result: *mut bool,
    code: u8,
) -> u8 {
    *result = false;
    if let MQTTOperation::UNSUBACK(ref unsuback) = tx.msg.op {
        if let Some(ref reason_codes) = unsuback.reason_codes {
            for rc in reason_codes.iter() {
                if *rc == code {
                    *result = true;
                    return 1;
                }
            }
        }
    }
    return 0;
}