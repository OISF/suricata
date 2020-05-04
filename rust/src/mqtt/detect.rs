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

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum MQTTFlagState {
    DONT_CARE = 0,
    MUST_BE_SET = 1,
    CANT_BE_SET = 2,
    INVALID,
}

impl From<u8> for MQTTFlagState {
    fn from(state: u8) -> Self {
        match state {
            0 => MQTTFlagState::DONT_CARE,
            1 => MQTTFlagState::MUST_BE_SET,
            2 => MQTTFlagState::CANT_BE_SET,
            _ => MQTTFlagState::INVALID,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_has_type(
    tx: &MQTTTransaction,
    mtype: u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if mtype == msg.message_type_id() {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_has_flags(
    tx: &MQTTTransaction,
    qretain: u8,
    qdup: u8,
) -> u8 {
    for msg in tx.msg.iter() {
        let retain = msg.header.retain;
        let dup = msg.header.dup_flag;
        let mut ok = true;
        match MQTTFlagState::from(qretain) {
            MQTTFlagState::MUST_BE_SET => {
                if !retain {
                    ok = false;
                }
            },
            MQTTFlagState::CANT_BE_SET => {
                if retain {
                    ok = false;
                }
            },
            _ => {}
        }
        match MQTTFlagState::from(qdup) {
            MQTTFlagState::MUST_BE_SET => {
                if !dup {
                    ok = false;
                }
            },
            MQTTFlagState::CANT_BE_SET => {
                if dup {
                    ok = false;
                }
            },
            _ => {}
        }
        if ok {
            return 1;
        }
    }

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_has_qos(
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
pub unsafe extern "C" fn rs_mqtt_tx_get_protocol_version(
    state: &MQTTState,
    version: *mut u8,
) -> u8 {
    *version = state.protocol_version;
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_has_connect_flags(
    tx: &MQTTTransaction,
    username: u8,
    password: u8,
    will: u8,
    will_retain: u8,
    clean_session: u8,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            let mut ok = true;
            match MQTTFlagState::from(username) {
                MQTTFlagState::MUST_BE_SET => {
                    if !cv.username_flag {
                        ok = false;
                    }
                },
                MQTTFlagState::CANT_BE_SET => {
                    if cv.username_flag {
                        ok = false;
                    }
                },
                _ => {}
            }
            match MQTTFlagState::from(password) {
                MQTTFlagState::MUST_BE_SET => {
                    if !cv.password_flag {
                        ok = false;
                    }
                },
                MQTTFlagState::CANT_BE_SET => {
                    if cv.password_flag {
                        ok = false;
                    }
                },
                _ => {}
            }
            match MQTTFlagState::from(will) {
                MQTTFlagState::MUST_BE_SET => {
                    if !cv.will_flag {
                        ok = false;
                    }
                },
                MQTTFlagState::CANT_BE_SET => {
                    if cv.will_flag {
                        ok = false;
                    }
                },
                _ => {}
            }
            match MQTTFlagState::from(will_retain) {
                MQTTFlagState::MUST_BE_SET => {
                    if !cv.will_retain {
                        ok = false;
                    }
                },
                MQTTFlagState::CANT_BE_SET => {
                    if cv.will_retain {
                        ok = false;
                    }
                },
                _ => {}
            }
            match MQTTFlagState::from(clean_session) {
                MQTTFlagState::MUST_BE_SET => {
                    if !cv.clean_session {
                        ok = false;
                    }
                },
                MQTTFlagState::CANT_BE_SET => {
                    if cv.clean_session {
                        ok = false;
                    }
                },
                _ => {}
            }
            if ok {
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_clientid(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            let p = &cv.client_id;
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
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_username(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.username {
                if p.len() > 0 {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return 1;
                }
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
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.password {
                if p.len() > 0 {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return 1;
                }
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
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.will_topic {
                if p.len() > 0 {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return 1;
                }
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
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.will_message {
                if p.len() > 0 {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return 1;
                }
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
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNACK(ref ca) = msg.op {
            *session_present = ca.session_present;
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_publish_topic(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::PUBLISH(ref pubv) = msg.op {
            let p = &pubv.topic;
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
pub unsafe extern "C" fn rs_mqtt_tx_get_publish_message(
    tx: &MQTTTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    for msg in tx.msg.iter() {
        if let MQTTOperation::PUBLISH(ref pubv) = msg.op {
            let p = &pubv.message;
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
pub unsafe extern "C" fn rs_mqtt_tx_has_topic(
    tx: &MQTTTransaction,
    result: *mut bool,
    topic: *const std::os::raw::c_char,
) -> u8 {
    *result = false;
    for msg in tx.msg.iter() {
        match msg.op {
            MQTTOperation::SUBSCRIBE(ref subv) => {
                if let Ok(c_topic) = CStr::from_ptr(topic).to_str() {
                    for topic in subv.topics.iter() {
                        if topic.topic_name == c_topic {
                            *result = true;
                            return 1;
                        }
                    }
                }
            }
            MQTTOperation::UNSUBSCRIBE(ref unsubv) => {
                if let Ok(c_topic) = CStr::from_ptr(topic).to_str() {
                    for topic in unsubv.topics.iter() {
                        if topic == c_topic {
                            *result = true;
                            return 1;
                        }
                    }
                }
                return 0;
            }
            _ => return 0
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_reason_code(
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
    for msg in tx.msg.iter() {
        if let MQTTOperation::UNSUBACK(ref unsuback) = msg.op {
            if let Some(ref reason_codes) = unsuback.reason_codes {
                for rc in reason_codes.iter() {
                    if *rc == code {
                        *result = true;
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}