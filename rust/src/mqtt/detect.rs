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

use crate::mqtt::mqtt::{MQTTState, MQTTTransaction};
use crate::mqtt::mqtt_message::{MQTTOperation, MQTTTypeCode};
use std::ffi::CStr;
use std::ptr;
use std::str::FromStr;

#[derive(FromPrimitive, Debug, Copy, Clone, PartialOrd, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum MQTTFlagState {
    MQTT_DONT_CARE = 0,
    MQTT_MUST_BE_SET = 1,
    MQTT_CANT_BE_SET = 2,
}

#[inline]
fn check_flag_state(flag_state: MQTTFlagState, flag_value: bool, ok: &mut bool) {
    match flag_state {
        MQTTFlagState::MQTT_MUST_BE_SET => {
            if !flag_value {
                *ok = false;
            }
        }
        MQTTFlagState::MQTT_CANT_BE_SET => {
            if flag_value {
                *ok = false;
            }
        }
        _ => {}
    }
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_has_type(tx: &MQTTTransaction, mtype: u8) -> u8 {
    for msg in tx.msg.iter() {
        if mtype == msg.header.message_type as u8 {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_cstr_message_code(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let msgtype: &CStr = CStr::from_ptr(str);
    if let Ok(s) = msgtype.to_str() {
        if let Ok(x) = MQTTTypeCode::from_str(s) {
            return x as i32;
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_has_flags(
    tx: &MQTTTransaction, qretain: MQTTFlagState, qdup: MQTTFlagState,
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
pub extern "C" fn rs_mqtt_tx_has_qos(tx: &MQTTTransaction, qos: u8) -> u8 {
    for msg in tx.msg.iter() {
        if qos == msg.header.qos_level {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_get_protocol_version(state: &MQTTState) -> u8 {
    return state.protocol_version;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_has_connect_flags(
    tx: &MQTTTransaction, username: MQTTFlagState, password: MQTTFlagState, will: MQTTFlagState,
    will_retain: MQTTFlagState, clean_session: MQTTFlagState,
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
pub unsafe extern "C" fn rs_mqtt_tx_get_connect_clientid(
    tx: &MQTTTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
    tx: &MQTTTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
    tx: &MQTTTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
    tx: &MQTTTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
    tx: &MQTTTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
    tx: &MQTTTransaction, session_present: *mut bool,
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
    tx: &MQTTTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
    tx: &MQTTTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
pub unsafe extern "C" fn rs_mqtt_tx_get_subscribe_topic(
    tx: &MQTTTransaction, i: u32, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let mut offset = 0;
    for msg in tx.msg.iter() {
        if let MQTTOperation::SUBSCRIBE(ref subv) = msg.op {
            if (i as usize) < subv.topics.len() + offset {
                let topic = &subv.topics[(i as usize) - offset];
                if topic.topic_name.len() > 0 {
                    *len = topic.topic_name.len() as u32;
                    *buf = topic.topic_name.as_ptr();
                    return 1;
                }
            } else {
                offset += subv.topics.len();
            }
        }
    }

    *buf = ptr::null();
    *len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_unsubscribe_topic(
    tx: &MQTTTransaction, i: u32, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let mut offset = 0;
    for msg in tx.msg.iter() {
        if let MQTTOperation::UNSUBSCRIBE(ref unsubv) = msg.op {
            if (i as usize) < unsubv.topics.len() + offset {
                let topic = &unsubv.topics[(i as usize) - offset];
                if topic.len() > 0 {
                    *len = topic.len() as u32;
                    *buf = topic.as_ptr();
                    return 1;
                }
            } else {
                offset += unsubv.topics.len();
            }
        }
    }

    *buf = ptr::null();
    *len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_tx_get_reason_code(tx: &MQTTTransaction, result: *mut u8) -> u8 {
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
            _ => return 0,
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_mqtt_tx_unsuback_has_reason_code(tx: &MQTTTransaction, code: u8) -> u8 {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::mqtt::mqtt::MQTTTransaction;
    use crate::mqtt::mqtt_message::*;
    use crate::mqtt::parser::FixedHeader;
    use std;

    #[test]
    fn test_multi_unsubscribe() {
        let mut t = MQTTTransaction::new(MQTTMessage {
            header: FixedHeader {
                message_type: MQTTTypeCode::UNSUBSCRIBE,
                dup_flag: false,
                qos_level: 0,
                retain: false,
                remaining_length: 0,
            },
            op: MQTTOperation::UNSUBSCRIBE(MQTTUnsubscribeData {
                message_id: 1,
                topics: vec!["foo".to_string(), "baar".to_string()],
                properties: None,
            }),
        });
        t.msg.push(MQTTMessage {
            header: FixedHeader {
                message_type: MQTTTypeCode::UNSUBSCRIBE,
                dup_flag: false,
                qos_level: 0,
                retain: false,
                remaining_length: 0,
            },
            op: MQTTOperation::UNSUBSCRIBE(MQTTUnsubscribeData {
                message_id: 1,
                topics: vec!["fieee".to_string(), "baaaaz".to_string()],
                properties: None,
            }),
        });
        let mut s: *const u8 = std::ptr::null_mut();
        let mut slen: u32 = 0;
        let mut r = unsafe { rs_mqtt_tx_get_unsubscribe_topic(&t, 0, &mut s, &mut slen) };
        assert_eq!(r, 1);
        let mut topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "foo");
        r = unsafe { rs_mqtt_tx_get_unsubscribe_topic(&t, 1, &mut s, &mut slen) };
        assert_eq!(r, 1);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baar");
        r = unsafe { rs_mqtt_tx_get_unsubscribe_topic(&t, 2, &mut s, &mut slen) };
        assert_eq!(r, 1);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "fieee");
        r = unsafe { rs_mqtt_tx_get_unsubscribe_topic(&t, 3, &mut s, &mut slen) };
        assert_eq!(r, 1);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baaaaz");
        r = unsafe { rs_mqtt_tx_get_unsubscribe_topic(&t, 4, &mut s, &mut slen) };
        assert_eq!(r, 0);
    }

    #[test]
    fn test_multi_subscribe() {
        let mut t = MQTTTransaction::new(MQTTMessage {
            header: FixedHeader {
                message_type: MQTTTypeCode::SUBSCRIBE,
                dup_flag: false,
                qos_level: 0,
                retain: false,
                remaining_length: 0,
            },
            op: MQTTOperation::SUBSCRIBE(MQTTSubscribeData {
                message_id: 1,
                topics: vec![
                    MQTTSubscribeTopicData {
                        topic_name: "foo".to_string(),
                        qos: 0,
                    },
                    MQTTSubscribeTopicData {
                        topic_name: "baar".to_string(),
                        qos: 1,
                    },
                ],
                properties: None,
            }),
        });
        t.msg.push(MQTTMessage {
            header: FixedHeader {
                message_type: MQTTTypeCode::SUBSCRIBE,
                dup_flag: false,
                qos_level: 0,
                retain: false,
                remaining_length: 0,
            },
            op: MQTTOperation::SUBSCRIBE(MQTTSubscribeData {
                message_id: 1,
                topics: vec![
                    MQTTSubscribeTopicData {
                        topic_name: "fieee".to_string(),
                        qos: 0,
                    },
                    MQTTSubscribeTopicData {
                        topic_name: "baaaaz".to_string(),
                        qos: 1,
                    },
                ],
                properties: None,
            }),
        });
        let mut s: *const u8 = std::ptr::null_mut();
        let mut slen: u32 = 0;
        let mut r = unsafe { rs_mqtt_tx_get_subscribe_topic(&t, 0, &mut s, &mut slen) };
        assert_eq!(r, 1);
        let mut topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "foo");
        r = unsafe { rs_mqtt_tx_get_subscribe_topic(&t, 1, &mut s, &mut slen) };
        assert_eq!(r, 1);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baar");
        r = unsafe { rs_mqtt_tx_get_subscribe_topic(&t, 2, &mut s, &mut slen) };
        assert_eq!(r, 1);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "fieee");
        r = unsafe { rs_mqtt_tx_get_subscribe_topic(&t, 3, &mut s, &mut slen) };
        assert_eq!(r, 1);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baaaaz");
        r = unsafe { rs_mqtt_tx_get_subscribe_topic(&t, 4, &mut s, &mut slen) };
        assert_eq!(r, 0);
    }
}
