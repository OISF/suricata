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

use super::mqtt::MQTTTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::mqtt::mqtt_message::{MQTTOperation, MQTTSubscribeTopicData};
use crate::mqtt::mqtt_property::MQTTProperty;
use crate::mqtt::parser::FixedHeader;
use std;

pub const MQTT_LOG_PASSWORDS: u32 = BIT_U32!(0);

// logger-owned caps: one record logs at most 128 messages and stops once
// the encoded output passes 1 MiB; a single string is capped at 64 KiB
// regardless of the configured string-log-limit
const MQTT_LOG_MAX_STRING: usize = 64 * 1024;
const MQTT_LOG_MAX_MSGS: usize = 128;
const MQTT_LOG_MAX_BYTES: usize = 1024 * 1024;
const MQTT_LOG_MAX_ARRAY_ITEMS: usize = 64;

struct MqttLogState {
    truncated: bool,
}

impl MqttLogState {
    fn new() -> Self {
        Self { truncated: false }
    }

    /// True once the encoded record is at its byte budget; callers stop.
    fn over_budget(&mut self, js: &JsonBuilder) -> bool {
        if js.len() >= MQTT_LOG_MAX_BYTES {
            self.truncated = true;
            return true;
        }
        false
    }
}

#[inline]
fn log_mqtt_topic(
    js: &mut JsonBuilder, t: &MQTTSubscribeTopicData, max_log_len: usize,
) -> Result<(), JsonError> {
    js.start_object()?;
    js.set_string_limited("topic", &t.topic_name, max_log_len)?;
    js.set_uint("qos", t.qos as u64)?;
    js.close()?;
    return Ok(());
}

#[inline]
fn log_mqtt_header(js: &mut JsonBuilder, hdr: &FixedHeader) -> Result<(), JsonError> {
    js.set_uint("qos", hdr.qos_level as u64)?;
    js.set_bool("retain", hdr.retain)?;
    js.set_bool("dup", hdr.dup_flag)?;
    return Ok(());
}

fn log_mqtt_user_properties(
    js: &mut JsonBuilder, props: &[MQTTProperty], max_log_len: usize, st: &mut MqttLogState,
) -> Result<(), JsonError> {
    let mut open = false;
    for prop in props {
        if let MQTTProperty::USER_PROPERTY((k, v)) = prop {
            if st.over_budget(js) {
                break;
            }
            if !open {
                js.open_array("user_properties")?;
                open = true;
            }
            js.start_object()?;
            js.set_string_limited("key", k, max_log_len)?;
            js.set_string_limited("value", v, max_log_len)?;
            js.close()?;
        }
    }
    if open {
        js.close()?; // user_properties
    }
    return Ok(());
}

// Logs a list of properties as a "properties" object. User properties are
// logged separately, as an array of [key, value] pairs, since their keys are
// peer-controlled and can occur more than once.
#[inline]
fn log_mqtt_properties(
    js: &mut JsonBuilder, props: &[MQTTProperty], max_log_len: usize, st: &mut MqttLogState,
    flags: u32,
) -> Result<(), JsonError> {
    js.open_object("properties")?;
    for prop in props {
        if st.over_budget(js) {
            break;
        }
        // enhanced authentication data is credential material (SCRAM proofs,
        // bearer tokens) and follows the password opt-in
        if let MQTTProperty::AUTHENTICATION_DATA(_) = prop {
            if flags & MQTT_LOG_PASSWORDS == 0 {
                js.set_bool("authentication_data_redacted", true)?;
                continue;
            }
        }
        prop.set_json(js, max_log_len)?;
    }
    log_mqtt_user_properties(js, props, max_log_len, st)?;
    js.close()?; // properties
    return Ok(());
}

fn log_mqtt(
    tx: &MQTTTransaction, flags: u32, max_log_len: usize, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    let max_log_len = if max_log_len == 0 {
        MQTT_LOG_MAX_STRING
    } else {
        std::cmp::min(max_log_len, MQTT_LOG_MAX_STRING)
    };
    let mut st = MqttLogState::new();
    js.open_object("mqtt")?;
    let mut logged_msgs = 0;
    for msg in tx.msg.iter() {
        if logged_msgs >= MQTT_LOG_MAX_MSGS || st.over_budget(js) {
            st.truncated = true;
            break;
        }
        logged_msgs += 1;
        match msg.op {
            MQTTOperation::CONNECT(ref conn) => {
                js.open_object("connect")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_string_limited("protocol_string", &conn.protocol_string, max_log_len)?;
                js.set_uint("protocol_version", conn.protocol_version as u64)?;
                js.set_string_limited("client_id", &conn.client_id, max_log_len)?;
                js.open_object("flags")?;
                js.set_bool("username", conn.username_flag)?;
                js.set_bool("password", conn.password_flag)?;
                js.set_bool("will_retain", conn.will_retain)?;
                js.set_bool("will", conn.will_flag)?;
                js.set_bool("clean_session", conn.clean_session)?;
                js.close()?; // flags
                if let Some(user) = &conn.username {
                    js.set_string_limited("username", user, max_log_len)?;
                }
                if flags & MQTT_LOG_PASSWORDS != 0 {
                    if let Some(pass) = &conn.password {
                        js.set_string_from_bytes_limited("password", pass, max_log_len)?;
                    }
                } else if conn.password.is_some() {
                    js.set_bool("password_redacted", true)?;
                }
                if conn.will_flag {
                    js.open_object("will")?;
                    if let Some(will_topic) = &conn.will_topic {
                        js.set_string_limited("topic", will_topic, max_log_len)?;
                    }
                    if let Some(will_message) = &conn.will_message {
                        js.set_string_from_bytes_limited("message", will_message, max_log_len)?;
                    }
                    if let Some(will_properties) = &conn.will_properties {
                        log_mqtt_properties(js, will_properties, max_log_len, &mut st, flags)?;
                    }
                    js.close()?; // will
                }
                if let Some(properties) = &conn.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // connect
            }
            MQTTOperation::CONNACK(ref connack) => {
                js.open_object("connack")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_bool("session_present", connack.session_present)?;
                js.set_uint("return_code", connack.return_code as u64)?;
                if let Some(properties) = &connack.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // connack
            }
            MQTTOperation::PUBLISH(ref publish) => {
                js.open_object("publish")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_string_limited("topic", &publish.topic, max_log_len)?;
                if let Some(message_id) = publish.message_id {
                    js.set_uint("message_id", message_id as u64)?;
                }
                js.set_string_from_bytes_limited("message", &publish.message, max_log_len)?;
                if let Some(properties) = &publish.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // publish
            }
            MQTTOperation::PUBACK(ref msgidonly) => {
                js.open_object("puback")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", msgidonly.message_id as u64)?;
                if let Some(reason_code) = &msgidonly.reason_code {
                    js.set_uint("reason_code", *reason_code as u64)?;
                }
                if let Some(properties) = &msgidonly.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // puback
            }
            MQTTOperation::PUBREC(ref msgidonly) => {
                js.open_object("pubrec")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", msgidonly.message_id as u64)?;
                if let Some(reason_code) = &msgidonly.reason_code {
                    js.set_uint("reason_code", *reason_code as u64)?;
                }
                if let Some(properties) = &msgidonly.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // pubrec
            }
            MQTTOperation::PUBREL(ref msgidonly) => {
                js.open_object("pubrel")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", msgidonly.message_id as u64)?;
                if let Some(reason_code) = &msgidonly.reason_code {
                    js.set_uint("reason_code", *reason_code as u64)?;
                }
                if let Some(properties) = &msgidonly.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // pubrel
            }
            MQTTOperation::PUBCOMP(ref msgidonly) => {
                js.open_object("pubcomp")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", msgidonly.message_id as u64)?;
                if let Some(reason_code) = &msgidonly.reason_code {
                    js.set_uint("reason_code", *reason_code as u64)?;
                }
                if let Some(properties) = &msgidonly.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // pubcomp
            }
            MQTTOperation::SUBSCRIBE(ref subs) => {
                js.open_object("subscribe")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", subs.message_id as u64)?;
                if !st.over_budget(js) {
                    js.open_array("topics")?;
                    let mut topic_chars: usize = 0;
                    // We only log topics until the length of the concatenation of
                    // the topic names exceed the log limit set.
                    for t in &subs.topics {
                        if st.over_budget(js) {
                            break;
                        }
                        if topic_chars + std::cmp::min(t.topic_name.len(), max_log_len)
                            > max_log_len
                        {
                            st.truncated = true;
                            log_mqtt_topic(js, t, max_log_len - topic_chars)?;
                            break;
                        }
                        log_mqtt_topic(js, t, max_log_len)?;
                        topic_chars += std::cmp::min(t.topic_name.len(), max_log_len);
                    }
                    js.close()?; //topics
                }
                if let Some(properties) = &subs.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // subscribe
            }
            MQTTOperation::SUBACK(ref suback) => {
                js.open_object("suback")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", suback.message_id as u64)?;
                if !st.over_budget(js) {
                    js.open_array("qos_granted")?;
                    for (i, t) in suback.qoss.iter().enumerate() {
                        if i >= MQTT_LOG_MAX_ARRAY_ITEMS || st.over_budget(js) {
                            st.truncated = true;
                            break;
                        }
                        js.append_uint(*t as u64)?;
                    }
                    js.close()?; // qos_granted
                }
                js.close()?; // suback
            }
            MQTTOperation::UNSUBSCRIBE(ref unsub) => {
                js.open_object("unsubscribe")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", unsub.message_id as u64)?;
                if !st.over_budget(js) {
                    js.open_array("topics")?;
                    let mut topic_chars: usize = 0;
                    for t in &unsub.topics {
                        if st.over_budget(js) {
                            break;
                        }
                        let len = std::cmp::min(t.len(), max_log_len);
                        if topic_chars + len > max_log_len {
                            st.truncated = true;
                            js.append_string_limited(t, max_log_len - topic_chars)?;
                            break;
                        }
                        js.append_string_limited(t, max_log_len)?;
                        topic_chars += len;
                    }
                    js.close()?; // topics
                }
                js.close()?; // unsubscribe
            }
            MQTTOperation::UNSUBACK(ref unsuback) => {
                js.open_object("unsuback")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", unsuback.message_id as u64)?;
                if let Some(codes) = &unsuback.reason_codes {
                    if !codes.is_empty() && !st.over_budget(js) {
                        js.open_array("reason_codes")?;
                        for (i, t) in codes.iter().enumerate() {
                            if i >= MQTT_LOG_MAX_ARRAY_ITEMS || st.over_budget(js) {
                                st.truncated = true;
                                break;
                            }
                            js.append_uint(*t as u64)?;
                        }
                        js.close()?; // reason_codes
                    }
                }
                js.close()?; // unsuback
            }
            MQTTOperation::PINGREQ => {
                js.open_object("pingreq")?;
                log_mqtt_header(js, &msg.header)?;
                js.close()?; // pingreq
            }
            MQTTOperation::PINGRESP => {
                js.open_object("pingresp")?;
                log_mqtt_header(js, &msg.header)?;
                js.close()?; // pingresp
            }
            MQTTOperation::AUTH(ref auth) => {
                js.open_object("auth")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("reason_code", auth.reason_code as u64)?;
                if let Some(properties) = &auth.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // auth
            }
            MQTTOperation::DISCONNECT(ref disco) => {
                js.open_object("disconnect")?;
                log_mqtt_header(js, &msg.header)?;
                if let Some(reason_code) = &disco.reason_code {
                    js.set_uint("reason_code", *reason_code as u64)?;
                }
                if let Some(properties) = &disco.properties {
                    log_mqtt_properties(js, properties, max_log_len, &mut st, flags)?;
                }
                js.close()?; // disconnect
            }
            MQTTOperation::TRUNCATED(ref trunc) => {
                js.open_object(&trunc.original_message_type.to_lower_str())?;
                log_mqtt_header(js, &msg.header)?;
                js.set_bool("truncated", true)?;
                js.set_uint("skipped_length", trunc.skipped_length as u64)?;
                js.close()?; // truncated
            }
            MQTTOperation::UNASSIGNED => {}
        }
    }
    if st.truncated {
        js.set_bool("truncated", true)?;
    }
    js.close()?; // mqtt

    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMqttLoggerLog(
    tx: *mut std::os::raw::c_void, flags: u32, max_log_len: u32, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    log_mqtt(tx, flags, max_log_len as usize, js).is_ok()
}
