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

use super::mqtt::{MQTTState, MQTTTransaction};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::mqtt::mqtt_message::{MQTTOperation, MQTTSubscribeTopicData};
use crate::mqtt::parser::FixedHeader;
use std;

pub const MQTT_LOG_PASSWORDS: u32 = BIT_U32!(0);

#[inline]
fn log_mqtt_topic(js: &mut JsonBuilder, t: &MQTTSubscribeTopicData) -> Result<(), JsonError> {
    js.start_object()?;
    js.set_string("topic", &t.topic_name)?;
    js.set_uint("qos", t.qos as u64)?;
    js.close()?;
    Ok(())
}

#[inline]
fn log_mqtt_header(js: &mut JsonBuilder, hdr: &FixedHeader) -> Result<(), JsonError> {
    js.set_uint("qos", hdr.qos_level as u64)?;
    js.set_bool("retain", hdr.retain)?;
    js.set_bool("dup", hdr.dup_flag)?;
    Ok(())
}

fn log_mqtt(tx: &MQTTTransaction, flags: u32, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("mqtt")?;
    for msg in tx.msg.iter() {
        match msg.op {
            MQTTOperation::CONNECT(ref conn) => {
                js.open_object("connect")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_string("protocol_string", &conn.protocol_string)?;
                js.set_uint("protocol_version", conn.protocol_version as u64)?;
                js.set_string("client_id", &conn.client_id)?;
                js.open_object("flags")?;
                js.set_bool("username", conn.username_flag)?;
                js.set_bool("password", conn.password_flag)?;
                js.set_bool("will_retain", conn.will_retain)?;
                js.set_bool("will", conn.will_flag)?;
                js.set_bool("clean_session", conn.clean_session)?;
                js.close()?; // flags
                if let Some(user) = &conn.username {
                    js.set_string("username", user)?;
                }
                if flags & MQTT_LOG_PASSWORDS != 0 {
                    if let Some(pass) = &conn.password {
                        js.set_string_from_bytes("password", pass)?;
                    }
                }
                if conn.will_flag {
                    js.open_object("will")?;
                    if let Some(will_topic) = &conn.will_topic {
                        js.set_string("topic", will_topic)?;
                    }
                    if let Some(will_message) = &conn.will_message {
                        js.set_string_from_bytes("message", will_message)?;
                    }
                    if let Some(will_properties) = &conn.will_properties {
                        js.open_object("properties")?;
                        for prop in will_properties {
                            prop.set_json(js)?;
                        }
                        js.close()?; // properties
                    }
                    js.close()?; // will
                }
                if let Some(properties) = &conn.properties {
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
                }
                js.close()?; // connect
            }
            MQTTOperation::CONNACK(ref connack) => {
                js.open_object("connack")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_bool("session_present", connack.session_present)?;
                js.set_uint("return_code", connack.return_code as u64)?;
                if let Some(properties) = &connack.properties {
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
                }
                js.close()?; // connack
            }
            MQTTOperation::PUBLISH(ref publish) => {
                js.open_object("publish")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_string("topic", &publish.topic)?;
                if let Some(message_id) = publish.message_id {
                    js.set_uint("message_id", message_id as u64)?;
                }
                js.set_string_from_bytes("message", &publish.message)?;
                if let Some(properties) = &publish.properties {
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
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
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
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
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
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
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
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
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
                }
                js.close()?; // pubcomp
            }
            MQTTOperation::SUBSCRIBE(ref subs) => {
                js.open_object("subscribe")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", subs.message_id as u64)?;
                js.open_array("topics")?;
                for t in &subs.topics {
                    log_mqtt_topic(js, t)?;
                }
                js.close()?; //topics
                if let Some(properties) = &subs.properties {
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
                }
                js.close()?; // subscribe
            }
            MQTTOperation::SUBACK(ref suback) => {
                js.open_object("suback")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", suback.message_id as u64)?;
                js.open_array("qos_granted")?;
                for t in &suback.qoss {
                    js.append_uint(*t as u64)?;
                }
                js.close()?; // qos_granted
                js.close()?; // suback
            }
            MQTTOperation::UNSUBSCRIBE(ref unsub) => {
                js.open_object("unsubscribe")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", unsub.message_id as u64)?;
                js.open_array("topics")?;
                for t in &unsub.topics {
                    js.append_string(t)?;
                }
                js.close()?; // topics
                js.close()?; // unsubscribe
            }
            MQTTOperation::UNSUBACK(ref unsuback) => {
                js.open_object("unsuback")?;
                log_mqtt_header(js, &msg.header)?;
                js.set_uint("message_id", unsuback.message_id as u64)?;
                if let Some(codes) = &unsuback.reason_codes {
                    if codes.len() > 0 {
                        js.open_array("reason_codes")?;
                        for t in codes {
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
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
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
                    js.open_object("properties")?;
                    for prop in properties {
                        prop.set_json(js)?;
                    }
                    js.close()?; // properties
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
    js.close()?; // mqtt

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_mqtt_logger_log(
    _state: &mut MQTTState, tx: *mut std::os::raw::c_void, flags: u32, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    log_mqtt(tx, flags, js).is_ok()
}
