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

use super::mqtt::{MQTTTransaction,MQTTState};
use crate::json::*;
use crate::mqtt::mqtt_message::MQTTOperation;
use std;

pub const MQTT_LOG_PASSWORDS: u32 = BIT_U32!(0);

fn log_mqtt(tx: &MQTTTransaction, flags: u32) -> Option<Json> {
    let js = Json::object();
    for msg in tx.msg.iter() {
        let msg_json = Json::object();
        msg_json.set_integer("qos", msg.header.qos_level as u64);
        msg_json.set_boolean("retain", msg.header.retain);
        msg_json.set_boolean("dup", msg.header.dup_flag);
        match msg.op {
            MQTTOperation::CONNECT(ref conn) => {
                msg_json.set_string("protocol_string", &conn.protocol_string);
                msg_json.set_integer("protocol_version", conn.protocol_version as u64);
                let flags_json = Json::object();
                flags_json.set_boolean("username", conn.username_flag);
                flags_json.set_boolean("password", conn.password_flag);
                flags_json.set_boolean("will_retain", conn.will_retain);
                flags_json.set_boolean("will", conn.will_flag);
                flags_json.set_boolean("clean_session", conn.clean_session);
                msg_json.set("flags", flags_json);
                msg_json.set_string("client_id", &conn.client_id);
                if let Some(user) = &conn.username {
                    msg_json.set_string("username", user);
                }
                if flags & MQTT_LOG_PASSWORDS != 0 {
                    if let Some(pass) = &conn.password {
                        msg_json.set_string_from_bytes("password", pass);
                    }
                }
                if conn.will_flag {
                    let will_json = Json::object();
                    if let Some(will_topic) = &conn.will_topic {
                        will_json.set_string("topic", will_topic);
                    }
                    if let Some(will_message) = &conn.will_message {
                        will_json.set_string_from_bytes("message", will_message);
                    }
                    if let Some(will_properties) = &conn.will_properties {
                        let prop_json = Json::object();
                        for prop in will_properties {
                            prop.set_json(&prop_json);
                        }
                        will_json.set("properties", prop_json);
                    }
                    msg_json.set("will", will_json);
                }
                if let Some(properties) = &conn.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("connect", msg_json);
            }
            MQTTOperation::CONNACK(ref connack) => {
                msg_json.set_boolean("session_present", connack.session_present);
                msg_json.set_integer("return_code", connack.return_code as u64);
                if let Some(properties) = &connack.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("connack", msg_json);
            }
            MQTTOperation::PUBLISH(ref publish) => {
                msg_json.set_string("topic", &publish.topic);
                if let Some(message_id) = publish.message_id {
                    msg_json.set_integer("message_id", message_id as u64);
                }
                msg_json.set_string_from_bytes("message", &publish.message);
                if let Some(properties) = &publish.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("publish", msg_json);
            }
            MQTTOperation::PUBACK(ref msgidonly) => {
                msg_json.set_integer("message_id", msgidonly.message_id as u64);
                if let Some(reason_code) = &msgidonly.reason_code {
                    msg_json.set_integer("reason_code", *reason_code as u64);
                }
                if let Some(properties) = &msgidonly.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("puback", msg_json);
            }
            MQTTOperation::PUBREC(ref msgidonly) => {
                msg_json.set_integer("message_id", msgidonly.message_id as u64);
                if let Some(reason_code) = &msgidonly.reason_code {
                    msg_json.set_integer("reason_code", *reason_code as u64);
                }
                if let Some(properties) = &msgidonly.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("pubrec", msg_json);
            }
            MQTTOperation::PUBREL(ref msgidonly) => {
                msg_json.set_integer("message_id", msgidonly.message_id as u64);
                if let Some(reason_code) = &msgidonly.reason_code {
                    msg_json.set_integer("reason_code", *reason_code as u64);
                }
                if let Some(properties) = &msgidonly.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("pubrel", msg_json);
            }
            MQTTOperation::PUBCOMP(ref msgidonly) => {
                msg_json.set_integer("message_id", msgidonly.message_id as u64);
                if let Some(reason_code) = &msgidonly.reason_code {
                    msg_json.set_integer("reason_code", *reason_code as u64);
                }
                if let Some(properties) = &msgidonly.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("pubcomp", msg_json);
            }
            MQTTOperation::SUBSCRIBE(ref subs) => {
                msg_json.set_integer("message_id", subs.message_id as u64);
                let topics_json = Json::array();
                for ref t in &subs.topics {
                    let topic_json = Json::object();
                    topic_json.set_string("topic", &t.topic_name);
                    topic_json.set_integer("qos", t.qos as u64);
                    topics_json.array_append(topic_json);
                }
                if let Some(properties) = &subs.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                msg_json.set("topics", topics_json);
                js.set("subscribe", msg_json);
            }
            MQTTOperation::SUBACK(ref suback) => {
                msg_json.set_integer("message_id", suback.message_id as u64);
                let qos_json = Json::array();
                for t in &suback.qoss {
                    qos_json.array_append_integer(*t as u64);
                }
                msg_json.set("qos_granted", qos_json);
                js.set("suback", msg_json);
            }
            MQTTOperation::UNSUBSCRIBE(ref unsub) => {
                msg_json.set_integer("message_id", unsub.message_id as u64);
                let unsub_json = Json::array();
                for t in &unsub.topics {
                    unsub_json.array_append_string(t);
                }
                msg_json.set("topics", unsub_json);
                js.set("unsubscribe", msg_json);
            }
            MQTTOperation::UNSUBACK(ref unsuback) => {
                msg_json.set_integer("message_id", unsuback.message_id as u64);
                if let Some(codes) = &unsuback.reason_codes {
                    let rcodes_json = Json::array();
                    for t in codes {
                        rcodes_json.array_append_integer(*t as u64);
                    }
                    msg_json.set("reason_codes", rcodes_json);
                }
                js.set("unsuback", msg_json);
            }
            MQTTOperation::AUTH(ref auth) => {
                msg_json.set_integer("reason_code", auth.reason_code as u64);
                if let Some(properties) = &auth.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("auth", msg_json);
            }
            MQTTOperation::DISCONNECT(ref disco) => {
                if let Some(reason_code) = &disco.reason_code {
                    msg_json.set_integer("reason_code", *reason_code as u64);
                }
                if let Some(properties) = &disco.properties {
                    let prop_json = Json::object();
                    for prop in properties {
                        prop.set_json(&prop_json);
                    }
                    msg_json.set("properties", prop_json);
                }
                js.set("disconnect", msg_json)
            },
            ref _what => {
                js.set("unassigned", msg_json);
            }
        }
    }
    return Some(js);
}

#[no_mangle]
pub extern "C" fn rs_mqtt_logger_log(_state: &mut MQTTState, tx: *mut std::os::raw::c_void, flags: u32) -> *mut JsonT {
    let tx = cast_pointer!(tx, MQTTTransaction);
    match log_mqtt(tx, flags) {
        Some(js) => js.unwrap(),
        None => std::ptr::null_mut(),
    }
}
