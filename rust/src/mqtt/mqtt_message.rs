
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

use crate::mqtt::mqtt_property::*;
use crate::mqtt::parser::*;

#[derive(Debug)]
pub struct MQTTMessage {
    pub header: FixedHeader,
    pub op: MQTTOperation,
}

#[derive(Debug)]
pub enum MQTTOperation {
    UNASSIGNED,
    CONNECT(MQTTConnectData),
    CONNACK(MQTTConnackData),
    PUBLISH(MQTTPublishData),
    PUBACK(MQTTMessageIdOnly),
    PUBREC(MQTTMessageIdOnly),
    PUBREL(MQTTMessageIdOnly),
    PUBCOMP(MQTTMessageIdOnly),
    SUBSCRIBE(MQTTSubscribeData),
    SUBACK(MQTTSubackData),
    UNSUBSCRIBE(MQTTUnsubscribeData),
    UNSUBACK(MQTTUnsubackData),
    AUTH(MQTTAuthData),
    PINGREQ,
    PINGRESP,
    DISCONNECT(MQTTDisconnectData),
    TRUNCATED(MQTTTruncatedData),
}

#[derive(Debug)]
pub struct MQTTConnectData {
    pub protocol_string: String,
    pub protocol_version: u8,
    pub username_flag: bool,
    pub password_flag: bool,
    pub will_retain: bool,
    pub will_qos: u8,
    pub will_flag: bool,
    pub clean_session: bool,
    pub keepalive: u16,
    pub client_id: String,
    pub will_topic: Option<String>,
    pub will_message: Option<Vec<u8>>,
    pub username: Option<String>,
    pub password: Option<Vec<u8>>,
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
    pub will_properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTConnackData {
    pub return_code: u8,
    pub session_present: bool,                 // MQTT 3.1.1
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTPublishData {
    pub topic: String,
    pub message_id: Option<u16>,
    pub message: Vec<u8>,
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTMessageIdOnly {
    pub message_id: u16,
    pub reason_code: Option<u8>,               // MQTT 5.0
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTSubscribeTopicData {
    pub topic_name: String,
    pub qos: u8,
}

#[derive(Debug)]
pub struct MQTTSubscribeData {
    pub message_id: u16,
    pub topics: Vec<MQTTSubscribeTopicData>,
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTSubackData {
    pub message_id: u16,
    pub qoss: Vec<u8>,
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTUnsubscribeData {
    pub message_id: u16,
    pub topics: Vec<String>,
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTUnsubackData {
    pub message_id: u16,
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
    pub reason_codes: Option<Vec<u8>>,         // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTAuthData {
    pub reason_code: u8,                       // MQTT 5.0
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTDisconnectData {
    pub reason_code: Option<u8>,               // MQTT 5.0
    pub properties: Option<Vec<MQTTProperty>>, // MQTT 5.0
}

#[derive(Debug)]
pub struct MQTTTruncatedData {
    pub original_message_type: u8,
    pub skipped_length: usize,
}

impl MQTTMessage {
    pub fn message_type_string(&self) -> String {
        match self.op {
            crate::mqtt::mqtt_message::MQTTOperation::CONNECT(_) => "connect",
            crate::mqtt::mqtt_message::MQTTOperation::CONNACK(_) => "connack",
            crate::mqtt::mqtt_message::MQTTOperation::PUBLISH(_) => "publish",
            crate::mqtt::mqtt_message::MQTTOperation::PUBACK(_) => "puback",
            crate::mqtt::mqtt_message::MQTTOperation::PUBREC(_) => "pubrec",
            crate::mqtt::mqtt_message::MQTTOperation::PUBREL(_) => "pubrel",
            crate::mqtt::mqtt_message::MQTTOperation::PUBCOMP(_) => "pubcomp",
            crate::mqtt::mqtt_message::MQTTOperation::SUBSCRIBE(_) => "subscribe",
            crate::mqtt::mqtt_message::MQTTOperation::SUBACK(_) => "suback",
            crate::mqtt::mqtt_message::MQTTOperation::UNSUBSCRIBE(_) => "unsubscribe",
            crate::mqtt::mqtt_message::MQTTOperation::UNSUBACK(_) => "unsuback",
            crate::mqtt::mqtt_message::MQTTOperation::PINGREQ => "pingreq",
            crate::mqtt::mqtt_message::MQTTOperation::PINGRESP => "pingresp",
            crate::mqtt::mqtt_message::MQTTOperation::DISCONNECT(_) => "disconnect",
            crate::mqtt::mqtt_message::MQTTOperation::AUTH(_) => "auth",
            crate::mqtt::mqtt_message::MQTTOperation::TRUNCATED(_) => "truncated",
            _ => "unassigned",
        }
        .to_string()
    }
}

pub fn message_code_string(op: u8) -> String {
    match op {
        1 => "connect",
        2 => "connack",
        3 => "publish",
        4 => "puback",
        5 => "pubrec",
        6 => "pubrel",
        7 => "pubcomp",
        8 => "subscribe",
        9 => "suback",
        10 => "unsubscribe",
        11 => "unsuback",
        12 => "pingreq",
        13 => "pingresp",
        14 => "disconnect",
        15 => "auth",
        _ => "unassigned",
    }
    .to_string()
}