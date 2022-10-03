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
use std::fmt;

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
    // TRUNCATED is special, representing a message that was not parsed
    // in its entirety due to size constraints. There is no equivalent in
    // the MQTT specification.
    TRUNCATED(MQTTTruncatedData),
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, PartialOrd, FromPrimitive, Debug)]
pub enum MQTTTypeCode {
    UNASSIGNED = 0,
    CONNECT = 1,
    CONNACK = 2,
    PUBLISH = 3,
    PUBACK = 4,
    PUBREC = 5,
    PUBREL = 6,
    PUBCOMP = 7,
    SUBSCRIBE = 8,
    SUBACK = 9,
    UNSUBSCRIBE = 10,
    UNSUBACK = 11,
    PINGREQ = 12,
    PINGRESP = 13,
    DISCONNECT = 14,
    AUTH = 15,
}

impl MQTTTypeCode {
    pub fn to_lower_str(&self) -> String {
        self.to_string().to_lowercase()
    }
}

impl fmt::Display for MQTTTypeCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for MQTTTypeCode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let su = s.to_uppercase();
        let su_slice: &str = &su;
        match su_slice {
            "CONNECT" => Ok(MQTTTypeCode::CONNECT),
            "CONNACK" => Ok(MQTTTypeCode::CONNACK),
            "PUBLISH" => Ok(MQTTTypeCode::PUBLISH),
            "PUBACK" => Ok(MQTTTypeCode::PUBACK),
            "PUBREC" => Ok(MQTTTypeCode::PUBREC),
            "PUBREL" => Ok(MQTTTypeCode::PUBREL),
            "PUBCOMP" => Ok(MQTTTypeCode::PUBCOMP),
            "SUBSCRIBE" => Ok(MQTTTypeCode::SUBSCRIBE),
            "SUBACK" => Ok(MQTTTypeCode::SUBACK),
            "UNSUBSCRIBE" => Ok(MQTTTypeCode::UNSUBSCRIBE),
            "UNSUBACK" => Ok(MQTTTypeCode::UNSUBACK),
            "PINGREQ" => Ok(MQTTTypeCode::PINGREQ),
            "PINGRESP" => Ok(MQTTTypeCode::PINGRESP),
            "DISCONNECT" => Ok(MQTTTypeCode::DISCONNECT),
            "AUTH" => Ok(MQTTTypeCode::AUTH),
            _ => Err(format!("'{}' is not a valid value for MQTTTypeCode", s)),
        }
    }
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
    pub original_message_type: MQTTTypeCode,
    pub skipped_length: usize,
}
