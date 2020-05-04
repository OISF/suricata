
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

use crate::mqtt::parser::*;
use nom::number::streaming::*;
use nom::*;

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum MQTTProperty {
    UNKNOWN,
    PAYLOAD_FORMAT_INDICATOR(u8),
    MESSAGE_EXPIRY_INTERVAL(u32),
    CONTENT_TYPE(String),
    RESPONSE_TOPIC(String),
    CORRELATION_DATA(Vec<u8>),
    SUBSCRIPTION_IDENTIFIER(u32),
    SESSION_EXPIRY_INTERVAL(u32),
    ASSIGNED_CLIENT_IDENTIFIER(String),
    SERVER_KEEP_ALIVE(u16),
    AUTHENTICATION_METHOD(String),
    AUTHENTICATION_DATA(Vec<u8>),
    REQUEST_PROBLEM_INFORMATION(u8),
    WILL_DELAY_INTERVAL(u32),
    REQUEST_RESPONSE_INFORMATION(u8),
    RESPONSE_INFORMATION(String),
    SERVER_REFERENCE(String),
    REASON_STRING(String),
    RECEIVE_MAXIMUM(u16),
    TOPIC_ALIAS_MAXIMUM(u16),
    TOPIC_ALIAS(u16),
    MAXIMUM_QOS(u8),
    RETAIN_AVAILABLE(u8),
    USER_PROPERTY((String, String)),
    MAXIMUM_PACKET_SIZE(u32),
    WILDCARD_SUBSCRIPTION_AVAILABLE(u8),
    SUBSCRIPTION_IDENTIFIER_AVAILABLE(u8),
    SHARED_SUBSCRIPTION_AVAILABLE(u8),
}

impl crate::mqtt::mqtt_property::MQTTProperty {
    pub fn set_json(&self, json: &crate::json::Json) {
        match self {
            crate::mqtt::mqtt_property::MQTTProperty::PAYLOAD_FORMAT_INDICATOR(v) => {
                json.set_integer("payload_format_indicator", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::MESSAGE_EXPIRY_INTERVAL(v) => {
                json.set_integer("message_expiry_interval", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::CONTENT_TYPE(v) => {
                json.set_string("content_type", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::RESPONSE_TOPIC(v) => {
                json.set_string("response_topic", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::CORRELATION_DATA(v) => {
                json.set_string_from_bytes("correlation_data", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::SUBSCRIPTION_IDENTIFIER(v) => {
                json.set_integer("subscription_identifier", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::SESSION_EXPIRY_INTERVAL(v) => {
                json.set_integer("session_expiry_interval", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::ASSIGNED_CLIENT_IDENTIFIER(v) => {
                json.set_string("assigned_client_identifier", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::SERVER_KEEP_ALIVE(v) => {
                json.set_integer("server_keep_alive", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::AUTHENTICATION_METHOD(v) => {
                json.set_string("authentication_method", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::AUTHENTICATION_DATA(v) => {
                json.set_string_from_bytes("authentication_data", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::REQUEST_PROBLEM_INFORMATION(v) => {
                json.set_integer("request_problem_information", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::WILL_DELAY_INTERVAL(v) => {
                json.set_integer("will_delay_interval", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::REQUEST_RESPONSE_INFORMATION(v) => {
                json.set_integer("request_response_information", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::RESPONSE_INFORMATION(v) => {
                json.set_string("response_information", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::SERVER_REFERENCE(v) => {
                json.set_string("server_reference", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::REASON_STRING(v) => {
                json.set_string("reason_string", &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::RECEIVE_MAXIMUM(v) => {
                json.set_integer("receive_maximum", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::TOPIC_ALIAS_MAXIMUM(v) => {
                json.set_integer("topic_alias_maximum", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::TOPIC_ALIAS(v) => {
                json.set_integer("topic_alias", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::MAXIMUM_QOS(v) => {
                json.set_integer("maximum_qos", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::RETAIN_AVAILABLE(v) => {
                json.set_integer("retain_available", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::USER_PROPERTY((k, v)) => {
                json.set_string(k, &v);
            }
            crate::mqtt::mqtt_property::MQTTProperty::MAXIMUM_PACKET_SIZE(v) => {
                json.set_integer("maximum_packet_size", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::WILDCARD_SUBSCRIPTION_AVAILABLE(v) => {
                json.set_integer("wildcard_subscription_available", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::SUBSCRIPTION_IDENTIFIER_AVAILABLE(v) => {
                json.set_integer("subscription_identifier_available", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::SHARED_SUBSCRIPTION_AVAILABLE(v) => {
                json.set_integer("shared_subscription_available", *v as u64);
            }
            crate::mqtt::mqtt_property::MQTTProperty::UNKNOWN => {
                // pass
            }
        }
    }
}

#[inline]
pub fn parse_qualified_property(input: &[u8], identifier: u32) -> IResult<&[u8], MQTTProperty> {
    match identifier {
        1 => match be_u8(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::PAYLOAD_FORMAT_INDICATOR(val))),
            Err(e) => return Err(e),
        },
        2 => match be_u32(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::MESSAGE_EXPIRY_INTERVAL(val))),
            Err(e) => return Err(e),
        },
        3 => match parse_mqtt_string(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::CONTENT_TYPE(val))),
            Err(e) => return Err(e),
        },
        8 => match parse_mqtt_string(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::RESPONSE_TOPIC(val))),
            Err(e) => return Err(e),
        },
        9 => match parse_mqtt_binary_data(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::CORRELATION_DATA(val))),
            Err(e) => return Err(e),
        },
        11 => match parse_mqtt_variable_integer(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::SUBSCRIPTION_IDENTIFIER(val))),
            Err(e) => return Err(e),
        },
        17 => match be_u32(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::SESSION_EXPIRY_INTERVAL(val))),
            Err(e) => return Err(e),
        },
        18 => match parse_mqtt_string(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::ASSIGNED_CLIENT_IDENTIFIER(val))),
            Err(e) => return Err(e),
        },
        19 => match be_u16(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::SERVER_KEEP_ALIVE(val))),
            Err(e) => return Err(e),
        },
        21 => match parse_mqtt_string(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::AUTHENTICATION_METHOD(val))),
            Err(e) => return Err(e),
        },
        22 => match parse_mqtt_binary_data(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::AUTHENTICATION_DATA(val))),
            Err(e) => return Err(e),
        },
        23 => match be_u8(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::REQUEST_PROBLEM_INFORMATION(val))),
            Err(e) => return Err(e),
        },
        24 => match be_u32(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::WILL_DELAY_INTERVAL(val))),
            Err(e) => return Err(e),
        },
        25 => match be_u8(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::REQUEST_RESPONSE_INFORMATION(val))),
            Err(e) => return Err(e),
        },
        26 => match parse_mqtt_string(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::RESPONSE_INFORMATION(val))),
            Err(e) => return Err(e),
        },
        28 => match parse_mqtt_string(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::SERVER_REFERENCE(val))),
            Err(e) => return Err(e),
        },
        31 => match parse_mqtt_string(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::REASON_STRING(val))),
            Err(e) => return Err(e),
        },
        33 => match be_u16(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::RECEIVE_MAXIMUM(val))),
            Err(e) => return Err(e),
        },
        34 => match be_u16(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::TOPIC_ALIAS_MAXIMUM(val))),
            Err(e) => return Err(e),
        },
        35 => match be_u16(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::TOPIC_ALIAS(val))),
            Err(e) => return Err(e),
        },
        36 => match be_u8(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::MAXIMUM_QOS(val))),
            Err(e) => return Err(e),
        },
        37 => match be_u8(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::RETAIN_AVAILABLE(val))),
            Err(e) => return Err(e),
        },
        38 => match parse_mqtt_string_pair(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::USER_PROPERTY(val))),
            Err(e) => return Err(e),
        },
        39 => match be_u32(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::MAXIMUM_PACKET_SIZE(val))),
            Err(e) => return Err(e),
        },
        40 => match be_u8(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::WILDCARD_SUBSCRIPTION_AVAILABLE(val))),
            Err(e) => return Err(e),
        },
        41 => match be_u8(input) {
            Ok((rem, val)) => {
                return Ok((rem, MQTTProperty::SUBSCRIPTION_IDENTIFIER_AVAILABLE(val)))
            }
            Err(e) => return Err(e),
        },
        42 => match be_u8(input) {
            Ok((rem, val)) => return Ok((rem, MQTTProperty::SHARED_SUBSCRIPTION_AVAILABLE(val))),
            Err(e) => return Err(e),
        },
        _ => {
            return Ok((input, MQTTProperty::UNKNOWN));
        }
    }
}
