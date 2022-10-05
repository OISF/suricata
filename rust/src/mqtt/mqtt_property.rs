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

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::mqtt::parser::*;
use nom7::number::streaming::*;
use nom7::IResult;

// TODO: It might be useful to also add detection on property presence and
// content, e.g. mqtt.property: AUTHENTICATION_METHOD.
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
    pub fn set_json(&self, js: &mut JsonBuilder) -> Result<(), JsonError> {
        match self {
            crate::mqtt::mqtt_property::MQTTProperty::PAYLOAD_FORMAT_INDICATOR(v) => {
                js.set_uint("payload_format_indicator", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::MESSAGE_EXPIRY_INTERVAL(v) => {
                js.set_uint("message_expiry_interval", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::CONTENT_TYPE(v) => {
                js.set_string("content_type", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::RESPONSE_TOPIC(v) => {
                js.set_string("response_topic", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::CORRELATION_DATA(v) => {
                js.set_string_from_bytes("correlation_data", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::SUBSCRIPTION_IDENTIFIER(v) => {
                js.set_uint("subscription_identifier", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::SESSION_EXPIRY_INTERVAL(v) => {
                js.set_uint("session_expiry_interval", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::ASSIGNED_CLIENT_IDENTIFIER(v) => {
                js.set_string("assigned_client_identifier", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::SERVER_KEEP_ALIVE(v) => {
                js.set_uint("server_keep_alive", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::AUTHENTICATION_METHOD(v) => {
                js.set_string("authentication_method", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::AUTHENTICATION_DATA(v) => {
                js.set_string_from_bytes("authentication_data", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::REQUEST_PROBLEM_INFORMATION(v) => {
                js.set_uint("request_problem_information", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::WILL_DELAY_INTERVAL(v) => {
                js.set_uint("will_delay_interval", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::REQUEST_RESPONSE_INFORMATION(v) => {
                js.set_uint("request_response_information", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::RESPONSE_INFORMATION(v) => {
                js.set_string("response_information", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::SERVER_REFERENCE(v) => {
                js.set_string("server_reference", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::REASON_STRING(v) => {
                js.set_string("reason_string", v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::RECEIVE_MAXIMUM(v) => {
                js.set_uint("receive_maximum", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::TOPIC_ALIAS_MAXIMUM(v) => {
                js.set_uint("topic_alias_maximum", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::TOPIC_ALIAS(v) => {
                js.set_uint("topic_alias", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::MAXIMUM_QOS(v) => {
                js.set_uint("maximum_qos", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::RETAIN_AVAILABLE(v) => {
                js.set_uint("retain_available", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::USER_PROPERTY((k, v)) => {
                js.set_string(k, v)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::MAXIMUM_PACKET_SIZE(v) => {
                js.set_uint("maximum_packet_size", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::WILDCARD_SUBSCRIPTION_AVAILABLE(v) => {
                js.set_uint("wildcard_subscription_available", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::SUBSCRIPTION_IDENTIFIER_AVAILABLE(v) => {
                js.set_uint("subscription_identifier_available", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::SHARED_SUBSCRIPTION_AVAILABLE(v) => {
                js.set_uint("shared_subscription_available", *v as u64)?;
            }
            crate::mqtt::mqtt_property::MQTTProperty::UNKNOWN => {
                // pass
            }
        }
        Ok(())
    }
}

#[inline]
pub fn parse_qualified_property(input: &[u8], identifier: u32) -> IResult<&[u8], MQTTProperty> {
    match identifier {
        1 => match be_u8(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::PAYLOAD_FORMAT_INDICATOR(val))),
            Err(e) => Err(e),
        },
        2 => match be_u32(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::MESSAGE_EXPIRY_INTERVAL(val))),
            Err(e) => Err(e),
        },
        3 => match parse_mqtt_string(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::CONTENT_TYPE(val))),
            Err(e) => Err(e),
        },
        8 => match parse_mqtt_string(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::RESPONSE_TOPIC(val))),
            Err(e) => Err(e),
        },
        9 => match parse_mqtt_binary_data(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::CORRELATION_DATA(val))),
            Err(e) => Err(e),
        },
        11 => match parse_mqtt_variable_integer(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::SUBSCRIPTION_IDENTIFIER(val))),
            Err(e) => Err(e),
        },
        17 => match be_u32(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::SESSION_EXPIRY_INTERVAL(val))),
            Err(e) => Err(e),
        },
        18 => match parse_mqtt_string(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::ASSIGNED_CLIENT_IDENTIFIER(val))),
            Err(e) => Err(e),
        },
        19 => match be_u16(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::SERVER_KEEP_ALIVE(val))),
            Err(e) => Err(e),
        },
        21 => match parse_mqtt_string(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::AUTHENTICATION_METHOD(val))),
            Err(e) => Err(e),
        },
        22 => match parse_mqtt_binary_data(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::AUTHENTICATION_DATA(val))),
            Err(e) => Err(e),
        },
        23 => match be_u8(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::REQUEST_PROBLEM_INFORMATION(val))),
            Err(e) => Err(e),
        },
        24 => match be_u32(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::WILL_DELAY_INTERVAL(val))),
            Err(e) => Err(e),
        },
        25 => match be_u8(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::REQUEST_RESPONSE_INFORMATION(val))),
            Err(e) => Err(e),
        },
        26 => match parse_mqtt_string(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::RESPONSE_INFORMATION(val))),
            Err(e) => Err(e),
        },
        28 => match parse_mqtt_string(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::SERVER_REFERENCE(val))),
            Err(e) => Err(e),
        },
        31 => match parse_mqtt_string(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::REASON_STRING(val))),
            Err(e) => Err(e),
        },
        33 => match be_u16(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::RECEIVE_MAXIMUM(val))),
            Err(e) => Err(e),
        },
        34 => match be_u16(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::TOPIC_ALIAS_MAXIMUM(val))),
            Err(e) => Err(e),
        },
        35 => match be_u16(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::TOPIC_ALIAS(val))),
            Err(e) => Err(e),
        },
        36 => match be_u8(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::MAXIMUM_QOS(val))),
            Err(e) => Err(e),
        },
        37 => match be_u8(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::RETAIN_AVAILABLE(val))),
            Err(e) => Err(e),
        },
        38 => match parse_mqtt_string_pair(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::USER_PROPERTY(val))),
            Err(e) => Err(e),
        },
        39 => match be_u32(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::MAXIMUM_PACKET_SIZE(val))),
            Err(e) => Err(e),
        },
        40 => match be_u8(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::WILDCARD_SUBSCRIPTION_AVAILABLE(val))),
            Err(e) => Err(e),
        },
        41 => match be_u8(input) {
            Ok((rem, val)) => {
                Ok((rem, MQTTProperty::SUBSCRIPTION_IDENTIFIER_AVAILABLE(val)))
            }
            Err(e) => Err(e),
        },
        42 => match be_u8(input) {
            Ok((rem, val)) => Ok((rem, MQTTProperty::SHARED_SUBSCRIPTION_AVAILABLE(val))),
            Err(e) => Err(e),
        },
        _ => {
            Ok((input, MQTTProperty::UNKNOWN))
        }
    }
}
