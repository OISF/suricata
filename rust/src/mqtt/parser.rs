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

use crate::mqtt::mqtt_message::*;
use crate::mqtt::mqtt_property::*;
use nom::combinator::rest;
use nom::number::streaming::*;
use nom::*;
use std::str;

#[derive(Debug)]
pub struct FixedHeader {
    pub message_type: u8,
    pub dup_flag: bool,
    pub qos_level: u8,
    pub retain: bool,
    pub remaining_length: u32,
}

// PARSING HELPERS

#[inline]
fn is_continuation_bit_set(b: u8) -> bool {
    return (b & 128) != 0;
}

#[inline]
fn convert_varint(continued: Vec<u8>, last: u8) -> u32 {
    let mut multiplier = 1u32;
    let mut value = 0u32;
    for val in &continued {
        value = value + ((val & 127) as u32 * multiplier);
        multiplier = multiplier * 128u32;
    }
    value = value + ((last & 127) as u32 * multiplier);
    return value;
}

#[inline]
fn varint_length(val: usize) -> usize {
  match val {
      0 ..= 127 => 1,
      128 ..= 16383 => 2,
      16384 ..= 2097151 => 3,
      2097152 ..= 268435455 => 4,
      _ => 0,
  }
}

// DATA TYPES

named!(#[inline], pub parse_mqtt_string<String>,
       do_parse!(
           length: be_u16
           >> content: take!(length)
           >>  (
                 str::from_utf8(&content).unwrap_or("NON-UTF8").to_string()
               )
       ));

named!(#[inline], pub parse_mqtt_variable_integer<u32>,
       do_parse!(
           continued_part: take_while!(is_continuation_bit_set)
           >> non_continued_part: be_u8
           >>  (
                 convert_varint(continued_part.to_vec(), non_continued_part)
               )
       ));

named!(#[inline], pub parse_mqtt_binary_data<Vec<u8>>,
       do_parse!(
           length: be_u16
           >> data: take!(length)
           >>  (
                 data.to_vec()
               )
       ));

named!(#[inline], pub parse_mqtt_string_pair<(String, String)>,
       do_parse!(
           name: parse_mqtt_string
           >> value: parse_mqtt_string
           >>  (
                 (name, value)
               )
       ));

// MESSAGE COMPONENTS

named!(#[inline], pub parse_property<MQTTProperty>,
       do_parse!(
           identifier: parse_mqtt_variable_integer
           >> value: call!(parse_qualified_property, identifier)
           >>  (
                 value
               )
       ));

#[inline]
fn parse_properties(input: &[u8], precond: bool) -> IResult<&[u8], Option<Vec<MQTTProperty>>> {
    // do not try to parse anything when precondition is not met
    if !precond {
        return Ok((input, None));
    }
    // parse properties length
    match parse_mqtt_variable_integer(input) {
        Ok((rem, mut proplen)) => {
            if proplen == 0 {
                // no properties
                return Ok((rem, None));
            }
            // parse properties
            let mut props = Vec::<MQTTProperty>::new();
            let mut newrem = rem;
            while proplen > 0 {
                match parse_property(newrem) {
                    Ok((rem, val)) => {
                        props.push(val);
                        let curparselen = (newrem.len() - rem.len()) as u32;
                        proplen -= curparselen;
                        newrem = &rem;
                    }
                    Err(e) => return Err(e),
                }
            }
            return Ok((newrem, Some(props)));
        }
        Err(e) => return Err(e),
    }
}

#[inline]
fn parse_fixed_header_flags(i: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8)> {
    bits!(
        i,
        tuple!(
            take_bits!(4u8),
            take_bits!(1u8),
            take_bits!(2u8),
            take_bits!(1u8)
        )
    )
}

named!(#[inline], pub parse_fixed_header<FixedHeader>,
       do_parse!(
           flags: parse_fixed_header_flags
           >> remaining_length: parse_mqtt_variable_integer
           >>  (
                 FixedHeader {
                   message_type: flags.0 as u8,
                   dup_flag: flags.1 != 0,
                   qos_level: flags.2 as u8,
                   retain: flags.3 != 0,
                   remaining_length: remaining_length,
                 }
               )
       ));

#[inline]
fn parse_connect_variable_flags(i: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8, u8, u8, u8)> {
    bits!(
        i,
        tuple!(
            take_bits!(1u8),
            take_bits!(1u8),
            take_bits!(1u8),
            take_bits!(2u8),
            take_bits!(1u8),
            take_bits!(1u8),
            take_bits!(1u8)
        )
    )
}

named!(#[inline], pub parse_connect<MQTTConnectData>,
       do_parse!(
           protocol_string: parse_mqtt_string
           >> protocol_version: be_u8
           >> flags: parse_connect_variable_flags
           >> keepalive: be_u16
           >> properties: call!(parse_properties, protocol_version == 5)
           >> client_id: parse_mqtt_string
           >> will_properties: call!(parse_properties, protocol_version == 5 && flags.4 != 0)
           >> will_topic: cond!(flags.4 != 0, parse_mqtt_string)
           >> will_message: cond!(flags.4 != 0, parse_mqtt_binary_data)
           >> username: cond!(flags.0 != 0, parse_mqtt_string)
           >> password: cond!(flags.1 != 0, parse_mqtt_binary_data)
           >>  (
                 MQTTConnectData {
                   protocol_string: protocol_string,
                   protocol_version: protocol_version,
                   username_flag: flags.0 != 0,
                   password_flag: flags.1 != 0,
                   will_retain: flags.2 != 0,
                   will_qos: flags.3 as u8,
                   will_flag: flags.4  != 0,
                   clean_session: flags.5 != 0,
                   keepalive: keepalive,
                   client_id: client_id,
                   will_topic: will_topic,
                   will_message: will_message,
                   username: username,
                   password: password,
                   properties: properties,
                   will_properties: will_properties,
                 }
               )
       ));

named_args!(pub parse_connack(protocol_version: u8)<MQTTConnackData>,
       do_parse!(
           topic_name_compression_response: be_u8
           >> retcode: be_u8
           >> properties: call!(parse_properties, protocol_version == 5)
           >>  (
                 MQTTConnackData {
                   session_present: (topic_name_compression_response & 1) != 0,
                   return_code: retcode,
                   properties: properties,
                 }
               )
       ));

named_args!(pub parse_publish(protocol_version: u8, has_id: bool)<MQTTPublishData>,
       do_parse!(
           topic: parse_mqtt_string
           >> message_id: cond!(has_id, be_u16)
           >> properties: call!(parse_properties, protocol_version == 5)
           >> message: rest
           >>  (
                 MQTTPublishData {
                   topic: topic,
                   message_id: message_id,
                   message: message.to_vec(),
                   properties: properties,
                 }
               )
       ));

#[inline]
fn parse_msgidonly(
    input: &[u8],
    mut remaining_len: usize,
    protocol_version: u8,
) -> IResult<&[u8], MQTTMessageIdOnly> {
    if protocol_version < 5 {
        // before v5 we don't even have to care about reason codes
        // and properties, lucky us
        return parse_msgidonly_v3(input);
    }
    match be_u16(input) {
        Ok((rem, message_id)) => {
            remaining_len -= 2;
            if remaining_len == 0 {
                // from the spec: " The Reason Code and Property Length can be
                // omitted if the Reason Code is 0x00 (Success) and there are
                // no Properties. In this case the message has a Remaining
                // Length of 2."
                return Ok((
                    rem,
                    MQTTMessageIdOnly {
                        message_id: message_id,
                        reason_code: Some(0),
                        properties: None,
                    },
                ));
            }
            match be_u8(rem) {
                Ok((rem, reason_code)) => {
                    remaining_len -= 1;
                    if remaining_len == 0 {
                        // no properties
                        return Ok((
                            rem,
                            MQTTMessageIdOnly {
                                message_id: message_id,
                                reason_code: Some(reason_code),
                                properties: None,
                            },
                        ));
                    }
                    match parse_properties(rem, true) {
                        Ok((rem, properties)) => {
                            return Ok((
                                rem,
                                MQTTMessageIdOnly {
                                    message_id: message_id,
                                    reason_code: Some(reason_code),
                                    properties: properties,
                                },
                            ));
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }
}

named!(#[inline], pub parse_msgidonly_v3<MQTTMessageIdOnly>,
       do_parse!(
           message_id: be_u16
           >>  (
                 MQTTMessageIdOnly {
                   message_id: message_id,
                   reason_code: None,
                   properties: None,
                 }
               )
       ));

named!(#[inline], pub parse_subscribe_topic<MQTTSubscribeTopicData>,
       do_parse!(
           topic: parse_mqtt_string
           >> qos: be_u8
           >>  (
                 MQTTSubscribeTopicData {
                   topic_name: topic,
                   qos: qos,
                 }
               )
       ));

named_args!(pub parse_subscribe(protocol_version: u8)<MQTTSubscribeData>,
       do_parse!(
           message_id: be_u16
           >> properties: call!(parse_properties, protocol_version == 5)
           >> topics: many1!(complete!(parse_subscribe_topic))
           >>  (
                 MQTTSubscribeData {
                   message_id: message_id,
                   topics: topics,
                   properties: properties,
                 }
               )
       ));

named_args!(pub parse_suback(protocol_version: u8)<MQTTSubackData>,
       do_parse!(
           message_id: be_u16
           >> properties: call!(parse_properties, protocol_version == 5)
           >> qoss: rest
           >>  (
                 MQTTSubackData {
                   message_id: message_id,
                   qoss: qoss.to_vec(),
                   properties: properties,
                 }
               )
       ));

named_args!(pub parse_unsubscribe(protocol_version: u8)<MQTTUnsubscribeData>,
       do_parse!(
           message_id: be_u16
           >> properties: call!(parse_properties, protocol_version == 5)
           >> topics: many0!(complete!(parse_mqtt_string))
           >>  (
                 MQTTUnsubscribeData {
                   message_id: message_id,
                   topics: topics,
                   properties: properties,
                 }
               )
       ));

named_args!(pub parse_unsuback(protocol_version: u8)<MQTTUnsubackData>,
       do_parse!(
           message_id: be_u16
           >> properties: call!(parse_properties, protocol_version == 5)
           >> reason_codes: many0!(complete!(be_u8))
           >>  (
                 MQTTUnsubackData {
                   message_id: message_id,
                   properties: properties,
                   reason_codes: Some(reason_codes),
                 }
               )
       ));

#[inline]
fn parse_disconnect(
    input: &[u8],
    mut remaining_len: usize,
    protocol_version: u8,
) -> IResult<&[u8], MQTTDisconnectData> {
    if protocol_version < 5 {
        return Ok((
            input,
            MQTTDisconnectData {
                reason_code: None,
                properties: None,
            },
        ));
    }
    if remaining_len == 0 {
        // The Reason Code and Property Length can be omitted if the Reason
        // Code is 0x00 (Normal disconnection) and there are no Properties.
        // In this case the DISCONNECT has a Remaining Length of 0.
        return Ok((
            input,
            MQTTDisconnectData {
                reason_code: Some(0),
                properties: None,
            },
        ));
    }
    match be_u8(input) {
        Ok((rem, reason_code)) => {
            remaining_len -= 1;
            if remaining_len == 0 {
                // no properties
                return Ok((
                    rem,
                    MQTTDisconnectData {
                        reason_code: Some(0),
                        properties: None,
                    },
                ));
            }
            match parse_properties(rem, true) {
                Ok((rem, properties)) => {
                    return Ok((
                        rem,
                        MQTTDisconnectData {
                            reason_code: Some(reason_code),
                            properties: properties,
                        },
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }
}

named!(#[inline], pub parse_auth<MQTTAuthData>,
       do_parse!(
           reason_code: be_u8
           >> properties: call!(parse_properties, true)
           >>  (
                 MQTTAuthData {
                   reason_code: reason_code,
                   properties: properties,
                 }
               )
       ));

pub fn parse_message(input: &[u8], protocol_version: u8) -> IResult<&[u8], MQTTMessage> {
    // Parse the fixed header first. This is identical across versions and can
    // be between 2 and 5 bytes long.
    match parse_fixed_header(input) {
        Ok((fullrem, header)) => {
            let len = header.remaining_length as usize;
            // This is the length of the fixed header that we need to skip
            // before returning the remainder. It is the sum of the length
            // of the flag byte (1) and the length of the message length
            // varint.
            let skiplen = 1 + varint_length(len);
            let message_type = header.message_type;
            if fullrem.len() < len {
                return Err(Err::Incomplete(Needed::Size(len - fullrem.len())));
            }
            // We reslice the remainder into the portion that we are interested
            // in, according to the length we just parsed. This helps with the
            // complete! parsers, where we would otherwise need to keep track
            // of the already parsed length.
            let rem = &fullrem[..len];
            match message_type {
                1 => match parse_connect(rem) {
                    Ok((_rem, conn)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::CONNECT(conn),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                2 => match parse_connack(rem, protocol_version) {
                    Ok((_rem, connack)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::CONNACK(connack),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                3 => match parse_publish(rem, protocol_version, header.qos_level > 0) {
                    Ok((_rem, publish)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::PUBLISH(publish),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                4..=7 => {
                    match parse_msgidonly(rem, len, protocol_version) {
                        Ok((_rem, msgidonly)) => {
                            let msg = MQTTMessage {
                                header: header,
                                op: match message_type {
                                    4 => MQTTOperation::PUBACK(msgidonly),
                                    5 => MQTTOperation::PUBREC(msgidonly),
                                    6 => MQTTOperation::PUBREL(msgidonly),
                                    7 => MQTTOperation::PUBCOMP(msgidonly),
                                    _ => MQTTOperation::UNASSIGNED,
                                },
                            };
                            Ok((&input[skiplen+len..], msg))
                        }
                        Err(e) => Err(e),
                    }
                }
                8 => match parse_subscribe(rem, protocol_version) {
                    Ok((_rem, subs)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::SUBSCRIBE(subs),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                9 => match parse_suback(rem, protocol_version) {
                    Ok((_rem, suback)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::SUBACK(suback),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                10 => match parse_unsubscribe(rem, protocol_version) {
                    Ok((_rem, unsub)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::UNSUBSCRIBE(unsub),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                11 => match parse_unsuback(rem, protocol_version) {
                    Ok((_rem, unsuback)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::UNSUBACK(unsuback),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                12..=13 => {
                    let msg = MQTTMessage {
                        header: header,
                        op: match message_type {
                            12 => MQTTOperation::PINGREQ,
                            13 => MQTTOperation::PINGRESP,
                            _ => MQTTOperation::UNASSIGNED,
                        },
                    };
                    if len > rem.len() {
                        return Err(Err::Incomplete(Needed::Size(len - rem.len())));
                    }
                    return Ok((&rem[len..], msg));
                }
                14 => match parse_disconnect(rem, len, protocol_version) {
                    Ok((_rem, disco)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::DISCONNECT(disco),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                15 => match parse_auth(rem) {
                    Ok((_rem, auth)) => {
                        let msg = MQTTMessage {
                            header: header,
                            op: MQTTOperation::AUTH(auth),
                        };
                        Ok((&input[skiplen+len..], msg))
                    }
                    Err(e) => Err(e),
                },
                // Unassigned message type code. Unlikely to happen with
                // regular traffic, might be an indication for broken or
                // crafted MQTT traffic.
                _ => {
                    let msg = MQTTMessage {
                        header: header,
                        op: MQTTOperation::UNASSIGNED,
                    };
                    if len > rem.len() {
                        return Err(Err::Incomplete(Needed::Size(len - rem.len())));
                    }
                    return Ok((&rem[len..], msg));
                }
            }
        }
        Err(err) => {
            return Err(err);
        }
    }
}
