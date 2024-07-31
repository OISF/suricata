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

use crate::common::nom7::bits;
use crate::mqtt::mqtt_message::*;
use crate::mqtt::mqtt_property::*;
use nom7::bits::streaming::take as take_bits;
use nom7::bytes::complete::take;
use nom7::bytes::streaming::take_while_m_n;
use nom7::combinator::{complete, cond, verify};
use nom7::multi::{length_data, many0, many1};
use nom7::number::streaming::*;
use nom7::sequence::tuple;
use nom7::{Err, IResult, Needed};
use num_traits::FromPrimitive;

#[derive(Copy, Clone, Debug)]
pub struct FixedHeader {
    pub message_type: MQTTTypeCode,
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
        value += (val & 127) as u32 * multiplier;
        multiplier *= 128u32;
    }
    value += (last & 127) as u32 * multiplier;
    return value;
}

// DATA TYPES

#[inline]
pub fn parse_mqtt_string(i: &[u8]) -> IResult<&[u8], String> {
    let (i, content) = length_data(be_u16)(i)?;
    Ok((i, String::from_utf8_lossy(content).to_string()))
}

#[inline]
pub fn parse_mqtt_variable_integer(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, continued_part) = take_while_m_n(0, 3, is_continuation_bit_set)(i)?;
    let (i, non_continued_part) = verify(be_u8, |&val| !is_continuation_bit_set(val))(i)?;
    Ok((
        i,
        convert_varint(continued_part.to_vec(), non_continued_part),
    ))
}

#[inline]
pub fn parse_mqtt_binary_data(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (i, data) = length_data(be_u16)(i)?;
    Ok((i, data.to_vec()))
}

#[inline]
pub fn parse_mqtt_string_pair(i: &[u8]) -> IResult<&[u8], (String, String)> {
    let (i, name) = parse_mqtt_string(i)?;
    let (i, value) = parse_mqtt_string(i)?;
    Ok((i, (name, value)))
}

// MESSAGE COMPONENTS

#[inline]
fn parse_property(i: &[u8]) -> IResult<&[u8], MQTTProperty> {
    let (i, identifier) = parse_mqtt_variable_integer(i)?;
    let (i, value) = parse_qualified_property(i, identifier)?;
    Ok((i, value))
}

#[inline]
fn parse_properties(input: &[u8], precond: bool) -> IResult<&[u8], Option<Vec<MQTTProperty>>> {
    // do not try to parse anything when precondition is not met
    if !precond {
        return Ok((input, None));
    }
    // parse properties length
    match parse_mqtt_variable_integer(input) {
        Ok((rem, proplen)) => {
            if proplen == 0 {
                // no properties
                return Ok((rem, None));
            }
            // parse properties
            let mut props = Vec::<MQTTProperty>::new();
            let (rem, mut newrem) = take(proplen as usize)(rem)?;
            while !newrem.is_empty() {
                match parse_property(newrem) {
                    Ok((rem2, val)) => {
                        props.push(val);
                        newrem = rem2;
                    }
                    Err(e) => return Err(e),
                }
            }
            return Ok((rem, Some(props)));
        }
        Err(e) => return Err(e),
    }
}

#[inline]
fn parse_fixed_header_flags(i: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8)> {
    bits(tuple((
        take_bits(4u8),
        take_bits(1u8),
        take_bits(2u8),
        take_bits(1u8),
    )))(i)
}

#[inline]
fn parse_message_type(code: u8) -> MQTTTypeCode {
    match code {
        0..=15 => {
            if let Some(t) = FromPrimitive::from_u8(code) {
                return t;
            } else {
                return MQTTTypeCode::UNASSIGNED;
            }
        }
        _ => {
            // unreachable state in parser: we only pass values parsed from take_bits!(4u8)
            debug_validate_fail!("can't have message codes >15 from 4 bits");
            MQTTTypeCode::UNASSIGNED
        }
    }
}

#[inline]
pub fn parse_fixed_header(i: &[u8]) -> IResult<&[u8], FixedHeader> {
    let (i, flags) = parse_fixed_header_flags(i)?;
    let (i, remaining_length) = parse_mqtt_variable_integer(i)?;
    Ok((
        i,
        FixedHeader {
            message_type: parse_message_type(flags.0),
            dup_flag: flags.1 != 0,
            qos_level: flags.2,
            retain: flags.3 != 0,
            remaining_length,
        },
    ))
}

#[inline]
fn parse_connect(i: &[u8]) -> IResult<&[u8], MQTTConnectData> {
    let (i, protocol_string) = parse_mqtt_string(i)?;
    let (i, protocol_version) = be_u8(i)?;
    let (i, rawflags) = be_u8(i)?;
    let (i, keepalive) = be_u16(i)?;
    let (i, properties) = parse_properties(i, protocol_version == 5)?;
    let (i, client_id) = parse_mqtt_string(i)?;
    let (i, will_properties) = parse_properties(i, protocol_version == 5 && rawflags & 0x4 != 0)?;
    let (i, will_topic) = cond(rawflags & 0x4 != 0, parse_mqtt_string)(i)?;
    let (i, will_message) = cond(rawflags & 0x4 != 0, parse_mqtt_binary_data)(i)?;
    let (i, username) = cond(rawflags & 0x80 != 0, parse_mqtt_string)(i)?;
    let (i, password) = cond(rawflags & 0x40 != 0, parse_mqtt_binary_data)(i)?;
    Ok((
        i,
        MQTTConnectData {
            protocol_string,
            protocol_version,
            rawflags,
            username_flag: rawflags & 0x80 != 0,
            password_flag: rawflags & 0x40 != 0,
            will_retain: rawflags & 0x20 != 0,
            will_qos: (rawflags & 0x18) >> 3,
            will_flag: rawflags & 0x4 != 0,
            clean_session: rawflags & 0x2 != 0,
            keepalive,
            client_id,
            will_topic,
            will_message,
            username,
            password,
            properties,
            will_properties,
        },
    ))
}

#[inline]
fn parse_connack(protocol_version: u8) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTConnackData> {
    move |i: &[u8]| {
        let (i, topic_name_compression_response) = be_u8(i)?;
        let (i, return_code) = be_u8(i)?;
        let (i, properties) = parse_properties(i, protocol_version == 5)?;
        Ok((
            i,
            MQTTConnackData {
                session_present: (topic_name_compression_response & 1) != 0,
                return_code,
                properties,
            },
        ))
    }
}

#[inline]
fn parse_publish(
    protocol_version: u8, has_id: bool,
) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTPublishData> {
    move |i: &[u8]| {
        let (i, topic) = parse_mqtt_string(i)?;
        let (i, message_id) = cond(has_id, be_u16)(i)?;
        let (message, properties) = parse_properties(i, protocol_version == 5)?;
        Ok((
            i,
            MQTTPublishData {
                topic,
                message_id,
                message: message.to_vec(),
                properties,
            },
        ))
    }
}

#[inline]
fn parse_msgidonly(protocol_version: u8) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTMessageIdOnly> {
    move |input: &[u8]| {
        if protocol_version < 5 {
            // before v5 we don't even have to care about reason codes
            // and properties, lucky us
            return parse_msgidonly_v3(input);
        }
        let remaining_len = input.len();
        match be_u16(input) {
            Ok((rem, message_id)) => {
                if remaining_len == 2 {
                    // from the spec: " The Reason Code and Property Length can be
                    // omitted if the Reason Code is 0x00 (Success) and there are
                    // no Properties. In this case the message has a Remaining
                    // Length of 2."
                    return Ok((
                        rem,
                        MQTTMessageIdOnly {
                            message_id,
                            reason_code: Some(0),
                            properties: None,
                        },
                    ));
                }
                match be_u8(rem) {
                    Ok((rem, reason_code)) => {
                        // We are checking for 3 because in that case we have a
                        // header plus reason code, but no properties.
                        if remaining_len == 3 {
                            // no properties
                            return Ok((
                                rem,
                                MQTTMessageIdOnly {
                                    message_id,
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
                                        message_id,
                                        reason_code: Some(reason_code),
                                        properties,
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
}

#[inline]
fn parse_msgidonly_v3(i: &[u8]) -> IResult<&[u8], MQTTMessageIdOnly> {
    let (i, message_id) = be_u16(i)?;
    Ok((
        i,
        MQTTMessageIdOnly {
            message_id,
            reason_code: None,
            properties: None,
        },
    ))
}

#[inline]
fn parse_subscribe_topic(i: &[u8]) -> IResult<&[u8], MQTTSubscribeTopicData> {
    let (i, topic_name) = parse_mqtt_string(i)?;
    let (i, qos) = be_u8(i)?;
    Ok((i, MQTTSubscribeTopicData { topic_name, qos }))
}

#[inline]
fn parse_subscribe(protocol_version: u8) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTSubscribeData> {
    move |i: &[u8]| {
        let (i, message_id) = be_u16(i)?;
        let (i, properties) = parse_properties(i, protocol_version == 5)?;
        let (i, topics) = many1(complete(parse_subscribe_topic))(i)?;
        Ok((
            i,
            MQTTSubscribeData {
                message_id,
                topics,
                properties,
            },
        ))
    }
}

#[inline]
fn parse_suback(protocol_version: u8) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTSubackData> {
    move |i: &[u8]| {
        let (i, message_id) = be_u16(i)?;
        let (qoss, properties) = parse_properties(i, protocol_version == 5)?;
        Ok((
            i,
            MQTTSubackData {
                message_id,
                qoss: qoss.to_vec(),
                properties,
            },
        ))
    }
}

#[inline]
fn parse_unsubscribe(
    protocol_version: u8,
) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTUnsubscribeData> {
    move |i: &[u8]| {
        let (i, message_id) = be_u16(i)?;
        let (i, properties) = parse_properties(i, protocol_version == 5)?;
        let (i, topics) = many0(complete(parse_mqtt_string))(i)?;
        Ok((
            i,
            MQTTUnsubscribeData {
                message_id,
                topics,
                properties,
            },
        ))
    }
}

#[inline]
fn parse_unsuback(protocol_version: u8) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTUnsubackData> {
    move |i: &[u8]| {
        let (i, message_id) = be_u16(i)?;
        let (i, properties) = parse_properties(i, protocol_version == 5)?;
        let (i, reason_codes) = many0(complete(be_u8))(i)?;
        Ok((
            i,
            MQTTUnsubackData {
                message_id,
                properties,
                reason_codes: Some(reason_codes),
            },
        ))
    }
}

#[inline]
fn parse_disconnect(
    remaining_len: usize, protocol_version: u8,
) -> impl Fn(&[u8]) -> IResult<&[u8], MQTTDisconnectData> {
    move |input: &[u8]| {
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
                // We are checking for 1 because in that case we have a
                // header plus reason code, but no properties.
                if remaining_len == 1 {
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
                                properties,
                            },
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }
}

#[inline]
fn parse_auth(i: &[u8]) -> IResult<&[u8], MQTTAuthData> {
    let (i, reason_code) = be_u8(i)?;
    let (i, properties) = parse_properties(i, true)?;
    Ok((
        i,
        MQTTAuthData {
            reason_code,
            properties,
        },
    ))
}

#[inline]
fn parse_remaining_message<'a>(
    full: &'a [u8], len: usize, skiplen: usize, header: FixedHeader, message_type: MQTTTypeCode,
    protocol_version: u8,
) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], MQTTMessage> {
    move |input: &'a [u8]| {
        match message_type {
            MQTTTypeCode::CONNECT => match parse_connect(input) {
                Ok((_rem, conn)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::CONNECT(conn),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::CONNACK => match parse_connack(protocol_version)(input) {
                Ok((_rem, connack)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::CONNACK(connack),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::PUBLISH => {
                match parse_publish(protocol_version, header.qos_level > 0)(input) {
                    Ok((_rem, publish)) => {
                        let msg = MQTTMessage {
                            header,
                            op: MQTTOperation::PUBLISH(publish),
                        };
                        Ok((&full[skiplen + len..], msg))
                    }
                    Err(e) => Err(e),
                }
            }
            MQTTTypeCode::PUBACK
            | MQTTTypeCode::PUBREC
            | MQTTTypeCode::PUBREL
            | MQTTTypeCode::PUBCOMP => match parse_msgidonly(protocol_version)(input) {
                Ok((_rem, msgidonly)) => {
                    let msg = MQTTMessage {
                        header,
                        op: match message_type {
                            MQTTTypeCode::PUBACK => MQTTOperation::PUBACK(msgidonly),
                            MQTTTypeCode::PUBREC => MQTTOperation::PUBREC(msgidonly),
                            MQTTTypeCode::PUBREL => MQTTOperation::PUBREL(msgidonly),
                            MQTTTypeCode::PUBCOMP => MQTTOperation::PUBCOMP(msgidonly),
                            _ => MQTTOperation::UNASSIGNED,
                        },
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::SUBSCRIBE => match parse_subscribe(protocol_version)(input) {
                Ok((_rem, subs)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::SUBSCRIBE(subs),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::SUBACK => match parse_suback(protocol_version)(input) {
                Ok((_rem, suback)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::SUBACK(suback),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::UNSUBSCRIBE => match parse_unsubscribe(protocol_version)(input) {
                Ok((_rem, unsub)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::UNSUBSCRIBE(unsub),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::UNSUBACK => match parse_unsuback(protocol_version)(input) {
                Ok((_rem, unsuback)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::UNSUBACK(unsuback),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::PINGREQ | MQTTTypeCode::PINGRESP => {
                let msg = MQTTMessage {
                    header,
                    op: match message_type {
                        MQTTTypeCode::PINGREQ => MQTTOperation::PINGREQ,
                        MQTTTypeCode::PINGRESP => MQTTOperation::PINGRESP,
                        _ => MQTTOperation::UNASSIGNED,
                    },
                };
                Ok((&full[skiplen + len..], msg))
            }
            MQTTTypeCode::DISCONNECT => match parse_disconnect(len, protocol_version)(input) {
                Ok((_rem, disco)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::DISCONNECT(disco),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            MQTTTypeCode::AUTH => match parse_auth(input) {
                Ok((_rem, auth)) => {
                    let msg = MQTTMessage {
                        header,
                        op: MQTTOperation::AUTH(auth),
                    };
                    Ok((&full[skiplen + len..], msg))
                }
                Err(e) => Err(e),
            },
            // Unassigned message type code. Unlikely to happen with
            // regular traffic, might be an indication for broken or
            // crafted MQTT traffic.
            _ => {
                let msg = MQTTMessage {
                    header,
                    op: MQTTOperation::UNASSIGNED,
                };
                return Ok((&full[skiplen + len..], msg));
            }
        }
    }
}

pub fn parse_message(
    input: &[u8], protocol_version: u8, max_msg_size: u32,
) -> IResult<&[u8], MQTTMessage> {
    // Parse the fixed header first. This is identical across versions and can
    // be between 2 and 5 bytes long.
    match parse_fixed_header(input) {
        Ok((fullrem, header)) => {
            let len = header.remaining_length as usize;
            // This is the length of the fixed header that we need to skip
            // before returning the remainder. It is the sum of the length
            // of the flag byte (1) and the length of the message length
            // varint.
            let skiplen = input.len() - fullrem.len();
            let message_type = header.message_type;

            // If the remaining length (message length) exceeds the specified
            // limit, we return a special truncation message type, containing
            // no parsed metadata but just the skipped length and the message
            // type.
            if len > max_msg_size as usize {
                let msg = MQTTMessage {
                    header,
                    op: MQTTOperation::TRUNCATED(MQTTTruncatedData {
                        original_message_type: message_type,
                        skipped_length: len + skiplen,
                    }),
                };
                // In this case we return the full input buffer, since this is
                // what the skipped_length value also refers to: header _and_
                // remaining length.
                return Ok((input, msg));
            }

            // We have not exceeded the maximum length limit, but still do not
            // have enough data in the input buffer to handle the full
            // message. Signal this by returning an Incomplete IResult value.
            if fullrem.len() < len {
                return Err(Err::Incomplete(Needed::new(len - fullrem.len())));
            }

            // Parse the contents of the buffer into a single message.
            // We reslice the remainder into the portion that we are interested
            // in, according to the length we just parsed. This helps with the
            // complete() parsers, where we would otherwise need to keep track
            // of the already parsed length.
            let rem = &fullrem[..len];

            // Parse remaining message in buffer. We use complete() to ensure
            // we do not request additional content in case of incomplete
            // parsing, but raise an error instead as we should have all the
            // data asked for in the header.
            return complete(parse_remaining_message(
                input,
                len,
                skiplen,
                header,
                message_type,
                protocol_version,
            ))(rem);
        }
        Err(err) => {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom7::error::ErrorKind;

    fn test_mqtt_parse_variable_fail(buf0: &[u8]) {
        let r0 = parse_mqtt_variable_integer(buf0);
        match r0 {
            Ok((_, _)) => {
                panic!("Result should not have been ok.");
            }
            Err(Err::Error(err)) => {
                assert_eq!(err.code, ErrorKind::Verify);
            }
            _ => {
                panic!("Result should be an error.");
            }
        }
    }

    fn test_mqtt_parse_variable_check(buf0: &[u8], expected: u32) {
        let r0 = parse_mqtt_variable_integer(buf0);
        match r0 {
            Ok((_, val)) => {
                assert_eq!(val, expected);
            }
            Err(_) => {
                panic!("Result should have been ok.");
            }
        }
    }

    #[test]
    fn test_mqtt_parse_variable_integer_largest_input() {
        test_mqtt_parse_variable_fail(&[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_mqtt_parse_variable_integer_boundary() {
        test_mqtt_parse_variable_fail(&[0xFF, 0xFF, 0xFF, 0x80]);
    }

    #[test]
    fn test_mqtt_parse_variable_integer_largest_valid() {
        test_mqtt_parse_variable_check(&[0xFF, 0xFF, 0xFF, 0x7F], 268435455);
    }

    #[test]
    fn test_mqtt_parse_variable_integer_smallest_valid() {
        test_mqtt_parse_variable_check(&[0x0], 0);
    }

    #[test]
    fn test_parse_fixed_header() {
        let buf = [
            0x30, /* Header Flags: 0x30, Message Type: Publish Message, QoS Level: At most once delivery (Fire and Forget) */
            0xb7, 0x97, 0x02, /* Msg Len: 35767 */
            0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0xa0,
        ];

        let result = parse_fixed_header(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message.message_type, MQTTTypeCode::PUBLISH);
                assert!(!message.dup_flag);
                assert_eq!(message.qos_level, 0);
                assert!(!message.retain);
                assert_eq!(message.remaining_length, 35767);
                assert_eq!(remainder.len(), 17);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_properties() {
        let buf = [
            0x03, 0x21, 0x00, 0x14, /* Properties */
            0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0xa0,
        ];

        let result = parse_properties(&buf, true);
        match result {
            Ok((remainder, message)) => {
                let res = message.unwrap();
                assert_eq!(res[0], MQTTProperty::RECEIVE_MAXIMUM(20));
                assert_eq!(remainder.len(), 17);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
    #[test]
    fn test_parse_connect() {
        let buf = [
            0x00, 0x04, /* Protocol Name Length: 4 */
            0x4d, 0x51, 0x54, 0x54, /* Protocol Name: MQTT */
            0x05, /* Version: MQTT v5.0 (5) */
            0xc2, /*Connect Flags: 0xc2, User Name Flag, Password Flag, QoS Level: At most once delivery (Fire and Forget), Clean Session Flag */
            0x00, 0x3c, /* Keep Alive: 60 */
            0x03, 0x21, 0x00, 0x14, /* Properties */
            0x00, 0x00, /* Client ID Length: 0 */
            0x00, 0x04, /* User Name Length: 4 */
            0x75, 0x73, 0x65, 0x72, /* User Name: user */
            0x00, 0x04, /* Password Length: 4 */
            0x71, 0x61, 0x71, 0x73, /* Password: pass */
        ];

        let result = parse_connect(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message.protocol_string, "MQTT");
                assert_eq!(message.protocol_version, 5);
                assert!(message.username_flag);
                assert!(message.password_flag);
                assert!(!message.will_retain);
                assert_eq!(message.will_qos, 0);
                assert!(!message.will_flag);
                assert!(message.clean_session);
                assert_eq!(message.keepalive, 60);
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_connack() {
        let buf = [
            0x00, /* Acknowledge Flags: 0x00 (0000 000. = Reserved: Not set )(.... ...0 = Session Present: Not set) */
            0x00, /* Reason Code: Success (0) */
            0x2f, /* Total Length: 47 */
            0x22, /* ID: Topic Alias Maximum (0x22) */
            0x00, 0x0a, /* Value: 10 */
            0x12, /* ID: Assigned Client Identifier (0x12) */
            0x00, 0x29, /* Length: 41 */
            0x61, 0x75, 0x74, 0x6f, 0x2d, 0x31, 0x42, 0x34, 0x33, 0x45, 0x38, 0x30, 0x30, 0x2d,
            0x30, 0x38, 0x45, 0x33, 0x2d, 0x33, 0x42, 0x41, 0x31, 0x2d, 0x32, 0x45, 0x39, 0x37,
            0x2d, 0x45, 0x39, 0x41, 0x30, 0x42, 0x34, 0x30, 0x36, 0x34, 0x42, 0x46,
            0x35, /* 41 byte Value: auto-1B43E800-08E3-3BA1-2E97-E9A0B4064BF5 */
        ];
        let client_identifier = "auto-1B43E800-08E3-3BA1-2E97-E9A0B4064BF5";

        let result = parse_connack(5);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                let props = message.properties.unwrap();
                assert_eq!(props[0], MQTTProperty::TOPIC_ALIAS_MAXIMUM(10));
                assert_eq!(
                    props[1],
                    MQTTProperty::ASSIGNED_CLIENT_IDENTIFIER(client_identifier.to_string())
                );
                assert_eq!(message.return_code, 0);
                assert!(!message.session_present);
                assert_eq!(remainder.len(), 0);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_publish() {
        let buf = [
            0x00, 0x06, /* Topic Length: 6 */
            0x74, 0x6f, 0x70, 0x69, 0x63, 0x58, /* Topic: topicX */
            0x00, 0x01, /* Message Identifier: 1 */
            0x00, /* Properties 6 */
            0x00, 0x61, 0x75, 0x74, 0x6f, 0x2d, 0x42, 0x34, 0x33, 0x45, 0x38, 0x30,
        ];

        let result = parse_publish(5, true);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                let message_id = message.message_id.unwrap();
                assert_eq!(message.topic, "topicX");
                assert_eq!(message_id, 1);
                assert_eq!(remainder.len(), 13);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_msgidonly_v3() {
        let buf = [
            0x00, 0x01, /* Message Identifier: 1 */
            0x74, 0x6f, 0x70, 0x69, 0x63, 0x58, 0x00, 0x61, 0x75, 0x74, 0x6f, 0x2d, 0x42, 0x34,
            0x33, 0x45, 0x38, 0x30,
        ];

        let result = parse_msgidonly(3);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                assert_eq!(message.message_id, 1);
                assert_eq!(remainder.len(), 18);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_msgidonly_v5() {
        let buf = [
            0x00, 0x01, /* Message Identifier: 1 */
            0x00, /* Reason Code: 0 */
            0x00, /* Properties */
            0x00, 0x61, 0x75, 0x74, 0x6f, 0x2d, 0x42, 0x34, 0x33, 0x45, 0x38, 0x30,
        ];

        let result = parse_msgidonly(5);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                let reason_code = message.reason_code.unwrap();
                assert_eq!(message.message_id, 1);
                assert_eq!(reason_code, 0);
                assert_eq!(remainder.len(), 12);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_subscribe() {
        let buf = [
            0x00, 0x01, /* Message Identifier: 1 */
            0x00, /* Properties 6 */
            0x00, 0x06, /* Topic Length: 6  */
            0x74, 0x6f, 0x70, 0x69, 0x63, 0x58, /* Topic: topicX */
            0x00, /*Subscription Options: 0x00, Retain Handling: Send msgs at subscription time, QoS: At most once delivery (Fire and Forget) */
            0x00, 0x06, /* Topic Length: 6  */
            0x74, 0x6f, 0x70, 0x69, 0x63, 0x59, /* Topic: topicY */
            0x00, /*Subscription Options: 0x00, Retain Handling: Send msgs at subscription time, QoS: At most once delivery (Fire and Forget) */
            0x00, 0x61, 0x75, 0x74, 0x6f, 0x2d, 0x42, 0x34, 0x33, 0x45, 0x38, 0x30,
        ];

        let result = parse_subscribe(5);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                assert_eq!(message.topics[0].topic_name, "topicX");
                assert_eq!(message.topics[1].topic_name, "topicY");
                assert_eq!(message.topics[0].qos, 0);
                assert_eq!(message.message_id, 1);
                assert_eq!(remainder.len(), 12);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
    #[test]
    fn test_parse_suback() {
        let buf = [
            0x00, 0x01, /* Message Identifier: 1 */
            0x00, /* Properties 6 */
            0x00, 0x00, /* Topic Length: 6  */
        ];

        let result = parse_suback(5);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                assert_eq!(message.qoss[0], 0);
                assert_eq!(message.message_id, 1);
                assert_eq!(remainder.len(), 3);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
    #[test]
    fn test_parse_unsubscribe() {
        let buf = [
            0x00, 0x01, /* Message Identifier: 1 */
            0x00, /* Properties 6 */
            0x00, 0x06, /* Topic Length: 6  */
            0x74, 0x6f, 0x70, 0x69, 0x63, 0x58, /* Topic: topicX */
            0x00, /*Subscription Options: 0x00, Retain Handling: Send msgs at subscription time, QoS: At most once delivery (Fire and Forget) */
        ];

        let result = parse_unsubscribe(5);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                assert_eq!(message.topics[0], "topicX");
                assert_eq!(message.message_id, 1);
                assert_eq!(remainder.len(), 1);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_unsuback() {
        let buf = [
            0x00, 0x01, /* Message Identifier: 1 */
            0x00, /* Properties 6 */
            0x00, /* Reason Code */
        ];

        let result = parse_unsuback(5);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                let reason_codes = message.reason_codes.unwrap();
                assert_eq!(reason_codes[0], 0);
                assert_eq!(message.message_id, 1);
                assert_eq!(remainder.len(), 0);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_disconnect() {
        let buf = [
            0xe0, /* Reason: 0 */
            0x00, /* Message Identifier: 1 */
        ];

        let result = parse_disconnect(0, 5);
        let input = result(&buf);
        match input {
            Ok((remainder, message)) => {
                let reason_code = message.reason_code.unwrap();
                assert_eq!(reason_code, 0);
                assert_eq!(remainder.len(), 2);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_message() {
        let buf = [
            0x10, /* Message Identifier: 1 */
            0x2f, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x05,
            0xc2, /* Connect Flags: 0xc2, User Name Flag, Password Flag, QoS Level: At most once delivery (Fire and Forget), Clean Session Flag */
            0x00, 0x3c, 0x03, 0x21, 0x00, 0x14, /* Properties */
            0x00, 0x13, 0x6d, 0x79, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x69, 0x73, 0x6d, 0x79, 0x70,
            0x61, 0x73, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x00, 0x04, 0x75, 0x73, 0x65, 0x72, 0x00,
            0x04, 0x70, 0x61, 0x73, 0x73,
        ];

        let result = parse_message(&buf, 5, 40);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message.header.message_type, MQTTTypeCode::CONNECT);
                assert!(!message.header.dup_flag);
                assert_eq!(message.header.qos_level, 0);
                assert!(!message.header.retain);
                assert_eq!(remainder.len(), 49);
            }

            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
}
