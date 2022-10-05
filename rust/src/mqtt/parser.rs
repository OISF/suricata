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
    (b & 128) != 0
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
    value
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
            while newrem.len() > 0 {
                match parse_property(newrem) {
                    Ok((rem2, val)) => {
                        props.push(val);
                        newrem = rem2;
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok((rem, Some(props)))
        }
        Err(e) => Err(e),
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
                t
            } else {
                MQTTTypeCode::UNASSIGNED
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
            qos_level: flags.2 as u8,
            retain: flags.3 != 0,
            remaining_length,
        },
    ))
}

#[inline]
fn parse_connect_variable_flags(i: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8, u8, u8, u8)> {
    bits(tuple((
        take_bits(1u8),
        take_bits(1u8),
        take_bits(1u8),
        take_bits(2u8),
        take_bits(1u8),
        take_bits(1u8),
        take_bits(1u8),
    )))(i)
}

#[inline]
fn parse_connect(i: &[u8]) -> IResult<&[u8], MQTTConnectData> {
    let (i, protocol_string) = parse_mqtt_string(i)?;
    let (i, protocol_version) = be_u8(i)?;
    let (i, flags) = parse_connect_variable_flags(i)?;
    let (i, keepalive) = be_u16(i)?;
    let (i, properties) = parse_properties(i, protocol_version == 5)?;
    let (i, client_id) = parse_mqtt_string(i)?;
    let (i, will_properties) = parse_properties(i, protocol_version == 5 && flags.4 != 0)?;
    let (i, will_topic) = cond(flags.4 != 0, parse_mqtt_string)(i)?;
    let (i, will_message) = cond(flags.4 != 0, parse_mqtt_binary_data)(i)?;
    let (i, username) = cond(flags.0 != 0, parse_mqtt_string)(i)?;
    let (i, password) = cond(flags.1 != 0, parse_mqtt_binary_data)(i)?;
    Ok((
        i,
        MQTTConnectData {
            protocol_string,
            protocol_version,
            username_flag: flags.0 != 0,
            password_flag: flags.1 != 0,
            will_retain: flags.2 != 0,
            will_qos: flags.3 as u8,
            will_flag: flags.4 != 0,
            clean_session: flags.5 != 0,
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
                                Ok((
                                    rem,
                                    MQTTMessageIdOnly {
                                        message_id,
                                        reason_code: Some(reason_code),
                                        properties,
                                    },
                                ))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
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
                        Ok((
                            rem,
                            MQTTDisconnectData {
                                reason_code: Some(reason_code),
                                properties,
                            },
                        ))
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
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
                Ok((&full[skiplen + len..], msg))
            }
        }
    }
}

pub fn parse_message(
    input: &[u8], protocol_version: u8, max_msg_size: usize,
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
            if len > max_msg_size {
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
            Err(err)
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
}
