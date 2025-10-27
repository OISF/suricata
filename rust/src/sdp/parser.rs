/* Copyright (C) 2024 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use nom8::{
    branch::alt,
    bytes::complete::{tag, take_till, take_while, take_while_m_n},
    character::complete::{char as char_parser, digit1, line_ending, space1, u8 as take_u8},
    combinator::map_res,
    combinator::{opt, peek, verify},
    error::{make_error, ErrorKind},
    multi::{many0, many1},
    number::complete::be_u8,
    sequence::preceded,
    {AsChar, Err, IResult, Parser},
};

use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug)]
pub struct SdpMessage {
    pub version: u32,
    pub origin: String,
    pub session_name: String,
    pub session_info: Option<String>,
    pub uri: Option<String>,
    pub email: Option<String>,
    pub phone_number: Option<String>,
    pub connection_data: Option<String>,
    pub bandwidths: Option<Vec<String>>,
    pub time_description: Vec<TimeDescription>,
    pub time_zone: Option<String>,
    pub encryption_key: Option<String>,
    pub attributes: Option<Vec<String>>,
    pub media_description: Option<Vec<MediaDescription>>,
}

#[derive(Debug)]
pub struct MediaDescription {
    pub media: String,
    pub session_info: Option<String>,
    pub connection_data: Option<String>,
    pub bandwidths: Option<Vec<String>>,
    pub encryption_key: Option<String>,
    pub attributes: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct TimeDescription {
    pub time: String,
    pub repeat_time: Option<String>,
}

// token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 / %x41-5A / %x5E-7E
#[inline]
fn is_token_char(b: u8) -> bool {
    matches!(b, 0x21 | 0x2A | 0x2B | 0x2D | 0x2E)
        || (0x23..=0x27).contains(&b)
        || (0x30..=0x39).contains(&b)
        || (0x41..=0x5a).contains(&b)
        || (0x5e..=0x7e).contains(&b)
}

#[inline]
fn is_request_uri_char(b: u8) -> bool {
    b.is_alphanum() || is_token_char(b) || b"~#@:;=?+&$,/".contains(&b)
}

#[inline]
fn is_line_ending(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

#[inline]
fn is_ipaddr_char(b: u8) -> bool {
    b.is_ascii_hexdigit() || b".:".contains(&b)
}

#[inline]
fn is_session_name_char(b: u8) -> bool {
    b.is_alphanum() || b.is_space()
}

#[inline]
fn is_time_char(b: u8) -> bool {
    b.is_dec_digit() || b"dhms-".contains(&b)
}

fn parse_num(i: &[u8]) -> IResult<&[u8], u8> {
    let (i, num) = preceded(verify(peek(be_u8), |d| *d != 0x30), take_u8).parse(i)?;
    Ok((i, num))
}

// SDP Message format (fields marked with * are optional):
// https://www.rfc-editor.org/rfc/rfc4566#page-9
//
//       Session description
//         v=  (protocol version)
//         o=  (originator and session identifier)
//         s=  (session name)
//         i=* (session information)
//         u=* (URI of description)
//         e=* (email address)
//         p=* (phone number)
//         c=* (connection information -- not required if included in
//              all media)
//         b=* (zero or more bandwidth information lines)
//         One or more time descriptions ("t=" and "r=" lines; see below)
//         z=* (time zone adjustments)
//         k=* (encryption key)
//         a=* (zero or more session attribute lines)
//         Zero or more media descriptions
//
//      Time description
//         t=  (time the session is active)
//         r=* (zero or more repeat times)
//
//      Media description, if present
//         m=  (media name and transport address)
//         i=* (media title)
//         c=* (connection information -- optional if included at
//              session level)
//         b=* (zero or more bandwidth information lines)
//         k=* (encryption key)
//         a=* (zero or more media attribute lines)

pub fn sdp_parse_message(i: &[u8]) -> IResult<&[u8], SdpMessage> {
    let (i, version) = parse_version_line(i)?;
    let (i, origin) = parse_origin_line(i)?;
    let (i, session_name) = parse_session_name(i)?;
    let (i, session_info) = opt(parse_session_info).parse(i)?;
    let (i, uri) = opt(parse_uri).parse(i)?;
    let (i, email) = opt(parse_email).parse(i)?;
    let (i, phone_number) = opt(parse_phone_number).parse(i)?;
    let (i, connection_data) = opt(parse_connection_data).parse(i)?;
    let (i, bandwidths) = opt(parse_bandwidth).parse(i)?;
    let (i, time_description) = many1(parse_time_description).parse(i)?;
    let (i, time_zone) = opt(parse_time_zone).parse(i)?;
    let (i, encryption_key) = opt(parse_encryption_key).parse(i)?;
    let (i, attributes) = opt(parse_attributes).parse(i)?;
    let (i, media_description) = opt(many0(parse_media_description)).parse(i)?;
    Ok((
        i,
        SdpMessage {
            version,
            origin,
            session_name,
            session_info,
            uri,
            email,
            phone_number,
            connection_data,
            bandwidths,
            time_description,
            time_zone,
            encryption_key,
            attributes,
            media_description,
        },
    ))
}

fn parse_version_line(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, _) = tag("v=").parse(i)?;
    let (i, _v) = tag("0").parse(i)?;
    let (i, _) = line_ending.parse(i)?;

    Ok((i, 0))
}

fn parse_origin_line(i: &[u8]) -> IResult<&[u8], String> {
    let (i, _) = tag("o=").parse(i)?;
    let (i, username) = map_res(take_while(is_token_char), std::str::from_utf8).parse(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, sess_id) = map_res(take_while(|c: u8| c.is_dec_digit()), std::str::from_utf8).parse(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, sess_version) = map_res(take_while(|c: u8| c.is_dec_digit()), std::str::from_utf8).parse(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, nettype) = map_res(take_while(|c: u8| c.is_alpha()), std::str::from_utf8).parse(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, addrtype) = map_res(take_while(|c: u8| c.is_alphanum()), std::str::from_utf8).parse(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, unicast_address) = map_res(take_till(is_line_ending), std::str::from_utf8).parse(i)?;
    let (i, _) = line_ending.parse(i)?;

    let origin_line = format!(
        "{} {} {} {} {} {}",
        username, sess_id, sess_version, nettype, addrtype, unicast_address
    );

    Ok((i, origin_line))
}

fn parse_session_name(i: &[u8]) -> IResult<&[u8], String> {
    let (i, _) = tag("s=").parse(i)?;
    let (i, name) = map_res(take_while(is_session_name_char), std::str::from_utf8).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    Ok((i, name.to_string()))
}

fn parse_session_info(i: &[u8]) -> IResult<&[u8], String> {
    let (i, _) = tag("i=").parse(i)?;
    let (i, info) = map_res(take_while(is_session_name_char), std::str::from_utf8).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    Ok((i, info.to_string()))
}

fn parse_uri(i: &[u8]) -> IResult<&[u8], String> {
    let (i, _) = tag("u=").parse(i)?;
    let (i, uri) = map_res(take_while(is_request_uri_char), std::str::from_utf8).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    Ok((i, uri.to_string()))
}

fn parse_connection_data(i: &[u8]) -> IResult<&[u8], String> {
    let (i, _) = tag("c=").parse(i)?;
    let (i, nettype) = map_res(take_while(|c: u8| c.is_alpha()), std::str::from_utf8).parse(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, addrtype) = map_res(take_while(|c: u8| c.is_alphanum()), std::str::from_utf8).parse(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, connection_address) = map_res(
        map_res(take_while(is_ipaddr_char), std::str::from_utf8),
        IpAddr::from_str,
    ).parse(i)?;
    let (i, first_num) = opt(preceded(char_parser('/'), parse_num)).parse(i)?;
    let (i, second_num) = opt(preceded(char_parser('/'), parse_num)).parse(i)?;
    let (i, _) = line_ending.parse(i)?;

    let (ttl, number_of_addresses) = match connection_address {
        _ if connection_address.is_ipv6() => (None, first_num),
        _ if connection_address.is_ipv4() && connection_address.is_multicast() => {
            match (first_num, second_num) {
                (None, _) => return Err(Err::Error(make_error(i, ErrorKind::HexDigit))),
                _ => (first_num, second_num),
            }
        }
        _ if connection_address.is_ipv4() => match (first_num, second_num) {
            (Some(_), None) => (None, first_num),
            _ => (first_num, second_num),
        },
        _ => (None, None),
    };

    let mut connection_data = format!(
        "{} {} {}",
        &nettype,
        &addrtype,
        &connection_address.to_string()
    );
    if let Some(ttl) = ttl {
        connection_data = format!("{}/{}", connection_data, ttl);
    }
    if let Some(num_addrs) = number_of_addresses {
        connection_data = format!("{}/{}", connection_data, num_addrs);
    }

    Ok((i, connection_data))
}

fn parse_email(i: &[u8]) -> IResult<&[u8], String> {
    let (i, email) = preceded(
        tag("e="),
        map_res(take_till(is_line_ending), std::str::from_utf8),
    ).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    Ok((i, email.to_string()))
}

fn parse_phone_number(i: &[u8]) -> IResult<&[u8], String> {
    let (i, phone_number) = preceded(
        tag("p="),
        map_res(take_till(is_line_ending), std::str::from_utf8),
    ).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    Ok((i, phone_number.to_string()))
}

fn parse_bandwidth(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, bws) = many0(preceded(
        tag("b="),
        (
            map_res(
                alt((tag("CT"), tag("AS"), tag("TIAS"))),
                std::str::from_utf8,
            ),
            char_parser(':'),
            map_res(digit1, std::str::from_utf8),
            line_ending,
        ),
    )).parse(i)?;
    let vec = bws.iter().map(|bw| format!("{}:{}", bw.0, bw.2)).collect();
    Ok((i, vec))
}

fn parse_time_description(i: &[u8]) -> IResult<&[u8], TimeDescription> {
    let (i, time) = parse_time(i)?;
    let (i, repeat_time) = opt(parse_repeat_times).parse(i)?;
    Ok((i, TimeDescription { time, repeat_time }))
}

fn parse_time(i: &[u8]) -> IResult<&[u8], String> {
    let (i, (start_time, _, stop_time)) = preceded(
        tag("t="),
        (
            map_res(digit1, std::str::from_utf8),
            space1,
            map_res(digit1, std::str::from_utf8),
        ),
    ).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    let time = format!("{} {}", start_time, stop_time);
    Ok((i, time))
}

fn parse_repeat_times(i: &[u8]) -> IResult<&[u8], String> {
    let (i, (d, _, h, _, m, _, s)) = preceded(
        tag("r="),
        (
            map_res(take_while(is_time_char), std::str::from_utf8),
            space1,
            map_res(take_while(is_time_char), std::str::from_utf8),
            space1,
            map_res(take_while(is_time_char), std::str::from_utf8),
            space1,
            map_res(take_while(is_time_char), std::str::from_utf8),
        ),
    ).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    let val = format!("{} {} {} {}", d, h, m, s);
    Ok((i, val.to_string()))
}

fn parse_time_zone(i: &[u8]) -> IResult<&[u8], String> {
    let (i, (z1, _, z2, _, z3, _, z4)) = preceded(
        tag("z="),
        (
            map_res(take_while(is_time_char), std::str::from_utf8),
            space1,
            map_res(take_while(is_time_char), std::str::from_utf8),
            space1,
            map_res(take_while(is_time_char), std::str::from_utf8),
            space1,
            map_res(take_while(is_time_char), std::str::from_utf8),
        ),
    ).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    let tz = format!("{} {} {} {}", z1, z2, z3, z4);
    Ok((i, tz.to_string()))
}

fn parse_encryption_key(i: &[u8]) -> IResult<&[u8], String> {
    let (i, key) = preceded(
        tag("k="),
        map_res(take_till(is_line_ending), std::str::from_utf8),
    ).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    Ok((i, key.to_string()))
}

fn parse_attributes(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, attrs) = many0(preceded(
        tag("a="),
        (
            map_res(take_while(|c: u8| c.is_alpha()), std::str::from_utf8),
            opt(preceded(
                char_parser(':'),
                map_res(take_till(is_line_ending), std::str::from_utf8),
            )),
            line_ending,
        ),
    )).parse(i)?;
    let vec = attrs
        .iter()
        .map(|a| {
            if let Some(val) = a.1 {
                format!("{}:{}", a.0, val)
            } else {
                a.0.to_string()
            }
        })
        .collect();
    Ok((i, vec))
}

fn parse_media_description(i: &[u8]) -> IResult<&[u8], MediaDescription> {
    let (i, _) = tag("m=").parse(i)?;
    let (i, media) = map_res(
        alt((
            tag("audio"),
            tag("video"),
            tag("text"),
            tag("application"),
            tag("message"),
        )),
        |bytes: &[u8]| String::from_utf8(bytes.to_vec()),
    ).parse(i)?;
    let (i, _) = space1.parse(i)?;

    let (i, port) = map_res(
        take_while_m_n(1, 5, |b: u8| b.is_ascii_digit()),
        std::str::from_utf8,
    ).parse(i)?;
    let (i, number_of_ports) = opt(preceded(
        char_parser('/'),
        map_res(
            take_while_m_n(1, 5, |b: u8| b.is_ascii_digit()),
            std::str::from_utf8,
        ),
    )).parse(i)?;
    let (i, _) = space1.parse(i)?;

    let (i, proto) = map_res(
        alt((tag("udp"), tag("RTP/AVP"), tag("RTP/SAVP"))),
        |bytes: &[u8]| String::from_utf8(bytes.to_vec()),
    ).parse(i)?;

    let (i, fmt) = many1(preceded(
        space1,
        map_res(
            take_while_m_n(1, 255, |b: u8| b.is_ascii_alphanumeric()),
            std::str::from_utf8,
        ),
    )).parse(i)?;
    let (i, _) = line_ending.parse(i)?;

    let (i, session_info) = opt(parse_session_info).parse(i)?;
    let (i, connection_data) = opt(parse_connection_data).parse(i)?;
    let (i, bandwidths) = opt(parse_bandwidth).parse(i)?;
    let (i, encryption_key) = opt(parse_encryption_key).parse(i)?;
    let (i, attributes) = opt(parse_attributes).parse(i)?;

    let port: u16 = match port.parse::<u16>() {
        Ok(p) => p,
        Err(_) => return Err(Err::Error(make_error(i, ErrorKind::HexDigit))),
    };
    let number_of_ports: Option<u16> = match number_of_ports {
        Some(num_str) => num_str.parse().ok(),
        None => None,
    };

    let port = if let Some(num_ports) = number_of_ports {
        format!("{}/{}", port, num_ports)
    } else {
        format!("{}", port)
    };
    let mut media_str = format!("{} {} {}", &media, &port, &proto);
    if !fmt.is_empty() {
        let fmt: Vec<String> = fmt.into_iter().map(String::from).collect();
        media_str = format!("{} {}", media_str, fmt.join(" "));
    }
    Ok((
        i,
        MediaDescription {
            media: media_str,
            session_info,
            connection_data,
            bandwidths,
            encryption_key,
            attributes,
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::sdp::parser::*;

    #[test]
    fn test_version_line() {
        let buf: &[u8] = "v=0\n\r".as_bytes();
        let (_, v) = parse_version_line(buf).expect("parsing failed");
        assert_eq!(v, 0);
    }

    #[test]
    fn test_origin_line() {
        let buf: &[u8] = "o=Clarent 120386 120387 IN IP4 200.57.7.196\r\n".as_bytes();

        let (_, o) = parse_origin_line(buf).expect("parsing failed");
        assert_eq!(o, "Clarent 120386 120387 IN IP4 200.57.7.196");
    }

    #[test]
    fn test_session_name_line() {
        let buf: &[u8] = "s=Clarent C5CM\r\n".as_bytes();

        let (_, s) = parse_session_name(buf).expect("parsing failed");
        assert_eq!(s, "Clarent C5CM");
    }

    #[test]
    fn test_session_info_line() {
        let buf: &[u8] = "i=Session Description Protocol\r\n".as_bytes();

        let (_, s) = parse_session_info(buf).expect("parsing failed");
        assert_eq!(s, "Session Description Protocol");
    }

    #[test]
    fn test_uri_line() {
        let buf: &[u8] = "u=https://www.sdp.proto\r\n".as_bytes();

        let (_, u) = parse_uri(buf).expect("parsing failed");
        assert_eq!(u, "https://www.sdp.proto");
    }

    #[test]
    fn test_connection_line_1() {
        let buf: &[u8] = "c=IN IP4 224.2.36.42/127\r\n".as_bytes();

        let (_, c) = parse_connection_data(buf).expect("parsing failed");
        assert_eq!(c, "IN IP4 224.2.36.42/127");
    }

    #[test]
    fn test_connection_line_2() {
        let buf: &[u8] = "c=IN IP6 FF15::101/3\r\n".as_bytes();

        let (_, c) = parse_connection_data(buf).expect("parsing failed");
        assert_eq!(c, "IN IP6 ff15::101/3");
    }

    #[test]
    fn test_connection_line_3() {
        let buf: &[u8] = "c=IN IP4 224.2.36.42/127/2\r\n".as_bytes();

        let (_, c) = parse_connection_data(buf).expect("parsing failed");
        assert_eq!(c, "IN IP4 224.2.36.42/127/2");
    }

    #[test]
    fn test_connection_line_4() {
        let buf: &[u8] = "c=IN IP4 224.2.36.42\r\n".as_bytes();

        let result = parse_connection_data(buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_line_5() {
        let buf: &[u8] = "c=IN IP4 8.8.8.8\r\n".as_bytes();

        let (_, c) = parse_connection_data(buf).expect("parsing failed");
        assert_eq!(c, "IN IP4 8.8.8.8");
    }

    #[test]
    fn test_connection_line_6() {
        let buf: &[u8] = "c=IN IP6 FF15::101\r\n".as_bytes();

        let (_, c) = parse_connection_data(buf).expect("parsing failed");
        assert_eq!(c, "IN IP6 ff15::101");
    }

    #[test]
    fn test_email_line() {
        let buf: &[u8] = "e=j.doe@example.com (Jane Doe)\r\n".as_bytes();

        let (_, e) = parse_email(buf).expect("parsing failed");
        assert_eq!(e, "j.doe@example.com (Jane Doe)");
    }

    #[test]
    fn test_phone_line() {
        let buf: &[u8] = "p=+1 617 555-6011 (Jane Doe)\r\n".as_bytes();

        let (_, p) = parse_phone_number(buf).expect("parsing failed");
        assert_eq!(p, "+1 617 555-6011 (Jane Doe)");
    }

    #[test]
    fn test_bandwidth_line() {
        let buf: &[u8] = "b=AS:64\r\n".as_bytes();
        let (_, b) = parse_bandwidth(buf).expect("parsing failed");
        assert_eq!(b.first().unwrap(), "AS:64");
    }

    #[test]
    fn test_time_line() {
        let buf: &[u8] = "t=3034423619 3042462419\r\n".as_bytes();
        let (_, t) = parse_time(buf).expect("parsing failed");
        assert_eq!(t, "3034423619 3042462419");
    }

    #[test]
    fn test_repeat_time_line_1() {
        let buf: &[u8] = "r=604800 3600 0 90000\r\n".as_bytes();
        let (_, t) = parse_repeat_times(buf).expect("parsing failed");
        assert_eq!(t, "604800 3600 0 90000");
    }

    #[test]
    fn test_repeat_time_line_2() {
        let buf: &[u8] = "r=7d 1h 0 25h\r\n".as_bytes();
        let (_, t) = parse_repeat_times(buf).expect("parsing failed");
        assert_eq!(t, "7d 1h 0 25h");
    }

    #[test]
    fn test_time_zone_line() {
        let buf: &[u8] = "z=2882844526 -1h 2898848070 0\r\n".as_bytes();
        let (_, t) = parse_time_zone(buf).expect("parsing failed");
        assert_eq!(t, "2882844526 -1h 2898848070 0");
    }

    #[test]
    fn test_encryption_key_line() {
        let buf: &[u8] = "k=prompt\r\n".as_bytes();
        let (_, k) = parse_encryption_key(buf).expect("parsing failed");
        assert_eq!(k, "prompt");
    }

    #[test]
    fn test_attribute_line() {
        let buf: &[u8] = "a=sendrecv\r\na=rtpmap:8 PCMA/8000/1\r\n".as_bytes();
        let (_, a) = parse_attributes(buf).expect("parsing failed");
        assert_eq!(a.first().unwrap(), "sendrecv");
        assert_eq!(a.get(1).unwrap(), "rtpmap:8 PCMA/8000/1");
    }

    #[test]
    fn test_media_line() {
        let buf: &[u8] = "m=audio 40392 RTP/AVP 8 0\r\n".as_bytes();
        let (_, m) = parse_media_description(buf).expect("parsing failed");
        assert_eq!(m.media, "audio 40392 RTP/AVP 8 0");
    }

    #[test]
    fn test_media_line_2() {
        let buf: &[u8] = "m=audio 70000 RTP/AVP 8 0\r\n".as_bytes();
        let result = parse_media_description(buf);
        assert!(result.is_err());
    }
}
