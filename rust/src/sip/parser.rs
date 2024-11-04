/* Copyright (C) 2019-2022 Open Information Security Foundation
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

use crate::sdp::parser::{sdp_parse_message, SdpMessage};
use nom7::bytes::streaming::{tag, take, take_while, take_while1};
use nom7::character::streaming::{char, crlf};
use nom7::character::{is_alphabetic, is_alphanumeric, is_digit, is_space};
use nom7::combinator::{map, map_res, opt};
use nom7::sequence::delimited;
use nom7::{Err, IResult, Needed};
use std;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, Vec<String>>,

    pub request_line_len: u16,
    pub headers_len: u16,
    pub body_offset: u16,
    pub body_len: u16,
    pub body: Option<SdpMessage>,
}

#[derive(Debug)]
pub struct Response {
    pub version: String,
    pub code: String,
    pub reason: String,
    pub headers: HashMap<String, Vec<String>>,
    pub response_line_len: u16,
    pub headers_len: u16,
    pub body_offset: u16,
    pub body_len: u16,
    pub body: Option<SdpMessage>,
}

/**
 * Valid tokens and chars are defined in RFC3261:
 * https://www.rfc-editor.org/rfc/rfc3261#section-25.1
 */
#[inline]
fn is_token_char(b: u8) -> bool {
    is_alphanumeric(b) || b"!%'*+-._`~".contains(&b)
}

#[inline]
fn is_method_char(b: u8) -> bool {
    is_alphabetic(b)
}

#[inline]
fn is_request_uri_char(b: u8) -> bool {
    is_alphanumeric(b) || is_token_char(b) || b"~#@:;=?+&$,/".contains(&b)
}

#[inline]
fn is_version_char(b: u8) -> bool {
    is_digit(b) || b".".contains(&b)
}

#[inline]
fn is_reason_phrase(b: u8) -> bool {
    is_alphanumeric(b) || is_token_char(b) || b"$&(),/:;=?@[\\]^ ".contains(&b)
}

fn is_header_name(b: u8) -> bool {
    is_alphanumeric(b) || is_token_char(b)
}

fn is_header_value(b: u8) -> bool {
    is_alphanumeric(b) || is_token_char(b) || b"\"#$&(),/;:<=>?@[]{}()^|~\\\t\n\r ".contains(&b)
}

fn expand_header_name(h: &str) -> &str {
    match h {
        "i" => "Call-ID",
        "m" => "Contact",
        "e" => "Content-Encoding",
        "l" => "Content-Length",
        "c" => "Content-Type",
        "f" => "From",
        "s" => "Subject",
        "k" => "Supported",
        "t" => "To",
        "v" => "Via",
        _ => h,
    }
}

pub fn sip_parse_request(oi: &[u8]) -> IResult<&[u8], Request> {
    let (i, method) = parse_method(oi)?;
    let (i, _) = char(' ')(i)?;
    let (i, path) = parse_request_uri(i)?;
    let (i, _) = char(' ')(i)?;
    let (i, version) = parse_version(i)?;
    let (hi, _) = crlf(i)?;
    let request_line_len = oi.len() - hi.len();
    let (phi, headers) = parse_headers(hi)?;
    let headers_len = hi.len() - phi.len();
    let (bi, _) = crlf(phi)?;
    let body_offset = oi.len() - bi.len();
    let (i, body) = opt(sdp_parse_message)(bi)?;
    Ok((
        i,
        Request {
            method: method.into(),
            path: path.into(),
            version,
            headers,

            request_line_len: request_line_len as u16,
            headers_len: headers_len as u16,
            body_offset: body_offset as u16,
            body_len: bi.len() as u16,
            body,
        },
    ))
}

pub fn sip_parse_response(oi: &[u8]) -> IResult<&[u8], Response> {
    let (i, version) = parse_version(oi)?;
    let (i, _) = char(' ')(i)?;
    let (i, code) = parse_code(i)?;
    let (i, _) = char(' ')(i)?;
    let (i, reason) = parse_reason(i)?;
    let (hi, _) = crlf(i)?;
    let response_line_len = oi.len() - hi.len();
    let (phi, headers) = parse_headers(hi)?;
    let headers_len = hi.len() - phi.len();
    let (bi, _) = crlf(phi)?;
    let body_offset = oi.len() - bi.len();
    let (i, body) = opt(sdp_parse_message)(bi)?;
    Ok((
        i,
        Response {
            version,
            code: code.into(),
            reason: reason.into(),
            headers,

            response_line_len: response_line_len as u16,
            headers_len: headers_len as u16,
            body_offset: body_offset as u16,
            body_len: bi.len() as u16,
            body,
        },
    ))
}

#[inline]
fn parse_method(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while(is_method_char), std::str::from_utf8)(i)
}

#[inline]
fn parse_request_uri(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_request_uri_char), std::str::from_utf8)(i)
}

#[inline]
fn parse_version(i: &[u8]) -> IResult<&[u8], String> {
    let (i, prefix) = map_res(tag("SIP/"), std::str::from_utf8)(i)?;
    let (i, version) = map_res(take_while1(is_version_char), std::str::from_utf8)(i)?;
    Ok((i, format!("{}{}", prefix, version)))
}

#[inline]
fn parse_code(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(take(3_usize), std::str::from_utf8)(i)
}

#[inline]
fn parse_reason(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while(is_reason_phrase), std::str::from_utf8)(i)
}

#[inline]
fn header_name(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while(is_header_name), std::str::from_utf8)(i)
}

#[inline]
fn header_value(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(parse_header_value, std::str::from_utf8)(i)
}

#[inline]
fn hcolon(i: &[u8]) -> IResult<&[u8], char> {
    delimited(take_while(is_space), char(':'), take_while(is_space))(i)
}

fn message_header(i: &[u8]) -> IResult<&[u8], Header> {
    let (i, n) = map(header_name, expand_header_name)(i)?;
    let (i, _) = hcolon(i)?;
    let (i, v) = header_value(i)?;
    let (i, _) = crlf(i)?;
    Ok((
        i,
        Header {
            name: String::from(n),
            value: String::from(v),
        },
    ))
}

pub fn sip_take_line(i: &[u8]) -> IResult<&[u8], Option<String>> {
    let (i, line) = map_res(take_while1(is_reason_phrase), std::str::from_utf8)(i)?;
    Ok((i, Some(line.into())))
}

pub fn parse_headers(mut input: &[u8]) -> IResult<&[u8], HashMap<String, Vec<String>>> {
    let mut headers_map: HashMap<String, Vec<String>> = HashMap::new();
    loop {
        match crlf(input) as IResult<&[u8], _> {
            Ok((_, _)) => {
                break;
            }
            Err(Err::Error(_)) => {}
            Err(Err::Failure(_)) => {}
            Err(Err::Incomplete(e)) => return Err(Err::Incomplete(e)),
        };
        let (rest, header) = message_header(input)?;
        headers_map
            .entry(header.name)
            .or_default()
            .push(header.value);
        input = rest;
    }

    Ok((input, headers_map))
}

fn parse_header_value(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    let mut end_pos = 0;
    let mut trail_spaces = 0;
    let mut idx = 0;
    while idx < buf.len() {
        match buf[idx] {
            b'\n' => {
                idx += 1;
                if idx >= buf.len() {
                    return Err(Err::Incomplete(Needed::new(1)));
                }
                match buf[idx] {
                    b' ' | b'\t' => {
                        idx += 1;
                        continue;
                    }
                    _ => {
                        return Ok((&buf[(end_pos + trail_spaces)..], &buf[..end_pos]));
                    }
                }
            }
            b' ' | b'\t' => {
                trail_spaces += 1;
            }
            b'\r' => {}
            b => {
                trail_spaces = 0;
                if !is_header_value(b) {
                    return Err(Err::Incomplete(Needed::new(1)));
                }
                end_pos = idx + 1;
            }
        }
        idx += 1;
    }
    Ok((&b""[..], buf))
}

#[cfg(test)]
mod tests {

    use crate::sip::parser::*;

    #[test]
    fn test_parse_request() {
        let buf: &[u8] = "REGISTER sip:sip.cybercity.dk SIP/2.0\r\n\
                          From: <sip:voi18063@sip.cybercity.dk>;tag=903df0a\r\n\
                          To: <sip:voi18063@sip.cybercity.dk>\r\n\
                          Content-Length: 0\r\n\
                          \r\n"
            .as_bytes();

        let (_, req) = sip_parse_request(buf).unwrap();
        assert_eq!(req.method, "REGISTER");
        assert_eq!(req.path, "sip:sip.cybercity.dk");
        assert_eq!(req.version, "SIP/2.0");
        assert_eq!(req.headers["Content-Length"].first().unwrap(), "0");
    }

    #[test]
    fn test_parse_request_trail_space_header() {
        let buf: &[u8] = "REGISTER sip:sip.cybercity.dk SIP/2.0\r\n\
                          From: <sip:voi18063@sip.cybercity.dk>;tag=903df0a\r\n\
                          To: <sip:voi18063@sip.cybercity.dk>\r\n\
                          Content-Length: 4  \r\n\
                          \r\nABCD"
            .as_bytes();

        let (body, req) = sip_parse_request(buf).expect("parsing failed");
        assert_eq!(req.method, "REGISTER");
        assert_eq!(req.path, "sip:sip.cybercity.dk");
        assert_eq!(req.version, "SIP/2.0");
        assert_eq!(req.headers["Content-Length"].first().unwrap(), "4");
        assert_eq!(body, "ABCD".as_bytes());
    }

    #[test]
    fn test_parse_response() {
        let buf: &[u8] = "SIP/2.0 401 Unauthorized\r\n\
                          \r\n"
            .as_bytes();

        let (_, resp) = sip_parse_response(buf).unwrap();
        assert_eq!(resp.version, "SIP/2.0");
        assert_eq!(resp.code, "401");
        assert_eq!(resp.reason, "Unauthorized");
    }

    #[test]
    fn test_parse_invalid_version() {
        let buf: &[u8] = "HTTP/1.1\r\n".as_bytes();

        // This test must fail if 'HTTP/1.1' is accepted
        assert!(parse_version(buf).is_err());
    }

    #[test]
    fn test_parse_valid_version() {
        let buf: &[u8] = "SIP/2.0\r\n".as_bytes();

        let (_rem, result) = parse_version(buf).unwrap();
        assert_eq!(result, "SIP/2.0");
    }

    #[test]
    fn test_header_multi_value() {
        let buf: &[u8] = "REGISTER sip:sip.cybercity.dk SIP/2.0\r\n\
                          From: <sip:voi18063@sip.cybercity.dk>;tag=903df0a\r\n\
                          To: <sip:voi18063@sip.cybercity.dk>\r\n\
                          Route: <sip:bob@biloxi.com>\r\n\
                          Route: <sip:carol@chicago.com>\r\n\
                          \r\n"
            .as_bytes();

        let (_, req) = sip_parse_request(buf).unwrap();
        assert_eq!(req.method, "REGISTER");
        assert_eq!(req.path, "sip:sip.cybercity.dk");
        assert_eq!(req.version, "SIP/2.0");
        assert_eq!(
            req.headers["Route"].first().unwrap(),
            "<sip:bob@biloxi.com>"
        );
        assert_eq!(
            req.headers["Route"].get(1).unwrap(),
            "<sip:carol@chicago.com>"
        );
    }
}
