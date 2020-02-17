/* Copyright (C) 2019 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glono.it>

use nom::*;
use nom::IResult;
use nom::character::{is_alphabetic, is_alphanumeric, is_space};
use nom::character::streaming::crlf;
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
    pub headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct Response {
    pub version: String,
    pub code: String,
    pub reason: String,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Method {
    Register,
    Custom(String),
}

#[inline]
fn is_token_char(b: u8) -> bool {
    is_alphanumeric(b) || b"!%'*+-._`".contains(&b)
}

#[inline]
fn is_method_char(b: u8) -> bool {
    is_alphabetic(b)
}

#[inline]
fn is_request_uri_char(b: u8) -> bool {
    is_alphanumeric(b) || is_token_char(b) || b"~#@:".contains(&b)
}

#[inline]
fn is_version_char(b: u8) -> bool {
    is_alphanumeric(b) || b"./".contains(&b)
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

named!(pub sip_parse_request<&[u8], Request>,
    do_parse!(
        method: parse_method >> char!(' ') >>
        path: parse_request_uri >> char!(' ') >>
        version: parse_version >> crlf >>
        headers: parse_headers >>
        crlf >>
        (Request { method: method.into(), path: path.into(), version: version.into(), headers: headers})
    )
);

named!(pub sip_parse_response<&[u8], Response>,
    do_parse!(
        version: parse_version >> char!(' ') >>
        code: parse_code >> char!(' ') >>
        reason: parse_reason >> crlf >>
        (Response { version: version.into(), code: code.into(), reason: reason.into() })
    )
);

named!(#[inline], parse_method<&[u8], &str>,
    map_res!(take_while!(is_method_char), std::str::from_utf8)
);

named!(#[inline], parse_request_uri<&[u8], &str>,
    map_res!(take_while1!(is_request_uri_char), std::str::from_utf8)
);

named!(#[inline], parse_version<&[u8], &str>,
    map_res!(take_while1!(is_version_char), std::str::from_utf8)
);

named!(#[inline], parse_code<&[u8], &str>,
    map_res!(take!(3), std::str::from_utf8)
);

named!(#[inline], parse_reason<&[u8], &str>,
    map_res!(take_while!(is_reason_phrase), std::str::from_utf8)
);

named!(#[inline], header_name<&[u8], &str>,
        map_res!(take_while!(is_header_name), std::str::from_utf8)
);

named!(#[inline], header_value<&[u8], &str>,
    map_res!(parse_header_value, std::str::from_utf8)
);

named!(
    hcolon<char>,
    delimited!(take_while!(is_space), char!(':'), take_while!(is_space))
);

named!(
    message_header<Header>,
    do_parse!(
        n: header_name
            >> hcolon
            >> v: header_value
            >> crlf
            >> (Header {
                name: String::from(n),
                value: String::from(v)
            })
    )
);

named!(pub sip_take_line<&[u8], Option<String> >,
    do_parse!(
        line: map_res!(take_while1!(is_reason_phrase), std::str::from_utf8) >>
        (Some(line.into()))
    )
);

pub fn parse_headers(mut input: &[u8]) -> IResult<&[u8], HashMap<String, String>> {
    let mut headers_map: HashMap<String, String> = HashMap::new();
    loop {
        match crlf(input) as IResult<&[u8],_> {
            Ok((_, _)) => {
                break;
            }
            Err(Err::Error(_)) => {}
            Err(Err::Failure(_)) => {}
            Err(Err::Incomplete(e)) => return Err(Err::Incomplete(e)),
        };
        let (rest, header) = try_parse!(input, message_header);
        headers_map.insert(header.name, header.value);
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
                    return Err(Err::Incomplete(Needed::Size(1)));
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
                    return Err(Err::Incomplete(Needed::Size(1)));
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

        match sip_parse_request(buf) {
            Ok((_, req)) => {
                assert_eq!(req.method, "REGISTER");
                assert_eq!(req.path, "sip:sip.cybercity.dk");
                assert_eq!(req.version, "SIP/2.0");
                assert_eq!(req.headers["Content-Length"], "0");
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parse_request_trail_space_header() {
        let buf: &[u8] = "REGISTER sip:sip.cybercity.dk SIP/2.0\r\n\
                          From: <sip:voi18063@sip.cybercity.dk>;tag=903df0a\r\n\
                          To: <sip:voi18063@sip.cybercity.dk>\r\n\
                          Content-Length: 0  \r\n\
                          \r\n"
            .as_bytes();

        match sip_parse_request(buf) {
            Ok((_, req)) => {
                assert_eq!(req.method, "REGISTER");
                assert_eq!(req.path, "sip:sip.cybercity.dk");
                assert_eq!(req.version, "SIP/2.0");
                assert_eq!(req.headers["Content-Length"], "0");
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parse_response() {
        let buf: &[u8] = "SIP/2.0 401 Unauthorized\r\n\
                          \r\n"
            .as_bytes();

        match sip_parse_response(buf) {
            Ok((_, resp)) => {
                assert_eq!(resp.version, "SIP/2.0");
                assert_eq!(resp.code, "401");
                assert_eq!(resp.reason, "Unauthorized");
            }
            _ => {
                assert!(false);
            }
        }
    }
}
