/* Copyright (C) 2017 Open Information Security Foundation
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

//! FTP parser and application layer module.

use nom7::bytes::complete::{tag, take_until, take_while1};
use nom7::character::complete::{digit1, multispace0};
use nom7::combinator::{complete, opt};
use nom7::error::{make_error, ErrorKind};
use nom7::sequence::{delimited, tuple};
use nom7::{Err, IResult};
use std;
use std::ffi::{c_char, CString};
use std::str;

pub mod constant;
pub mod event;
pub mod ftp;
pub mod response;

// Receives 221,243
fn parse_ftp_port_v4(i: &[u8]) -> IResult<&[u8], (u16, String)> {
    let (i, part1_bytes) = take_while1(|c: u8| c.is_ascii_digit())(i)?;
    let (i, _) = tag(",")(i)?;
    let (i, part2_bytes) = take_while1(|c: u8| c.is_ascii_digit())(i)?;

    let part1_str = str::from_utf8(part1_bytes).unwrap();
    let part2_str = str::from_utf8(part2_bytes).unwrap();

    let part1: u16 = part1_str.parse().unwrap();
    let part2: u16 = part2_str.parse().unwrap();

    let port = part1
        .checked_mul(256)
        .and_then(|v| v.checked_add(part2))
        .ok_or_else(|| Err::Error(make_error(i, ErrorKind::Verify)))?;

    let port_str = format!("{}", port);
    Ok((i, (port, port_str)))
}

// PORT 192,168,0,13,234,10
pub fn ftp_active_port(i: &[u8]) -> IResult<&[u8], (u16, String)> {
    let (i, _) = tag("PORT")(i)?;
    let (i, _) = delimited(multispace0, digit1, multispace0)(i)?;
    let (i, _) = tuple((
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
    ))(i)?;

    parse_ftp_port_v4(i)
}

// 227 Entering Passive Mode (212,27,32,66,221,243).
pub fn ftp_pasv_response(i: &[u8]) -> IResult<&[u8], (u16, String)> {
    let (i, _) = tag("227")(i)?;
    let (i, _) = take_until("(")(i)?;
    let (i, _) = tag("(")(i)?;
    let (i, _) = tuple((
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
    ))(i)?;

    parse_ftp_port_v4(i)
}
// Receives:
// - EPSV: '|||487581|'
// - EPRT: '|<proto>|<IPv6 address|41813|'
fn parse_ftp_port_v6<'a>(
    i: &'a [u8], prefix: &[&str], suffix: Option<&str>,
) -> IResult<&'a [u8], (u16, &'a str)> {
    let mut input = i;

    for part in prefix {
        let (rest, _) = take_until(*part)(input)?;
        let (rest, _) = tag(*part)(rest)?;
        input = rest;
    }

    let (input, port_bytes) = take_while1(|c: u8| c.is_ascii_digit())(input)?;
    let port_str = str::from_utf8(port_bytes).unwrap();
    let port_num: u16 = port_str
        .parse()
        .map_err(|_| Err::Error(make_error(i, ErrorKind::Digit)))?;

    let input = if let Some(tag_suffix) = suffix {
        let (input, _) = tag(tag_suffix)(input)?;
        input
    } else {
        input
    };

    Ok((input, (port_num, port_str)))
}

// 229 Entering Extended Passive Mode (|||48758|).
pub fn ftp_epsv_response(i: &[u8]) -> IResult<&[u8], (u16, &str)> {
    let (i, _) = tag("229")(i)?;
    let (i, (port, port_str)) = parse_ftp_port_v6(i, &["|||"], Some("|)"))?;
    let (i, _) = opt(complete(tag(".")))(i)?;

    Ok((i, (port, port_str)))
}

// EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|
pub fn ftp_active_eprt(i: &[u8]) -> IResult<&[u8], (u16, &str)> {
    let (i, _) = tag("EPRT")(i)?;
    let (i, (port, port_str)) = parse_ftp_port_v6(i, &["|", "|", "|"], Some("|"))?;
    Ok((i, (port, port_str)))
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPPortFromPortResponse(
    input: *const u8, len: u32, dport_out: *mut u16,
) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let buf = build_slice!(input, len as usize);
    match ftp_active_port(buf) {
        Ok((_, (dport, dport_str))) => {
            *dport_out = dport;
            if let Ok(cstring) = CString::new(dport_str) {
                return cstring.into_raw();
            }
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("port incomplete: '{:?}'", buf);
        }
        Err(_) => {
            SCLogDebug!("port error on '{:?}'", buf);
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPPortFromPasvResponse(
    input: *const u8, len: u32, dport_out: *mut u16,
) -> *mut c_char {
    if input.is_null() || dport_out.is_null() {
        return std::ptr::null_mut();
    }
    let buf = build_slice!(input, len as usize);
    match ftp_pasv_response(buf) {
        Ok((_, (dport, dport_str))) => {
            *dport_out = dport;
            if let Ok(cstring) = CString::new(dport_str) {
                return cstring.into_raw();
            }
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("pasv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
        Err(_) => {
            SCLogDebug!("pasv error on '{:?}'", String::from_utf8_lossy(buf));
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPPortFromEprtResponse(
    input: *const u8, len: u32, dport_out: *mut u16,
) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let buf = build_slice!(input, len as usize);
    match ftp_active_eprt(buf) {
        Ok((_, (dport, dport_str))) => {
            *dport_out = dport;
            if let Ok(cstring) = CString::new(dport_str) {
                return cstring.into_raw();
            }
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("eprt incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
        Err(_) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPFreeDynamicPortString(dyn_port_str: *mut c_char) {
    if !dyn_port_str.is_null() {
        drop(CString::from_raw(dyn_port_str));
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPPortFromEpsvResponse(
    input: *const u8, len: u32, dport_out: *mut u16,
) -> *mut c_char {
    if input.is_null() || dport_out.is_null() {
        return std::ptr::null_mut();
    }
    let buf = build_slice!(input, len as usize);
    match ftp_epsv_response(buf) {
        Ok((_, (dport, dport_str))) => {
            *dport_out = dport;
            if let Ok(cstring) = CString::new(dport_str) {
                return cstring.into_raw();
            }
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
        Err(_) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
    }
    return std::ptr::null_mut();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pasv_response_valid() {
        let input = b"227 Entering Passive Mode (212,27,32,66,221,243).";
        let result = ftp_pasv_response(input);

        assert!(result.is_ok(), "parser should succeed");
        let (_, (port, port_str)) = result.unwrap();

        // Correct value is 221*256+243
        assert_eq!(port, 56819);
        assert_eq!(port_str, "56819");
    }

    #[test]
    fn test_epsv_response_valid() {
        let input = b"229 Entering Extended Passive Mode (|||48758|).";
        let result = ftp_epsv_response(input);
        assert!(result.is_ok(), "parser should succeed");
        let (_, (port, port_str)) = result.unwrap();
        assert_eq!(port, 48758);
        assert_eq!(port_str, "48758");
    }

    #[test]
    fn test_active_eprt_valid() {
        let input = b"EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|";
        let result = ftp_active_eprt(input);
        assert!(result.is_ok(), "parser should succeed");

        let (_, (port, port_str)) = result.unwrap();
        assert_eq!(port, 41813);
        assert_eq!(port_str, "41813");
    }

    #[test]
    fn test_active_port_valid() {
        let input = b"PORT 192,168,0,13,234,10";
        let result = ftp_active_port(input);
        assert!(result.is_ok(), "parser should succeed");

        let (_, (port, port_str)) = result.unwrap();
        // Correct value is 234*256+10
        assert_eq!(port, 59914);
        assert_eq!(port_str, "59914");
    }

    // A port that is too large for a u16.
    #[test]
    fn test_pasv_response_too_large() {
        let input = b"227 Entering Passive Mode (212,27,32,66,257,243).";
        let result = ftp_pasv_response(input);
        assert!(result.is_err());

        let input = b"227 Entering Passive Mode (212,27,32,66,255,65535).";
        let result = ftp_pasv_response(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_active_eprt_too_large() {
        let input = b"EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|81813|";
        let result = ftp_epsv_response(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_active_port_too_large() {
        let input = b"PORT 212,27,32,66,257,243";
        let port = ftp_active_port(input);
        assert!(port.is_err());

        let input = b"PORT 212,27,32,66,255,65535";
        let port = ftp_active_port(input);
        assert!(port.is_err());
    }
}
