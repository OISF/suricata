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

use nom7::bytes::complete::{tag, take_until};
use nom7::character::complete::{digit1, multispace0};
use nom7::combinator::{complete, map_res, opt, verify};
use nom7::sequence::{delimited, tuple};
use nom7::{Err, IResult};
use std;
use std::str;
use std::str::FromStr;

// We transform an integer string into a i64, ignoring surrounding whitespaces
// We look for a digit suite, and try to convert it.
// If either str::from_utf8 or FromStr::from_str fail,
// we fallback to the parens parser defined above
fn getu16(i: &[u8]) -> IResult<&[u8], u16> {
    map_res(
        map_res(delimited(multispace0, digit1, multispace0), str::from_utf8),
        FromStr::from_str,
    )(i)
}

fn parse_u16(i: &[u8]) -> IResult<&[u8], u16> {
    map_res(map_res(digit1, str::from_utf8), u16::from_str)(i)
}

// PORT 192,168,0,13,234,10
pub fn ftp_active_port(i: &[u8]) -> IResult<&[u8], u16> {
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
    let (i, part1) = verify(parse_u16, |&v| v <= std::u8::MAX as u16)(i)?;
    let (i, _) = tag(",")(i)?;
    let (i, part2) = verify(parse_u16, |&v| v <= std::u8::MAX as u16)(i)?;
    Ok((i, part1 * 256 + part2))
}

// 227 Entering Passive Mode (212,27,32,66,221,243).
pub fn ftp_pasv_response(i: &[u8]) -> IResult<&[u8], u16> {
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
    let (i, part1) = verify(getu16, |&v| v <= std::u8::MAX as u16)(i)?;
    let (i, _) = tag(",")(i)?;
    let (i, part2) = verify(getu16, |&v| v <= std::u8::MAX as u16)(i)?;
    // may also be completed by a final point
    let (i, _) = tag(")")(i)?;
    let (i, _) = opt(complete(tag(".")))(i)?;
    Ok((i, part1 * 256 + part2))
}

#[no_mangle]
pub unsafe extern "C" fn rs_ftp_active_port(input: *const u8, len: u32) -> u16 {
    let buf = build_slice!(input, len as usize);
    match ftp_active_port(buf) {
        Ok((_, dport)) => {
            return dport;
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("port incomplete: '{:?}'", buf);
        }
        Err(_) => {
            SCLogDebug!("port error on '{:?}'", buf);
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_ftp_pasv_response(input: *const u8, len: u32) -> u16 {
    let buf = std::slice::from_raw_parts(input, len as usize);
    match ftp_pasv_response(buf) {
        Ok((_, dport)) => {
            return dport;
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("pasv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
        Err(_) => {
            SCLogDebug!("pasv error on '{:?}'", String::from_utf8_lossy(buf));
        }
    }
    0
}

// 229 Entering Extended Passive Mode (|||48758|).
pub fn ftp_epsv_response(i: &[u8]) -> IResult<&[u8], u16> {
    let (i, _) = tag("229")(i)?;
    let (i, _) = take_until("|||")(i)?;
    let (i, _) = tag("|||")(i)?;
    let (i, port) = getu16(i)?;
    let (i, _) = tag("|)")(i)?;
    let (i, _) = opt(complete(tag(".")))(i)?;
    Ok((i, port))
}

// EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|
pub fn ftp_active_eprt(i: &[u8]) -> IResult<&[u8], u16> {
    let (i, _) = tag("EPRT")(i)?;
    let (i, _) = take_until("|")(i)?;
    let (i, _) = tag("|")(i)?;
    let (i, _) = take_until("|")(i)?;
    let (i, _) = tag("|")(i)?;
    let (i, _) = take_until("|")(i)?;
    let (i, _) = tag("|")(i)?;
    let (i, port) = getu16(i)?;
    let (i, _) = tag("|")(i)?;
    Ok((i, port))
}

#[no_mangle]
pub unsafe extern "C" fn rs_ftp_active_eprt(input: *const u8, len: u32) -> u16 {
    let buf = build_slice!(input, len as usize);
    match ftp_active_eprt(buf) {
        Ok((_, dport)) => {
            return dport;
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("eprt incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
        Err(_) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
    }
    0
}
#[no_mangle]
pub unsafe extern "C" fn rs_ftp_epsv_response(input: *const u8, len: u32) -> u16 {
    let buf = std::slice::from_raw_parts(input, len as usize);
    match ftp_epsv_response(buf) {
        Ok((_, dport)) => {
            return dport;
        }
        Err(Err::Incomplete(_)) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
        Err(_) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        }
    }
    0
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pasv_response_valid() {
        let port =
            ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,221,243).".as_bytes());
        assert_eq!(port, Ok((&b""[..], 56819)));
        let port_notdot =
            ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,221,243)".as_bytes());
        assert_eq!(port_notdot, Ok((&b""[..], 56819)));

        let port_epsv_dot =
            ftp_epsv_response("229 Entering Extended Passive Mode (|||48758|).".as_bytes());
        assert_eq!(port_epsv_dot, Ok((&b""[..], 48758)));
        let port_epsv_nodot =
            ftp_epsv_response("229 Entering Extended Passive Mode (|||48758|)".as_bytes());
        assert_eq!(port_epsv_nodot, Ok((&b""[..], 48758)));
    }

    #[test]
    fn test_active_eprt_valid() {
        let port =
            ftp_active_eprt("EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|".as_bytes());
        assert_eq!(port, Ok((&b""[..], 41813)));
    }

    #[test]
    fn test_active_port_valid() {
        let port = ftp_active_port("PORT 192,168,0,13,234,10".as_bytes());
        assert_eq!(port, Ok((&b""[..], 59914)));
    }

    // A port that is too large for a u16.
    #[test]
    fn test_pasv_response_too_large() {
        let port =
            ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,257,243).".as_bytes());
        assert!(port.is_err());

        let port =
            ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,255,65535).".as_bytes());
        assert!(port.is_err());
    }

    #[test]
    fn test_active_eprt_too_large() {
        let port =
            ftp_active_eprt("EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|81813|".as_bytes());
        assert!(port.is_err());
    }

    #[test]
    fn test_active_port_too_large() {
        let port = ftp_active_port("PORT 212,27,32,66,257,243".as_bytes());
        assert!(port.is_err());

        let port = ftp_active_port("PORT 212,27,32,66,255,65535".as_bytes());
        assert!(port.is_err());
    }
}
