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

extern crate nom;

use nom::character::complete::{digit1, multispace0};
use std::str;
use std;
use std::str::FromStr;

// We transform an integer string into a i64, ignoring surrounding whitespaces
// We look for a digit suite, and try to convert it.
// If either str::from_utf8 or FromStr::from_str fail,
// we fallback to the parens parser defined above
named!(getu16<u16>,
    map_res!(
      map_res!(
        delimited!(multispace0, digit1, multispace0),
        str::from_utf8
      ),
      FromStr::from_str
    )
);

named!(parse_u16<u16>,
    map_res!(map_res!(digit1, str::from_utf8), u16::from_str));


// PORT 192,168,0,13,234,10
named!(pub ftp_active_port<u16>,
       do_parse!(
            tag!("PORT") >>
            delimited!(multispace0, digit1, multispace0) >> tag!(",") >> digit1 >> tag!(",") >>
            digit1 >> tag!(",") >> digit1 >> tag!(",") >>
            part1: verify!(parse_u16, |&v| v <= std::u8::MAX as u16) >>
            tag!(",") >>
            part2: verify!(parse_u16, |&v| v <= std::u8::MAX as u16) >>
            (
                part1 * 256 + part2
            )
        )
);

// 227 Entering Passive Mode (212,27,32,66,221,243).
named!(pub ftp_pasv_response<u16>,
       do_parse!(
            tag!("227") >>
            take_until!("(") >>
            tag!("(") >>
            digit1 >> tag!(",") >> digit1 >> tag!(",") >>
            digit1 >> tag!(",") >> digit1 >> tag!(",") >>
            part1: verify!(getu16, |&v| v <= std::u8::MAX as u16) >>
            tag!(",") >>
            part2: verify!(getu16, |&v| v <= std::u8::MAX as u16) >>
            // may also be completed by a final point
            tag!(")") >> opt!(complete!(tag!("."))) >>
            (
                part1 * 256 + part2
            )
        )
);


#[no_mangle]
pub extern "C" fn rs_ftp_active_port(input: *const u8, len: u32) -> u16 {
    let buf = build_slice!(input, len as usize);
    match ftp_active_port(buf) {
        Ok((_, dport)) => {
            return dport;
        },
        Err(nom::Err::Incomplete(_)) => {
            SCLogDebug!("port incomplete: '{:?}'", buf);
        },
        Err(_) => {
            SCLogDebug!("port error on '{:?}'", buf);
        },
    }
    return 0;
}


#[no_mangle]
pub extern "C" fn rs_ftp_pasv_response(input: *const u8, len: u32) -> u16 {
    let buf = unsafe{std::slice::from_raw_parts(input, len as usize)};
    match ftp_pasv_response(buf) {
        Ok((_, dport)) => {
            return dport;
        },
        Err(nom::Err::Incomplete(_)) => {
            SCLogDebug!("pasv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        },
        Err(_) => {
            SCLogDebug!("pasv error on '{:?}'", String::from_utf8_lossy(buf));
        },
    }
    return 0;
}

// 229 Entering Extended Passive Mode (|||48758|).
named!(pub ftp_epsv_response<u16>,
       do_parse!(
            tag!("229") >>
            take_until!("|||") >>
            tag!("|||") >>
            port: getu16 >>
            tag!("|)") >> opt!(complete!(tag!("."))) >>
            (
                port
            )
        )
);

// EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|
named!(pub ftp_active_eprt<u16>,
       do_parse!(
            tag!("EPRT") >>
            take_until_and_consume!("|") >>
            take_until_and_consume!("|") >>
            take_until_and_consume!("|") >>
            port: getu16 >>
            tag!("|") >>
            (
                port
            )
        )
);

#[no_mangle]
pub extern "C" fn rs_ftp_active_eprt(input: *const u8, len: u32) -> u16 {
    let buf = build_slice!(input, len as usize);
    match ftp_active_eprt(buf) {
        Ok((_, dport)) => {
            return dport;
        },
        Err(nom::Err::Incomplete(_)) => {
            SCLogDebug!("eprt incomplete: '{:?}'", String::from_utf8_lossy(buf));
        },
        Err(_) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        },

    }
    return 0;
}
#[no_mangle]
pub extern "C" fn rs_ftp_epsv_response(input: *const u8, len: u32) -> u16 {
    let buf = unsafe{std::slice::from_raw_parts(input, len as usize)};
    match ftp_epsv_response(buf) {
        Ok((_, dport)) => {
            return dport;
        },
        Err(nom::Err::Incomplete(_)) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        },
        Err(_) => {
            SCLogDebug!("epsv incomplete: '{:?}'", String::from_utf8_lossy(buf));
        },

    }
    return 0;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pasv_response_valid() {
        let port = ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,221,243).".as_bytes());
        assert_eq!(port, Ok((&b""[..], 56819)));
        let port_notdot = ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,221,243)".as_bytes());
        assert_eq!(port_notdot, Ok((&b""[..], 56819)));

        let port_epsv_dot = ftp_epsv_response("229 Entering Extended Passive Mode (|||48758|).".as_bytes());
        assert_eq!(port_epsv_dot, Ok((&b""[..], 48758)));
        let port_epsv_nodot = ftp_epsv_response("229 Entering Extended Passive Mode (|||48758|)".as_bytes());
        assert_eq!(port_epsv_nodot, Ok((&b""[..], 48758)));
    }

    #[test]
    fn test_active_eprt_valid() {
        let port = ftp_active_eprt("EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|".as_bytes());
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
        let port = ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,257,243).".as_bytes());
        assert!(port.is_err());

        let port = ftp_pasv_response("227 Entering Passive Mode (212,27,32,66,255,65535).".as_bytes());
        assert!(port.is_err());
    }

    #[test]
    fn test_active_eprt_too_large() {
        let port = ftp_active_eprt("EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|81813|".as_bytes());
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
