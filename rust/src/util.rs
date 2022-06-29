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

use std::ffi::CStr;
use std::os::raw::c_char;

use nom7::bytes::complete::take_while1;
use nom7::character::complete::char;
use nom7::character::{is_alphabetic, is_alphanumeric};
use nom7::combinator::verify;
use nom7::multi::many1_count;
use nom7::IResult;

#[no_mangle]
pub unsafe extern "C" fn rs_check_utf8(val: *const c_char) -> bool {
    CStr::from_ptr(val).to_str().is_ok()
}

fn is_alphanumeric_or_hyphen(chr: u8) -> bool {
    return is_alphanumeric(chr) || chr == b'-';
}

fn parse_domain_label(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = verify(take_while1(is_alphanumeric_or_hyphen), |x: &[u8]| {
        is_alphabetic(x[0]) && x[x.len() - 1] != b'-'
    })(i)?;
    return Ok((i, ()));
}

fn parse_subdomain(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = parse_domain_label(input)?;
    let (input, _) = char('.')(input)?;
    return Ok((input, ()));
}

fn parse_domain(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = many1_count(parse_subdomain)(input)?;
    let (input, _) = many1_count(parse_domain_label)(input)?;
    return Ok((input, ()));
}

#[no_mangle]
pub unsafe extern "C" fn rs_validate_domain(input: *const u8, in_len: u32) -> u32 {
    let islice = build_slice!(input, in_len as usize);
    match parse_domain(islice) {
        Ok((rem, _)) => {
            return (islice.len() - rem.len()) as u32;
        }
        _ => {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_domain() {
        let buf0: &[u8] = "a-1.oisf.net more".as_bytes();
        let r0 = parse_domain(buf0);
        match r0 {
            Ok((rem, _)) => {
                // And we should have 5 bytes left.
                assert_eq!(rem.len(), 5);
            }
            _ => {
                panic!("Result should have been ok.");
            }
        }
        let buf1: &[u8] = "justatext".as_bytes();
        let r1 = parse_domain(buf1);
        match r1 {
            Ok((_, _)) => {
                panic!("Result should not have been ok.");
            }
            _ => {}
        }
        let buf1: &[u8] = "1.com".as_bytes();
        let r1 = parse_domain(buf1);
        match r1 {
            Ok((_, _)) => {
                panic!("Result should not have been ok.");
            }
            _ => {}
        }
        let buf1: &[u8] = "a-.com".as_bytes();
        let r1 = parse_domain(buf1);
        match r1 {
            Ok((_, _)) => {
                panic!("Result should not have been ok.");
            }
            _ => {}
        }
        let buf1: &[u8] = "a(x)y.com".as_bytes();
        let r1 = parse_domain(buf1);
        match r1 {
            Ok((_, _)) => {
                panic!("Result should not have been ok.");
            }
            _ => {}
        }
    }
}
