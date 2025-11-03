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

//! Utility module.

use std::ffi::CStr;
use std::os::raw::c_char;

use nom8::bytes::complete::take_while1;
use nom8::character::complete::char;
use nom8::combinator::verify;
use nom8::multi::many1_count;
use nom8::{AsChar, IResult, Parser};

#[no_mangle]
pub unsafe extern "C" fn SCCheckUtf8(val: *const c_char) -> bool {
    CStr::from_ptr(val).to_str().is_ok()
}

fn is_alphanumeric_or_hyphen(chr: u8) -> bool {
    return chr.is_alphanum() || chr == b'-';
}

fn parse_domain_label(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = verify(take_while1(is_alphanumeric_or_hyphen), |x: &[u8]| {
        x[0].is_alpha() && x[x.len() - 1] != b'-'
    }).parse(i)?;
    return Ok((i, ()));
}

fn parse_subdomain(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = parse_domain_label(input)?;
    let (input, _) = char('.').parse(input)?;
    return Ok((input, ()));
}

fn parse_domain(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = many1_count(parse_subdomain).parse(input)?;
    let (input, _) = parse_domain_label(input)?;
    return Ok((input, ()));
}

#[no_mangle]
pub unsafe extern "C" fn SCValidateDomain(input: *const u8, in_len: u32) -> u32 {
    let islice = build_slice!(input, in_len as usize);
    if let Ok((rem, _)) = parse_domain(islice) {
        return (islice.len() - rem.len()) as u32;
    }
    return 0;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_domain() {
        let buf0: &[u8] = "a-1.oisf.net more".as_bytes();
        let (rem, _) = parse_domain(buf0).unwrap();
        // And we should have 5 bytes left.
        assert_eq!(rem.len(), 5);
        let buf1: &[u8] = "justatext".as_bytes();
        assert!(parse_domain(buf1).is_err());
        let buf1: &[u8] = "1.com".as_bytes();
        assert!(parse_domain(buf1).is_err());
        let buf1: &[u8] = "a-.com".as_bytes();
        assert!(parse_domain(buf1).is_err());
        let buf1: &[u8] = "a(x)y.com".as_bytes();
        assert!(parse_domain(buf1).is_err());
    }
}
