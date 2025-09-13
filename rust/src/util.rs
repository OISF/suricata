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

use nom7::bytes::complete::take_while1;
use nom7::character::complete::char;
use nom7::character::{is_alphabetic, is_alphanumeric};
use nom7::combinator::verify;
use nom7::multi::many1_count;
use nom7::IResult;

use parse_duration::parse;
use parse_duration::parse::Error;

#[no_mangle]
pub unsafe extern "C" fn SCCheckUtf8(val: *const c_char) -> bool {
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
    use std::ffi::CString;

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

    #[test]
    fn test_parse_time_valid() {
        unsafe {
            let mut v: u64 = 0;

            let s = CString::new("10").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 10);

            let s = CString::new("0").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 0);

            let s = CString::new("2H").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 7200);

            assert_eq!(
                SCParseTimeDuration(std::ptr::null(), &mut v as *mut u64),
                -3
            );
            assert_eq!(SCParseTimeDuration(s.as_ptr(), std::ptr::null_mut()), -3);

            let s = CString::new("1 day").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 86400);

            let s = CString::new("1w").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 604800);

            let s = CString::new("1 week").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 604800);

            let s = CString::new("1y").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 31556952);

            let s = CString::new("1 year").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, 31556952);

            // max
            let s = CString::new("18446744073709551615").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);
            assert_eq!(v, u64::MAX);
        }
    }

    #[test]
    fn test_parse_time_duration_invalid() {
        unsafe {
            let mut v: u64 = 0;
            let s = CString::new("10q").unwrap();
            assert_ne!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);

            let s = CString::new("abc").unwrap();
            assert_ne!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), 0);

            let overflow_years = (u64::MAX / 31556952) + 1;
            let s = CString::new(format!("{}y", overflow_years)).unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v as *mut u64), -1);
        }
    }
}

/// Reads a C string from `input`, parses it, and writes the result to `*res`.
/// Returns:
/// - 0 on success (result written to *res)
/// - -1 on overflow
/// - -2 on invalid format
/// - -3 on NULL pointer
#[no_mangle]
pub unsafe extern "C" fn SCParseTimeDuration(input: *const c_char, res: *mut u64) -> i32 {
    if input.is_null() || res.is_null() {
        return -3;
    }

    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match parse(input_str) {
        Ok(duration) => {
            *res = duration.as_secs();
            return 0;
        }
        Err(Error::OutOfBounds(_)) => return -1,  // Overflow
        Err(Error::ParseInt(_)) => return -2,     // Invalid number format
        Err(Error::UnknownUnit(_)) => return -2,  // Unrecognized unit
        Err(Error::NoUnitFound(_)) => return -2,  // Missing unit when required
        Err(Error::NoValueFound(_)) => return -2, // Empty or whitespace-only
    }
}
