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

use std::borrow::Cow;
use std::ffi::CStr;
use std::os::raw::c_char;

use nom8::bytes::complete::take_while1;
use nom8::character::complete::char;
use nom8::combinator::verify;
use nom8::multi::many1_count;
use nom8::{AsChar, IResult, Parser};

use humantime::parse_duration;

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

/// Add 's' suffix if input is only digits, and convert to lowercase if needed.
fn duration_unit_normalize(input: &str) -> Cow<'_, str> {
    if input.bytes().all(|b| b.is_ascii_digit()) {
        let mut owned = String::with_capacity(input.len() + 1);
        owned.push_str(input);
        owned.push('s');
        return Cow::Owned(owned);
    }

    if input.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(input.to_ascii_lowercase())
    } else {
        Cow::Borrowed(input)
    }
}

/// Reads a C string from `input`, parses it, and writes the result to `*res`.
/// Returns 0 on success (result written to *res), -1 otherwise.
#[no_mangle]
pub unsafe extern "C" fn SCParseTimeDuration(input: *const c_char, res: *mut u64) -> i32 {
    if input.is_null() || res.is_null() {
        return -1;
    }

    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let trimmed = input_str.trim();
    if trimmed.is_empty() {
        return -1;
    }

    let normalized = duration_unit_normalize(trimmed);
    match parse_duration(normalized.as_ref()) {
        Ok(duration) => {
            *res = duration.as_secs();
            0
        }
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::ffi::CString;
    use std::ptr::{null, null_mut};

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
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 10);

            let s = CString::new("0").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 0);

            let s = CString::new("2H").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 7200);

            let s = CString::new("1 day").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 86400);

            let s = CString::new("1w").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 604800);

            let s = CString::new("1 week").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 604800);

            let s = CString::new("1y").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 31557600);

            let s = CString::new("1 year").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, 31557600);

            // max
            let s = CString::new("18446744073709551615").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), 0);
            assert_eq!(v, u64::MAX);
        }
    }

    #[test]
    fn test_parse_time_duration_invalid() {
        unsafe {
            let mut v: u64 = 0;
            let s = CString::new("10q").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), -1);

            let s = CString::new("abc").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), -1);

            let s = CString::new("-300s").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), -1);

            let s = CString::new("1h -600s").unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), -1);

            assert_eq!(SCParseTimeDuration(null(), &mut v), -1);
            assert_eq!(SCParseTimeDuration(s.as_ptr(), null_mut()), -1);

            let overflow_years = (u64::MAX / 31557600) + 1;
            let s = CString::new(format!("{}y", overflow_years)).unwrap();
            assert_eq!(SCParseTimeDuration(s.as_ptr(), &mut v), -1);
        }
    }
}
