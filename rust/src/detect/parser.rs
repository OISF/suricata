/* Copyright (C) 2022 Open Information Security Foundation
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

use crate::detect::error::RuleParseError;

use nom7::bytes::complete::is_not;
use nom7::character::complete::multispace0;
use nom7::sequence::preceded;
use nom7::IResult;
use std::ffi::CString;
use std::os::raw::c_char;

#[derive(Debug)]
pub enum ResultValue {
    Numeric(u64),
    String(String),
}

static WHITESPACE: &str = " \t\r\n";
/// Parse all characters up until the next whitespace character.
pub fn take_until_whitespace(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    nom7::bytes::complete::is_not(WHITESPACE)(input)
}

// Parsed as a u64 so the value can be validated against a u32 min/max if needed.
pub fn parse_var(input: &str) -> IResult<&str, ResultValue, RuleParseError<&str>> {
    let (input, value) = parse_token(input)?;
    if let Ok(val) = value.parse::<u64>() {
        Ok((input, ResultValue::Numeric(val)))
    } else {
        Ok((input, ResultValue::String(value.to_string())))
    }
}
/// Parse the next token ignoring leading whitespace.
///
/// A token is the next sequence of chars until a terminating character. Leading whitespace
/// is ignore.
pub fn parse_token(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    let terminators = "\n\r\t,;: ";
    preceded(multispace0, is_not(terminators))(input)
}

#[no_mangle]
/// Trim whitespace from a single-token value, e.g.,
/// "      some-value    " --> returns "somevalue"
pub unsafe extern "C" fn SCParseToken(c_arg: *const c_char, len: usize) -> *mut c_char {
    if c_arg.is_null() || len == 0 {
        return std::ptr::null_mut();
    }

    let bytes = std::slice::from_raw_parts(c_arg as *const u8, len);

    if let Ok(s) = std::str::from_utf8(bytes) {
        let trimmed = s.trim();
        match CString::new(trimmed) {
            Ok(c_string) => return c_string.into_raw(),
            Err(_) => return std::ptr::null_mut(),
        }
    }

    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn SCFreeToken(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}
