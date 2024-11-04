/* Copyright (C) 2024 Open Information Security Foundation
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

// Author: Jeff Lucovsky <jlucovsky@oisf.net>

use crate::detect::error::RuleParseError;
use crate::detect::parser::{parse_var, take_until_whitespace, ResultValue};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::ffi::base64::Base64Mode;

use nom7::bytes::complete::tag;
use nom7::character::complete::multispace0;
use nom7::sequence::preceded;
use nom7::{Err, IResult};
use std::str;

pub const TRANSFORM_FROM_BASE64_MODE_DEFAULT: Base64Mode = Base64Mode::Base64ModeRFC4648;

const DETECT_TRANSFORM_BASE64_MAX_PARAM_COUNT: usize = 3;
pub const DETECT_TRANSFORM_BASE64_FLAG_MODE: u8 = 0x01;
pub const DETECT_TRANSFORM_BASE64_FLAG_NBYTES: u8 = 0x02;
pub const DETECT_TRANSFORM_BASE64_FLAG_OFFSET: u8 = 0x04;
pub const DETECT_TRANSFORM_BASE64_FLAG_OFFSET_VAR: u8 = 0x08;
pub const DETECT_TRANSFORM_BASE64_FLAG_NBYTES_VAR: u8 = 0x10;

#[repr(C)]
#[derive(Debug)]
pub struct SCDetectTransformFromBase64Data {
    flags: u8,
    nbytes: u32,
    nbytes_str: *const c_char,
    offset: u32,
    offset_str: *const c_char,
    mode: Base64Mode,
}

impl Drop for SCDetectTransformFromBase64Data {
    fn drop(&mut self) {
        unsafe {
            if !self.offset_str.is_null() {
                let _ = CString::from_raw(self.offset_str as *mut c_char);
            }
            if !self.nbytes_str.is_null() {
                let _ = CString::from_raw(self.nbytes_str as *mut c_char);
            }
        }
    }
}
impl Default for SCDetectTransformFromBase64Data {
    fn default() -> Self {
        SCDetectTransformFromBase64Data {
            flags: 0,
            nbytes: 0,
            nbytes_str: std::ptr::null_mut(),
            offset: 0,
            offset_str: std::ptr::null_mut(),
            mode: TRANSFORM_FROM_BASE64_MODE_DEFAULT,
        }
    }
}

impl SCDetectTransformFromBase64Data {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

fn get_mode_value(value: &str) -> Option<Base64Mode> {
    let res = match value {
        "rfc4648" => Some(Base64Mode::Base64ModeRFC4648),
        "rfc2045" => Some(Base64Mode::Base64ModeRFC2045),
        "strict" => Some(Base64Mode::Base64ModeStrict),
        _ => None,
    };

    res
}

fn parse_transform_base64(
    input: &str,
) -> IResult<&str, SCDetectTransformFromBase64Data, RuleParseError<&str>> {
    // Inner utility function for easy error creation.
    fn make_error(reason: String) -> nom7::Err<RuleParseError<&'static str>> {
        Err::Error(RuleParseError::InvalidTransformBase64(reason))
    }
    let mut transform_base64 = SCDetectTransformFromBase64Data::new();

    // No options so return defaults
    if input.is_empty() {
        return Ok((input, transform_base64));
    }
    let (_, values) = nom7::multi::separated_list1(
        tag(","),
        preceded(multispace0, nom7::bytes::complete::is_not(",")),
    )(input)?;

    // Too many options?
    if values.len() > DETECT_TRANSFORM_BASE64_MAX_PARAM_COUNT {
        return Err(make_error(format!("Incorrect argument string; at least 1 value must be specified but no more than {}: {:?}",
            DETECT_TRANSFORM_BASE64_MAX_PARAM_COUNT, input)));
    }

    for value in values {
        let (mut val, mut name) = take_until_whitespace(value)?;
        val = val.trim();
        name = name.trim();
        match name {
            "mode" => {
                if 0 != (transform_base64.flags & DETECT_TRANSFORM_BASE64_FLAG_MODE) {
                    return Err(make_error("mode already set".to_string()));
                }
                if let Some(mode) = get_mode_value(val) {
                    transform_base64.mode = mode;
                } else {
                    return Err(make_error(format!("invalid mode value: {}", val)));
                }
                transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_MODE;
            }

            "offset" => {
                if 0 != (transform_base64.flags & DETECT_TRANSFORM_BASE64_FLAG_OFFSET) {
                    return Err(make_error("offset already set".to_string()));
                }

                let (_, res) = parse_var(val)?;
                match res {
                    ResultValue::Numeric(val) => {
                        if val <= u16::MAX.into() {
                            transform_base64.offset = val as u32
                        } else {
                            return Err(make_error(format!(
                                "invalid offset value: must be between 0 and {}: {}",
                                u16::MAX, val
                            )));
                        }
                    }
                    ResultValue::String(val) => match CString::new(val) {
                        Ok(newval) => {
                            transform_base64.offset_str = newval.into_raw();
                            transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_OFFSET_VAR;
                        }
                        _ => {
                            return Err(make_error(
                                "parse string not safely convertible to C".to_string(),
                            ))
                        }
                    },
                }

                transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_OFFSET;
            }

            "bytes" => {
                if 0 != (transform_base64.flags & DETECT_TRANSFORM_BASE64_FLAG_NBYTES) {
                    return Err(make_error("bytes already set".to_string()));
                }
                let (_, res) = parse_var(val)?;
                match res {
                    ResultValue::Numeric(val) => {
                        if val as u32 <= u16::MAX.into() {
                            transform_base64.nbytes = val as u32
                        } else {
                            return Err(make_error(format!(
                                "invalid bytes value: must be between {} and {}: {}",
                                0, u16::MAX, val
                            )));
                        }
                    }
                    ResultValue::String(val) => match CString::new(val) {
                        Ok(newval) => {
                            transform_base64.nbytes_str = newval.into_raw();
                            transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_NBYTES_VAR;
                        }
                        _ => {
                            return Err(make_error(
                                "parse string not safely convertible to C".to_string(),
                            ))
                        }
                    },
                }
                transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_NBYTES;
            }
            _ => {
                return Err(make_error(format!("unknown base64 keyword: {}", name)));
            }
        };
    }

    Ok((input, transform_base64))
}

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn SCTransformBase64Parse(
    c_arg: *const c_char,
) -> *mut SCDetectTransformFromBase64Data {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }

    let arg = CStr::from_ptr(c_arg)
        .to_str()
        .unwrap_or("");

    match parse_transform_base64(arg) {
        Ok((_, detect)) => return Box::into_raw(Box::new(detect)),
        Err(_) => return std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCTransformBase64Free(ptr: *mut SCDetectTransformFromBase64Data) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // structure equality only used by test cases
    impl PartialEq for SCDetectTransformFromBase64Data {
        fn eq(&self, other: &Self) -> bool {
            let mut res: bool = true;

            if !self.nbytes_str.is_null() && !other.nbytes_str.is_null() {
                let s_val = unsafe { CStr::from_ptr(self.nbytes_str) };
                let o_val = unsafe { CStr::from_ptr(other.nbytes_str) };
                res = s_val == o_val;
            } else if !self.nbytes_str.is_null() || !other.nbytes_str.is_null() {
                return false;
            }

            if !self.offset_str.is_null() && !other.offset_str.is_null() {
                let s_val = unsafe { CStr::from_ptr(self.offset_str) };
                let o_val = unsafe { CStr::from_ptr(other.offset_str) };
                res = s_val == o_val;
            } else if !self.offset_str.is_null() || !other.offset_str.is_null() {
                return false;
            }

            res && self.nbytes == other.nbytes
                && self.flags == other.flags
                && self.offset == other.offset
                && self.mode == other.mode
        }
    }

    fn valid_test(
        args: &str,
        nbytes: u32,
        nbytes_str: &str,
        offset: u32,
        offset_str: &str,
        mode: Base64Mode,
        flags: u8,
    ) {
        let tbd = SCDetectTransformFromBase64Data {
            flags,
            nbytes,
            nbytes_str: if !nbytes_str.is_empty() {
                CString::new(nbytes_str).unwrap().into_raw()
            } else {
                std::ptr::null_mut()
            },
            offset,
            offset_str: if !offset_str.is_empty() {
                CString::new(offset_str).unwrap().into_raw()
            } else {
                std::ptr::null_mut()
            },
            mode,
        };

        let (_, val) = parse_transform_base64(args).unwrap();
        assert_eq!(val, tbd);
    }

    #[test]
    fn test_parser_invalid() {
        assert!(parse_transform_base64("bytes 4, offset 3933, mode unknown").is_err());
        assert!(parse_transform_base64("bytes 4, offset 70000, mode strict").is_err());
        assert!(
            parse_transform_base64("bytes 4, offset 70000, mode strict, mode rfc2045").is_err()
        );
    }

    #[test]
    fn test_parser_parse_partial_valid() {
        let mut tbd = SCDetectTransformFromBase64Data {
            nbytes: 4,
            offset: 0,
            mode: TRANSFORM_FROM_BASE64_MODE_DEFAULT,
            flags: 0,
            ..Default::default()
        };

        tbd.mode = TRANSFORM_FROM_BASE64_MODE_DEFAULT;
        tbd.flags = DETECT_TRANSFORM_BASE64_FLAG_NBYTES;
        let (_, val) = parse_transform_base64("bytes 4").unwrap();
        assert_eq!(val, tbd);

        tbd.offset = 3933;
        tbd.flags = DETECT_TRANSFORM_BASE64_FLAG_NBYTES | DETECT_TRANSFORM_BASE64_FLAG_OFFSET;
        let (_, val) = parse_transform_base64("bytes 4, offset 3933").unwrap();
        assert_eq!(val, tbd);

        tbd.flags = DETECT_TRANSFORM_BASE64_FLAG_NBYTES | DETECT_TRANSFORM_BASE64_FLAG_OFFSET;
        let (_, val) = parse_transform_base64("offset 3933, bytes 4").unwrap();
        assert_eq!(val, tbd);

        tbd.flags = DETECT_TRANSFORM_BASE64_FLAG_MODE;
        tbd.mode = Base64Mode::Base64ModeRFC2045;
        tbd.offset = 0;
        tbd.nbytes = 0;
        let (_, val) = parse_transform_base64("mode rfc2045").unwrap();
        assert_eq!(val, tbd);
    }

    #[test]
    fn test_parser_parse_valid() {
        valid_test("", 0, "", 0, "", TRANSFORM_FROM_BASE64_MODE_DEFAULT, 0);

        valid_test(
            "bytes 4, offset 3933, mode strict",
            4,
            "",
            3933,
            "",
            Base64Mode::Base64ModeStrict,
            DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                | DETECT_TRANSFORM_BASE64_FLAG_MODE,
        );

        valid_test(
            "bytes 4, offset 3933, mode rfc2045",
            4,
            "",
            3933,
            "",
            Base64Mode::Base64ModeRFC2045,
            DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                | DETECT_TRANSFORM_BASE64_FLAG_MODE,
        );

        valid_test(
            "bytes 4, offset 3933, mode rfc4648",
            4,
            "",
            3933,
            "",
            Base64Mode::Base64ModeRFC4648,
            DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                | DETECT_TRANSFORM_BASE64_FLAG_MODE,
        );

        valid_test(
            "bytes 4, offset var, mode rfc4648",
            4,
            "",
            0,
            "var",
            Base64Mode::Base64ModeRFC4648,
            DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                | DETECT_TRANSFORM_BASE64_FLAG_OFFSET_VAR
                | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                | DETECT_TRANSFORM_BASE64_FLAG_MODE,
        );

        valid_test(
            "bytes var, offset 3933, mode rfc4648",
            0,
            "var",
            3933,
            "",
            Base64Mode::Base64ModeRFC4648,
            DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                | DETECT_TRANSFORM_BASE64_FLAG_NBYTES_VAR
                | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                | DETECT_TRANSFORM_BASE64_FLAG_MODE,
        );
    }
}
