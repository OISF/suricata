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

// Author: Jeff Lucovsky <jlucovsky@oisf.net>

use crate::detect_parser::error::RuleParseError;
use crate::detect_parser::parser::{parse_token, take_until_whitespace};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use nom7::bytes::complete::tag;
use nom7::character::complete::multispace0;
use nom7::sequence::preceded;
use nom7::{Err, IResult};
use std::str;

pub const DETECT_BYTEMATH_FLAG_RELATIVE: u32 = 0x01;
pub const DETECT_BYTEMATH_FLAG_STRING: u32 = 0x02;
pub const DETECT_BYTEMATH_FLAG_BITMASK: u32 = 0x04;
pub const DETECT_BYTEMATH_FLAG_ENDIAN: u32 = 0x08;
pub const DETECT_BYTEMATH_FLAG_RVALUE_VAR: u32 = 0x10;

// Ensure required values are provided
const DETECT_BYTEMATH_FLAG_NBYTES: u32 = 0x1;
const DETECT_BYTEMATH_FLAG_OFFSET: u32 = 0x2;
const DETECT_BYTEMATH_FLAG_OPER: u32 = 0x4;
const DETECT_BYTEMATH_FLAG_RVALUE: u32 = 0x8;
const DETECT_BYTEMATH_FLAG_RESULT: u32 = 0x10;
const DETECT_BYTEMATH_FLAG_REQUIRED: u32 = DETECT_BYTEMATH_FLAG_RESULT
    | DETECT_BYTEMATH_FLAG_RVALUE
    | DETECT_BYTEMATH_FLAG_NBYTES
    | DETECT_BYTEMATH_FLAG_OFFSET
    | DETECT_BYTEMATH_FLAG_OPER;

// operator: +, -, /, *, <<, >>
pub const DETECT_BYTEMATH_OPERATOR_NONE: u8 = 1;
pub const DETECT_BYTEMATH_OPERATOR_PLUS: u8 = 2;
pub const DETECT_BYTEMATH_OPERATOR_MINUS: u8 = 3;
pub const DETECT_BYTEMATH_OPERATOR_DIVIDE: u8 = 4;
pub const DETECT_BYTEMATH_OPERATOR_MULTIPLY: u8 = 5;
pub const DETECT_BYTEMATH_OPERATOR_LSHIFT: u8 = 6;
pub const DETECT_BYTEMATH_OPERATOR_RSHIFT: u8 = 7;

// endian <big|little|dce>
pub const DETECT_BYTEMATH_ENDIAN_NONE: u8 = 0;
pub const DETECT_BYTEMATH_ENDIAN_BIG: u8 = 1;
pub const DETECT_BYTEMATH_ENDIAN_LITTLE: u8 = 2;
pub const DETECT_BYTEMATH_ENDIAN_DCE: u8 = 3;
pub const DETECT_BYTEMATH_ENDIAN_DEFAULT: u8 = DETECT_BYTEMATH_ENDIAN_BIG;

pub const DETECT_BYTEMATH_BASE_HEX: u8 = 16;
pub const DETECT_BYTEMATH_BASE_DEC: u8 = 10;
pub const DETECT_BYTEMATH_BASE_OCT: u8 = 8;
pub const DETECT_BYTEMATH_BASE_NONE: u8 = 0;
pub const DETECT_BYTEMATH_BASE_DEFAULT: u8 = DETECT_BYTEMATH_BASE_DEC;

// Fixed position parameter count: bytes, offset, oper, rvalue, result
// result is not parsed with the fixed position parameters as it's
// often swapped with optional parameters
pub const DETECT_BYTEMATH_FIXED_PARAM_COUNT: u8 = 5;
// Optional parameters: endian, relative, string, dce, bitmask
pub const DETECT_BYTEMATH_MAX_PARAM_COUNT: u8 = 10;

#[derive(Debug)]
enum ResultValue {
    Numeric(u64),
    String(String),
}

#[derive(Debug)]
#[repr(C)]
pub struct DetectByteMathData {
    rvalue_str: *const c_char,
    result: *const c_char,
    rvalue: u32,
    flags: u32,
    offset: i32,
    bitmask_val: u32,
    bitmask_shift_count: u16,
    id: u16,
    local_id: u8,
    nbytes: u8,
    oper: u8,
    endian: u8, // big, little, dce
    base: u8,   // From string or dce
}

impl Default for DetectByteMathData {
    fn default() -> Self {
        DetectByteMathData {
            local_id: 0,
            flags: 0,
            nbytes: 0,
            offset: 0,
            oper: 0,
            rvalue_str: std::ptr::null_mut(),
            rvalue: 0,
            result: std::ptr::null_mut(),
            endian: DETECT_BYTEMATH_ENDIAN_DEFAULT,
            base: DETECT_BYTEMATH_BASE_DEFAULT,
            bitmask_val: 0,
            bitmask_shift_count: 0,
            id: 0,
        }
    }
}

impl DetectByteMathData {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

fn get_string_value(value: &str) -> Result<u8, ()> {
    let res = match value {
        "hex" => DETECT_BYTEMATH_BASE_HEX,
        "oct" => DETECT_BYTEMATH_BASE_OCT,
        "dec" => DETECT_BYTEMATH_BASE_DEC,
        _ => return Err(()),
    };

    Ok(res)
}

fn get_oper_value(value: &str) -> Result<u8, ()> {
    let res = match value {
        "+" => DETECT_BYTEMATH_OPERATOR_PLUS,
        "-" => DETECT_BYTEMATH_OPERATOR_MINUS,
        "/" => DETECT_BYTEMATH_OPERATOR_DIVIDE,
        "*" => DETECT_BYTEMATH_OPERATOR_MULTIPLY,
        "<<" => DETECT_BYTEMATH_OPERATOR_LSHIFT,
        ">>" => DETECT_BYTEMATH_OPERATOR_RSHIFT,
        _ => return Err(()),
    };

    Ok(res)
}

fn get_endian_value(value: &str) -> Result<u8, ()> {
    let res = match value {
        "big" => 1,
        "little" => 2,
        _ => return Err(()),
    };

    Ok(res)
}

// Parsed as a u64 for validation with u32 {min,max}
fn parse_rvalue(input: &str) -> IResult<&str, ResultValue, RuleParseError<&str>> {
    let (input, rvalue) = parse_token(input)?;
    if let Ok(val) = rvalue.parse::<u64>() {
        Ok((input, ResultValue::Numeric(val)))
    } else {
        Ok((input, ResultValue::String(rvalue.to_string())))
    }
}

fn parse_bytemath(input: &str) -> IResult<&str, DetectByteMathData, RuleParseError<&str>> {
    // Inner utility function for easy error creation.
    fn make_error(reason: String) -> nom7::Err<RuleParseError<&'static str>> {
        Err::Error(RuleParseError::InvalidByteMath(reason))
    }
    let (_, values) = nom7::multi::separated_list1(
        tag(","),
        preceded(multispace0, nom7::bytes::complete::is_not(",")),
    )(input)?;

    if values.len() < DETECT_BYTEMATH_FIXED_PARAM_COUNT as usize
        || values.len() > DETECT_BYTEMATH_MAX_PARAM_COUNT as usize
    {
        return Err(make_error(format!("Incorrect argument string; at least {} values must be specified but no more than {}: {:?}",
            DETECT_BYTEMATH_FIXED_PARAM_COUNT, DETECT_BYTEMATH_MAX_PARAM_COUNT, input)));
    }

    let mut required_flags: u32 = 0;
    let mut byte_math = DetectByteMathData::new();
    for value in &values[0..] {
        let (val, name) = take_until_whitespace(value)?;
        match name.trim() {
            "oper" => {
                byte_math.oper = match get_oper_value(val.trim()) {
                    Ok(val) => val,
                    Err(_) => {
                        return Err(make_error(format!("unknown oper value {}", val)));
                    }
                };
                required_flags |= DETECT_BYTEMATH_FLAG_OPER;
            }
            "result" => {
                let tmp: String = val
                    .trim()
                    .parse()
                    .map_err(|_| make_error(format!("invalid result: {}", val)))?;
                byte_math.result = CString::new(tmp).unwrap().into_raw();
                required_flags |= DETECT_BYTEMATH_FLAG_RESULT;
            }
            "rvalue" => {
                let (_, res) = match parse_rvalue(val.trim()) {
                    Ok(val) => val,
                    Err(_) => {
                        return Err(make_error(format!("invalid rvalue value: {}", val)));
                    }
                };
                match res {
                    ResultValue::Numeric(val) => {
                        if val > u32::MIN.into() && val <= u32::MAX.into() {
                            byte_math.rvalue = val as u32
                        } else {
                            return Err(make_error(format!(
                                "invalid rvalue value: must be between {} and {}: {}",
                                1,
                                u32::MAX,
                                val
                            )));
                        }
                    }
                    ResultValue::String(val) => {
                        byte_math.rvalue_str = CString::new(val).unwrap().into_raw();
                        byte_math.flags |= DETECT_BYTEMATH_FLAG_RVALUE_VAR;
                    }
                }
                required_flags |= DETECT_BYTEMATH_FLAG_RVALUE;
            }
            "endian" => {
                if 0 != (byte_math.flags & DETECT_BYTEMATH_FLAG_ENDIAN) {
                    return Err(make_error("endianess already set".to_string()));
                }
                byte_math.endian = match get_endian_value(val.trim()) {
                    Ok(val) => val,
                    Err(_) => {
                        return Err(make_error(format!("invalid endian value: {}", val)));
                    }
                };
                byte_math.flags |= DETECT_BYTEMATH_FLAG_ENDIAN;
            }
            "string" => {
                byte_math.base = match get_string_value(val.trim()) {
                    Ok(val) => val,
                    Err(_) => {
                        return Err(make_error(format!("invalid string value: {}", val)));
                    }
                };
                byte_math.flags |= DETECT_BYTEMATH_FLAG_STRING;
            }
            "relative" => {
                byte_math.flags |= DETECT_BYTEMATH_FLAG_RELATIVE;
            }
            "dce" => {
                if 0 != (byte_math.flags & DETECT_BYTEMATH_FLAG_ENDIAN) {
                    return Err(make_error("endianess already set".to_string()));
                }
                byte_math.flags |= DETECT_BYTEMATH_FLAG_ENDIAN;
                byte_math.endian = DETECT_BYTEMATH_ENDIAN_DCE;
            }
            "bitmask" => {
                let val = val.trim();
                let trimmed = if val.starts_with("0x") || val.starts_with("0X") {
                    &val[2..]
                } else {
                    val
                };

                let val = u32::from_str_radix(trimmed, 16)
                    .map_err(|_| make_error(format!("invalid bitmask value: {}", value)))?;
                byte_math.bitmask_val = val;
                byte_math.flags |= DETECT_BYTEMATH_FLAG_BITMASK;
            }
            "offset" => {
                byte_math.offset = val
                    .trim()
                    .parse::<i32>()
                    .map_err(|_| make_error(format!("invalid offset value: {}", val)))?;
                if byte_math.offset > 65535 || byte_math.offset < -65535 {
                    return Err(make_error(format!(
                        "invalid offset value: must be between -65535 and 65535: {}",
                        val
                    )));
                }
                required_flags |= DETECT_BYTEMATH_FLAG_OFFSET;
            }
            "bytes" => {
                byte_math.nbytes = val
                    .trim()
                    .parse()
                    .map_err(|_| make_error(format!("invalid bytes value: {}", val)))?;
                if byte_math.nbytes < 1 || byte_math.nbytes > 10 {
                    return Err(make_error(format!(
                        "invalid bytes value: must be between 1 and 10: {}",
                        byte_math.nbytes
                    )));
                }
                required_flags |= DETECT_BYTEMATH_FLAG_NBYTES;
            }
            _ => {
                return Err(make_error(format!("unknown byte_math keyword: {}", name)));
            }
        };
    }

    // Ensure required values are present
    if (required_flags & DETECT_BYTEMATH_FLAG_REQUIRED) != DETECT_BYTEMATH_FLAG_REQUIRED {
        return Err(make_error(format!(
            "required byte_math parameters missing: \"{:?}\"",
            input
        )));
    }

    match byte_math.oper {
        DETECT_BYTEMATH_OPERATOR_LSHIFT | DETECT_BYTEMATH_OPERATOR_RSHIFT => {
            if byte_math.nbytes > 4 {
                return Err(make_error(format!("nbytes must be 1 through 4 (inclusive) when used with \"<<\" or \">>\"; {} is not valid", byte_math.nbytes)));
            }
        }
        _ => {}
    };
    Ok((input, byte_math))
}

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn ScByteMathParse(c_arg: *const c_char) -> *mut DetectByteMathData {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }

    let arg = match CStr::from_ptr(c_arg).to_str() {
        Ok(arg) => arg,
        Err(_) => {
            return std::ptr::null_mut();
        }
    };
    match parse_bytemath(arg) {
        Ok(detect) => return Box::into_raw(Box::new(detect.1)) as *mut DetectByteMathData,
        Err(_) => return std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ScByteMathFree(ptr: *mut DetectByteMathData) {
    if !ptr.is_null() {
        let bmd = Box::from_raw(ptr as *mut DetectByteMathData);
        if !bmd.result.is_null() {
            let _ = Box::from_raw(bmd.result as *mut *const c_char);
        }
        if !bmd.rvalue_str.is_null() {
            let _ = Box::from_raw(bmd.rvalue_str as *mut *const c_char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // structure equality only used by test cases
    impl PartialEq for DetectByteMathData {
        fn eq(&self, other: &Self) -> bool {
            let mut res: bool = false;

            if !self.rvalue_str.is_null() && !other.rvalue_str.is_null() {
                let s_val = unsafe { CStr::from_ptr(self.rvalue_str) };
                let o_val = unsafe { CStr::from_ptr(other.rvalue_str) };
                res = s_val == o_val;
            } else if !self.rvalue_str.is_null() || !other.rvalue_str.is_null() {
                return false;
            }

            if !self.result.is_null() && !self.result.is_null() {
                let s_val = unsafe { CStr::from_ptr(self.result) };
                let o_val = unsafe { CStr::from_ptr(other.result) };
                res = s_val == o_val;
            } else if !self.result.is_null() || !self.result.is_null() {
                return false;
            }

            !res || self.local_id == other.local_id
                && self.nbytes == other.nbytes
                && self.oper == other.oper
                && self.rvalue == other.rvalue
                && self.flags == other.flags
                && self.endian == other.endian
                && self.base == other.base
                && self.bitmask_val == other.bitmask_val
                && self.bitmask_shift_count == other.bitmask_shift_count
                && self.id == other.id
        }
    }

    fn valid_test(
        args: &str, nbytes: u8, offset: i32, oper: u8, rvalue_str: &str, rvalue: u32, result: &str,
        base: u8, endian: u8, bitmask_val: u32, flags: u32,
    ) {
        let bmd = DetectByteMathData {
            nbytes: nbytes,
            offset: offset,
            oper: oper,
            rvalue_str: if rvalue_str != "" {
                CString::new(rvalue_str).unwrap().into_raw()
            } else {
                std::ptr::null_mut()
            },
            rvalue: rvalue,
            result: CString::new(result).unwrap().into_raw(),
            base: base,
            endian: endian,
            bitmask_val: bitmask_val,
            flags: flags,
            ..Default::default()
        };

        match parse_bytemath(args) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parser_valid() {
        valid_test(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result myresult, dce, string dec",
            4,
            3933,
            DETECT_BYTEMATH_OPERATOR_PLUS,
            "myrvalue",
            0,
            "myresult",
            DETECT_BYTEMATH_BASE_DEC,
            DETECT_BYTEMATH_ENDIAN_DCE,
            0,
            DETECT_BYTEMATH_FLAG_RVALUE_VAR
                | DETECT_BYTEMATH_FLAG_STRING
                | DETECT_BYTEMATH_FLAG_ENDIAN,
        );

        valid_test(
            "bytes 4, offset 3933, oper +, rvalue 99, result other, dce, string dec",
            4,
            3933,
            DETECT_BYTEMATH_OPERATOR_PLUS,
            "",
            99,
            "other",
            DETECT_BYTEMATH_BASE_DEC,
            DETECT_BYTEMATH_ENDIAN_DCE,
            0,
            DETECT_BYTEMATH_FLAG_STRING | DETECT_BYTEMATH_FLAG_ENDIAN,
        );

        valid_test(
            "bytes 4, offset -3933, oper +, rvalue myrvalue, result foo",
            4,
            -3933,
            DETECT_BYTEMATH_OPERATOR_PLUS,
            "rvalue",
            0,
            "foo",
            DETECT_BYTEMATH_BASE_DEFAULT,
            DETECT_BYTEMATH_ENDIAN_DEFAULT,
            0,
            DETECT_BYTEMATH_FLAG_RVALUE_VAR,
        );

        // Out of order
        valid_test(
            "string dec, endian big, result other, rvalue 99, oper +, offset 3933, bytes 4",
            4,
            3933,
            DETECT_BYTEMATH_OPERATOR_PLUS,
            "",
            99,
            "other",
            DETECT_BYTEMATH_BASE_DEC,
            DETECT_BYTEMATH_ENDIAN_BIG,
            0,
            DETECT_BYTEMATH_FLAG_STRING | DETECT_BYTEMATH_FLAG_ENDIAN,
        );
    }

    #[test]
    fn test_parser_string_valid() {
        let mut bmd = DetectByteMathData {
            nbytes: 4,
            offset: 3933,
            oper: DETECT_BYTEMATH_OPERATOR_PLUS,
            rvalue_str: CString::new("myrvalue").unwrap().into_raw(),
            rvalue: 0,
            result: CString::new("foo").unwrap().into_raw(),
            endian: DETECT_BYTEMATH_ENDIAN_DEFAULT,
            base: DETECT_BYTEMATH_BASE_DEC,
            flags: DETECT_BYTEMATH_FLAG_RVALUE_VAR | DETECT_BYTEMATH_FLAG_STRING,
            ..Default::default()
        };

        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, string dec",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.flags = DETECT_BYTEMATH_FLAG_RVALUE_VAR;
        bmd.base = DETECT_BYTEMATH_BASE_DEFAULT;
        match parse_bytemath("bytes 4, offset 3933, oper +, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.flags = DETECT_BYTEMATH_FLAG_RVALUE_VAR | DETECT_BYTEMATH_FLAG_STRING;
        bmd.base = DETECT_BYTEMATH_BASE_HEX;
        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, string hex",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.base = DETECT_BYTEMATH_BASE_OCT;
        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, string oct",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parser_string_invalid() {
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, string decimal"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, string hexadecimal"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, string octal"
            )
            .is_err()
        );
    }

    #[test]
    // bytes must be between 1 and 10; when combined with rshift/lshift, must be 4 or less
    fn test_parser_bytes_invalid() {
        assert_eq!(
            true,
            parse_bytemath("bytes 0, offset 3933, oper +, rvalue myrvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 11, offset 3933, oper +, rvalue myrvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 5, offset 3933, oper >>, rvalue myrvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 5, offset 3933, oper <<, rvalue myrvalue, result foo").is_err()
        );
    }

    #[test]
    fn test_parser_bitmask_invalid() {
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask 0x")
                .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask x12345678"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask X12345678"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask 0x123456789012"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask 0q")
                .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask maple"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask 0xGHIJKLMN"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask #*#*@-"
            )
            .is_err()
        );
    }

    #[test]
    fn test_parser_bitmask_valid() {
        let mut bmd = DetectByteMathData {
            nbytes: 4,
            offset: 3933,
            oper: DETECT_BYTEMATH_OPERATOR_PLUS,
            rvalue_str: CString::new("myrvalue").unwrap().into_raw(),
            rvalue: 0,
            result: CString::new("foo").unwrap().into_raw(),
            endian: DETECT_BYTEMATH_ENDIAN_BIG,
            base: DETECT_BYTEMATH_BASE_DEFAULT,
            flags: DETECT_BYTEMATH_FLAG_RVALUE_VAR | DETECT_BYTEMATH_FLAG_BITMASK,
            ..Default::default()
        };

        bmd.bitmask_val = 0x12345678;
        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask 0x12345678",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.bitmask_val = 0xffff1234;
        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask ffff1234",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.bitmask_val = 0xffff1234;
        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, bitmask 0Xffff1234",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }
    #[test]
    fn test_parser_endian_valid() {
        let mut bmd = DetectByteMathData {
            nbytes: 4,
            offset: 3933,
            oper: DETECT_BYTEMATH_OPERATOR_PLUS,
            rvalue_str: CString::new("myrvalue").unwrap().into_raw(),
            rvalue: 0,
            result: CString::new("foo").unwrap().into_raw(),
            endian: DETECT_BYTEMATH_ENDIAN_BIG,
            base: DETECT_BYTEMATH_BASE_DEFAULT,
            flags: DETECT_BYTEMATH_FLAG_RVALUE_VAR | DETECT_BYTEMATH_FLAG_ENDIAN,
            ..Default::default()
        };

        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, endian big",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.endian = DETECT_BYTEMATH_ENDIAN_LITTLE;
        match parse_bytemath(
            "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, endian little",
        ) {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.endian = DETECT_BYTEMATH_ENDIAN_DCE;
        match parse_bytemath("bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, dce") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.endian = DETECT_BYTEMATH_ENDIAN_DEFAULT;
        bmd.flags = DETECT_BYTEMATH_FLAG_RVALUE_VAR;
        match parse_bytemath("bytes 4, offset 3933, oper +, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parser_endian_invalid() {
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, endian bigger"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, endian smaller"
            )
            .is_err()
        );

        // endianess can only be specified once
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, endian big, dce"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, endian small, endian big"
            )
            .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath(
                "bytes 4, offset 3933, oper +, rvalue myrvalue, result foo, endian small, dce"
            )
            .is_err()
        );
    }

    #[test]
    fn test_parser_oper_valid() {
        let mut bmd = DetectByteMathData {
            nbytes: 4,
            offset: 3933,
            oper: DETECT_BYTEMATH_OPERATOR_PLUS,
            rvalue_str: CString::new("myrvalue").unwrap().into_raw(),
            rvalue: 0,
            result: CString::new("foo").unwrap().into_raw(),
            endian: DETECT_BYTEMATH_ENDIAN_BIG,
            base: DETECT_BYTEMATH_BASE_DEFAULT,
            flags: DETECT_BYTEMATH_FLAG_RVALUE_VAR,
            ..Default::default()
        };

        match parse_bytemath("bytes 4, offset 3933, oper +, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.oper = DETECT_BYTEMATH_OPERATOR_MINUS;
        match parse_bytemath("bytes 4, offset 3933, oper -, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.oper = DETECT_BYTEMATH_OPERATOR_MULTIPLY;
        match parse_bytemath("bytes 4, offset 3933, oper *, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
        bmd.oper = DETECT_BYTEMATH_OPERATOR_DIVIDE;
        match parse_bytemath("bytes 4, offset 3933, oper /, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
        bmd.oper = DETECT_BYTEMATH_OPERATOR_RSHIFT;
        match parse_bytemath("bytes 4, offset 3933, oper >>, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
        bmd.oper = DETECT_BYTEMATH_OPERATOR_LSHIFT;
        match parse_bytemath("bytes 4, offset 3933, oper <<, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parser_oper_invalid() {
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper !, rvalue myvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper ^, rvalue myvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper <>, rvalue myvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper ><, rvalue myvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper <, rvalue myvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper >, rvalue myvalue, result foo").is_err()
        );
    }

    #[test]
    fn test_parser_rvalue_valid() {
        let mut bmd = DetectByteMathData {
            nbytes: 4,
            offset: 47303,
            oper: DETECT_BYTEMATH_OPERATOR_MULTIPLY,
            rvalue_str: std::ptr::null_mut(),
            rvalue: 4294967295,
            result: CString::new("foo").unwrap().into_raw(),
            endian: DETECT_BYTEMATH_ENDIAN_DEFAULT,
            base: DETECT_BYTEMATH_BASE_DEFAULT,
            ..Default::default()
        };

        match parse_bytemath("bytes 4, offset 47303, oper *, rvalue 4294967295, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.rvalue = 1;
        match parse_bytemath("bytes 4, offset 47303, oper *, rvalue 1, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parser_rvalue_invalid() {
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 47303, oper *, rvalue 4294967296, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 47303, oper +, rvalue 0, result foo").is_err()
        );
    }

    #[test]
    fn test_parser_offset_valid() {
        let mut bmd = DetectByteMathData {
            nbytes: 4,
            offset: -65535,
            oper: DETECT_BYTEMATH_OPERATOR_MULTIPLY,
            rvalue_str: CString::new("myrvalue").unwrap().into_raw(),
            rvalue: 0,
            result: CString::new("foo").unwrap().into_raw(),
            endian: DETECT_BYTEMATH_ENDIAN_DEFAULT,
            base: DETECT_BYTEMATH_BASE_DEFAULT,
            flags: DETECT_BYTEMATH_FLAG_RVALUE_VAR,
            ..Default::default()
        };

        match parse_bytemath("bytes 4, offset -65535, oper *, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }

        bmd.offset = 65535;
        match parse_bytemath("bytes 4, offset 65535, oper *, rvalue myrvalue, result foo") {
            Ok((_, val)) => {
                assert_eq!(val, bmd);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    // offset: numeric values must be between -65535 and 65535
    fn test_parser_offset_invalid() {
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset -70000, oper *, rvalue myvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 70000, oper +, rvalue myvalue, result foo").is_err()
        );
    }

    #[test]
    fn test_parser_incomplete_args() {
        assert_eq!(true, parse_bytemath("").is_err());
        assert_eq!(true, parse_bytemath("bytes 4").is_err());
        assert_eq!(true, parse_bytemath("bytes 4, offset 0").is_err());
        assert_eq!(true, parse_bytemath("bytes 4, offset 0, oper <<").is_err());
    }

    #[test]
    fn test_parser_missing_required() {
        assert_eq!(
            true,
            parse_bytemath("endian big, offset 3933, oper +, rvalue myrvalue, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, endian big, oper +, rvalue myrvalue, result foo,").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 3933, endian big, rvalue myrvalue, result foo")
                .is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 3933, oper +, endian big, result foo").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 3933, oper +, rvalue myrvalue, endian big").is_err()
        );
    }

    #[test]
    fn test_parser_invalid_args() {
        assert_eq!(true, parse_bytemath("monkey banana").is_err());
        assert_eq!(true, parse_bytemath("bytes nan").is_err());
        assert_eq!(true, parse_bytemath("bytes 4, offset nan").is_err());
        assert_eq!(true, parse_bytemath("bytes 4, offset 0, three 3, four 4, five 5, six 6, seven 7, eight 8, nine 9, ten 10, eleven 11").is_err());
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper ><, rvalue myrvalue").is_err()
        );
        assert_eq!(
            true,
            parse_bytemath("bytes 4, offset 0, oper +, rvalue myrvalue, endian endian").is_err()
        );
    }
}
