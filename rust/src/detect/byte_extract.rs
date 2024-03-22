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
use crate::detect::parser::{parse_token, take_until_whitespace};
use crate::detect::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use nom7::bytes::complete::tag;
use nom7::character::complete::multispace0;
use nom7::sequence::preceded;
use nom7::{Err, IResult};
use std::str;

pub const DETECT_BYTE_EXTRACT_FLAG_RELATIVE: u16 = 0x01;
pub const DETECT_BYTE_EXTRACT_FLAG_STRING: u16 = 0x02;
pub const DETECT_BYTE_EXTRACT_FLAG_ALIGN: u16 = 0x04;
pub const DETECT_BYTE_EXTRACT_FLAG_ENDIAN: u16 = 0x08;
pub const DETECT_BYTE_EXTRACT_FLAG_SLICE: u16 = 0x10;
pub const DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER: u16 = 0x20;
pub const DETECT_BYTE_EXTRACT_FLAG_NBYTES: u16 = 0x40;
pub const DETECT_BYTE_EXTRACT_FLAG_OFFSET: u16 = 0x80;
pub const DETECT_BYTE_EXTRACT_FLAG_BASE: u16 = 0x100;

pub const DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT: u16 = 1;
const DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT: ByteEndian = ByteEndian::BigEndian;

const BASE_DEFAULT: ByteBase = ByteBase::BaseDec;

// Fixed position parameter count: bytes, offset, variable
pub const DETECT_BYTE_EXTRACT_FIXED_PARAM_COUNT: usize = 3;
// Optional parameters: endian, relative, string, dce, slice, align, multiplier
pub const DETECT_BYTE_EXTRACT_MAX_PARAM_COUNT: usize = 10;

#[derive(Debug)]
enum ResultValue {
    Numeric(u64),
    String(String),
}

#[repr(C)]
#[derive(Debug)]
pub struct SCDetectByteExtractData {
    local_id: u8,
    nbytes: u8,
    offset: i16,
    name: *const c_char,
    flags: u16,
    endian: ByteEndian, // big, little, dce
    base: ByteBase,     // From string or dce
    align_value: u8,
    multiplier_value: u16,
    id: u16,
}

impl Drop for SCDetectByteExtractData {
    fn drop(&mut self) {
        unsafe {
            if !self.name.is_null() {
                let _ = CString::from_raw(self.name as *mut c_char);
            }
        }
    }
}

impl Default for SCDetectByteExtractData {
    fn default() -> Self {
        SCDetectByteExtractData {
            local_id: 0,
            nbytes: 0,
            offset: 0,
            name: std::ptr::null_mut(),
            flags: 0,
            endian: DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT, // big, little, dce
            base: BASE_DEFAULT,                         // From string or dce
            align_value: 0,
            multiplier_value: DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT,
            id: 0,
        }
    }
}

// Parsed as a u64 for validation with u32 {min,max} so values greater than uint32
// are not treated as a string value.
fn parse_var(input: &str) -> IResult<&str, ResultValue, RuleParseError<&str>> {
    let (input, value) = parse_token(input)?;
    if let Ok(val) = value.parse::<u64>() {
        Ok((input, ResultValue::Numeric(val)))
    } else {
        Ok((input, ResultValue::String(value.to_string())))
    }
}

fn parse_byteextract(input: &str) -> IResult<&str, SCDetectByteExtractData, RuleParseError<&str>> {
    // Inner utility function for easy error creation.
    fn make_error(reason: String) -> nom7::Err<RuleParseError<&'static str>> {
        Err::Error(RuleParseError::InvalidByteExtract(reason))
    }
    let (_, values) = nom7::multi::separated_list1(
        tag(","),
        preceded(multispace0, nom7::bytes::complete::is_not(",")),
    )(input)?;

    if values.len() < DETECT_BYTE_EXTRACT_FIXED_PARAM_COUNT
        || values.len() > DETECT_BYTE_EXTRACT_MAX_PARAM_COUNT
    {
        return Err(make_error(format!("Incorrect argument string; at least {} values must be specified but no more than {}: {:?}",
            DETECT_BYTE_EXTRACT_FIXED_PARAM_COUNT, DETECT_BYTE_EXTRACT_MAX_PARAM_COUNT, input)));
    }

    let mut byte_extract = { SCDetectByteExtractData {
        nbytes: values[0].parse::<u8>()
        .map_err(|_| make_error(format!("invalid nbytes value: {}", values[0])))?, ..Default::default() } };

    let value = values[1]
        .parse::<i32>()
        .map_err(|_| make_error(format!("invalid offset value: {}", values[1])))?;
    if value >= i16::MIN.into() && value <= i16::MAX.into() {
        byte_extract.offset = value as i16;
    } else {
        return Err(make_error(format!(
            "invalid offset value: must be between {} and {}: {}",
            i16::MIN,
            i16::MAX,
            value
        )));
    }

    let value = values[2];
    let (_, res) = parse_var(value)?;
    match res {
        ResultValue::String(value) => match CString::new(value) {
            Ok(newval) => {
                byte_extract.name = newval.into_raw();
            }
            _ => {
                return Err(make_error(
                    "parse string not safely convertible to C".to_string(),
                ))
            }
        },
        _ => {
            return Err(make_error(
                "parse string not safely convertible to C".to_string(),
            ))
        }
    }

    for value in values.iter().skip(DETECT_BYTE_EXTRACT_FIXED_PARAM_COUNT) {
        let (mut val, mut name) = take_until_whitespace(value)?;
        val = val.trim();
        name = name.trim();
        match name {
            "align" => {
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_ALIGN) {
                    return Err(make_error("align already set".to_string()));
                }
                byte_extract.align_value = val
                    .parse::<u8>()
                    .map_err(|_| make_error(format!("invalid align value: {}", val)))?;
                if !(byte_extract.align_value == 2 || byte_extract.align_value == 4) {
                    return Err(make_error(format!(
                        "invalid align value: must be 2 or 4: {}",
                        val
                    )));
                }
                byte_extract.flags |= DETECT_BYTE_EXTRACT_FLAG_ALIGN;
            }
            "slice" => {
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_SLICE) {
                    return Err(make_error("slice already set".to_string()));
                }
                byte_extract.flags |= DETECT_BYTE_EXTRACT_FLAG_SLICE;
            }
            "dce" | "big" | "little" => {
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN) {
                    return Err(make_error("endianess already set".to_string()));
                }
                byte_extract.endian = match get_endian_value(name) {
                    Some(val) => val,
                    None => {
                        return Err(make_error(format!("invalid endian value: {}", val)));
                    }
                };
                byte_extract.flags |= DETECT_BYTE_EXTRACT_FLAG_ENDIAN;
            }
            "string" => {
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_STRING) {
                    return Err(make_error("string already set".to_string()));
                }
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_BASE) {
                    return Err(make_error(
                        "base specified before string; use \"string, base\"".to_string(),
                    ));
                }
                byte_extract.flags |= DETECT_BYTE_EXTRACT_FLAG_STRING;
            }
            "oct" | "dec" | "hex" => {
                if 0 == (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_STRING) {
                    return Err(make_error("string must be set first".to_string()));
                }
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_BASE) {
                    return Err(make_error("base already set".to_string()));
                }
                byte_extract.base = match get_string_value(name) {
                    Some(val) => val,
                    None => {
                        return Err(make_error(format!("invalid string value: {}", val)));
                    }
                };
                byte_extract.flags |= DETECT_BYTE_EXTRACT_FLAG_BASE;
            }
            "relative" => {
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE) {
                    return Err(make_error("relative already set".to_string()));
                }
                byte_extract.flags |= DETECT_BYTE_EXTRACT_FLAG_RELATIVE;
            }
            "multiplier" => {
                if 0 != (byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER) {
                    return Err(make_error("multiplier already set".to_string()));
                }
                let mult = val
                    .parse::<u32>()
                    .map_err(|_| make_error(format!("invalid multiplier value: {}", val)))?;
                if mult == 0 || mult > u16::MAX.into() {
                    return Err(make_error(format!(
                        "invalid multiplier value: must be between 0 and {}: {}",
                        u16::MAX,
                        val
                    )));
                }
                byte_extract.multiplier_value = mult as u16;
                byte_extract.flags |= DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER;
            }
            _ => {
                return Err(make_error(format!("unknown byte_extract option: {}", name)));
            }
        };
    }

    // string w/out base: default is set to decimal so no error

    // base w/out string
    if 0 != byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_BASE
        && (0 == byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_STRING)
    {
        return Err(make_error("must specify string with base".to_string()));
    }

    if 0 != byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_STRING
        && 0 != byte_extract.flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN
    {
        return Err(make_error(
            "can't specify string and an endian value".to_string(),
        ));
    }

    if (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_SLICE)
        == (byte_extract.flags & (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_SLICE))
    {
        return Err(make_error(
            "string and slice are mutually exclusive".to_string(),
        ));
    }

    Ok((input, byte_extract))
}

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn SCByteExtractParse(c_arg: *const c_char) -> *mut SCDetectByteExtractData {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }

    let arg = match CStr::from_ptr(c_arg).to_str() {
        Ok(arg) => arg,
        Err(_) => {
            return std::ptr::null_mut();
        }
    };
    match parse_byteextract(arg) {
        Ok((_, detect)) => return Box::into_raw(Box::new(detect)),
        Err(_) => return std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCByteExtractFree(ptr: *mut SCDetectByteExtractData) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // structure equality only used by test cases
    impl PartialEq for SCDetectByteExtractData {
        fn eq(&self, other: &Self) -> bool {
            let mut res: bool = false;

            if !self.name.is_null() && !other.name.is_null() {
                let s_val = unsafe { CStr::from_ptr(self.name) };
                let o_val = unsafe { CStr::from_ptr(other.name) };
                res = s_val == o_val;
            } else if !self.name.is_null() || !other.name.is_null() {
                return false;
            }

            res && self.local_id == other.local_id
                && self.nbytes == other.nbytes
                && self.offset == other.offset
                && self.flags == other.flags
                && self.endian == other.endian
                && self.base == other.base
                && self.align_value == other.align_value
                && self.multiplier_value == other.multiplier_value
                && self.id == other.id
        }
    }

    fn valid_test(
        args: &str,
        nbytes: u8,
        offset: i16,
        var_name_str: &str,
        base: ByteBase,
        endian: ByteEndian,
        align_value: u8,
        multiplier_value: u16,
        flags: u16,
    ) {
        let bed = SCDetectByteExtractData {
            nbytes,
            offset,
            name: if !var_name_str.is_empty() {
                CString::new(var_name_str).unwrap().into_raw()
            } else {
                std::ptr::null_mut()
            },
            base,
            endian,
            align_value,
            multiplier_value,
            flags,
            ..Default::default()
        };

        let (_, val) = parse_byteextract(args).unwrap();
        assert_eq!(val, bed);
    }

    #[test]
    fn parser_valid() {
        assert!(parse_byteextract("4, 2, one").is_ok());
        assert!(parse_byteextract("4, 2, one, relative").is_ok());
        assert!(parse_byteextract("4, 2, one, relative, multiplier 10").is_ok());
        assert!(parse_byteextract("4, 2, one, big").is_ok());
        assert!(parse_byteextract("4, 2, one, little").is_ok());
        assert!(parse_byteextract("4, 2, one, dce").is_ok());
        assert!(parse_byteextract("4, 2, one, string").is_ok());
        assert!(parse_byteextract("4, 2, one, string, hex").is_ok());
        assert!(parse_byteextract("4, 2, one, string, dec").is_ok());
        assert!(parse_byteextract("4, 2, one, string, oct").is_ok());
        assert!(parse_byteextract("4, 2, one, align 4").is_ok());
        assert!(parse_byteextract("4, 2, one, align 4, relative").is_ok());
        assert!(parse_byteextract("4, 2, one, align 2, relative").is_ok());
        assert!(parse_byteextract("4, 2, one, align 4, relative, big").is_ok());
        assert!(parse_byteextract("4, 2, one, align 4, relative, dce").is_ok());
        assert!(parse_byteextract("4, 2, one, align 4, relative, little").is_ok());
        assert!(parse_byteextract("4, 2, one, align 4, relative, little, multiplier 2").is_ok());
        assert!(
            parse_byteextract("4, 2, one, align 4, relative, little, multiplier 2, slice").is_ok()
        );
    }
    #[test]
    // Invalid token combinations
    fn parser_invalid() {
        assert!(parse_byteextract("4").is_err());
        assert!(parse_byteextract("4, 2").is_err());
        assert!(parse_byteextract("4, 65536").is_err());
        assert!(parse_byteextract("4, -65536").is_err());
        assert!(parse_byteextract("4, 2, one, align 4, align 4").is_err());
        assert!(parse_byteextract("4, 2, one, relative, relative").is_err());
        assert!(parse_byteextract("4, 2, one, hex").is_err());
        assert!(parse_byteextract("4, 2, one, dec").is_err());
        assert!(parse_byteextract("4, 2, one, oct").is_err());
        assert!(parse_byteextract("4, 2, one, little, little").is_err());
        assert!(parse_byteextract("4, 2, one, slice, slice").is_err());
        assert!(parse_byteextract("4, 2, one, multiplier").is_err());
        assert!(parse_byteextract("4, 2, one, multiplier 0").is_err());
        assert!(parse_byteextract("4, 2, one, multiplier 65536").is_err());
        assert!(parse_byteextract("4, 2, one, multiplier 2, multiplier 2").is_err());
        assert!(parse_byteextract(
            "4, 2, one, align 4, relative, little, multiplier 2, string hex"
        )
        .is_err());
    }

    #[test]
    fn test_parser_valid() {
        valid_test(
            "4, 2, one",
            4,
            2,
            "one",
            BASE_DEFAULT,
            DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT,
            0,
            DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT,
            0,
        );
        valid_test(
            "4, 2, one, relative",
            4,
            2,
            "one",
            BASE_DEFAULT,
            DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT,
            0,
            DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT,
            DETECT_BYTE_EXTRACT_FLAG_RELATIVE,
        );
        valid_test(
            "4, 2, one, string",
            4,
            2,
            "one",
            BASE_DEFAULT,
            DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT,
            0,
            DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT,
            DETECT_BYTE_EXTRACT_FLAG_STRING,
        );
        valid_test(
            "4, 2, one, string, hex",
            4,
            2,
            "one",
            ByteBase::BaseHex,
            DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT,
            0,
            DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT,
            DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING,
        );
        valid_test(
            "4, 2, one, dce",
            4,
            2,
            "one",
            BASE_DEFAULT,
            ByteEndian::EndianDCE,
            0,
            DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT,
            DETECT_BYTE_EXTRACT_FLAG_ENDIAN,
        );
        valid_test(
            "4, 2, one, align 4, relative, little, multiplier 2, slice",
            4,
            2,
            "one",
            ByteBase::BaseDec,
            ByteEndian::LittleEndian,
            4,
            2,
            DETECT_BYTE_EXTRACT_FLAG_ENDIAN
                | DETECT_BYTE_EXTRACT_FLAG_RELATIVE
                | DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER
                | DETECT_BYTE_EXTRACT_FLAG_ALIGN
                | DETECT_BYTE_EXTRACT_FLAG_SLICE,
        );
    }
}
