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

use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag, tag_no_case, take_while};
use nom7::character::complete::{char, digit1, hex_digit1};
use nom7::combinator::{all_consuming, map_opt, opt, value, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::Err;
use nom7::IResult;

use super::EnumString;

use std::ffi::CStr;

#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(u8)]
pub enum DetectUintMode {
    DetectUintModeEqual,
    DetectUintModeLt,
    DetectUintModeLte,
    DetectUintModeGt,
    DetectUintModeGte,
    DetectUintModeRange,
    DetectUintModeNe,
    DetectUintModeNegRg,
    DetectUintModeBitmask,
    DetectUintModeNegBitmask,
}

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct DetectUintData<T> {
    pub arg1: T,
    pub arg2: T,
    pub mode: DetectUintMode,
}

/// Parses a string for detection with integers, using enumeration strings
///
/// Needs to specify T1 the integer type (like u8)
/// And the Enumeration for the stringer.
/// Will try to parse numerical value first, as any integer detection keyword
/// And if this fails, will resort to using the enumeration strings.
///
/// Returns Some DetectUintData on success, None on failure
pub fn detect_parse_uint_enum<T1: DetectIntType, T2: EnumString<T1>>(s: &str) -> Option<DetectUintData<T1>> {
    if let Ok((_, ctx)) = detect_parse_uint::<T1>(s) {
        return Some(ctx);
    }
    if let Some(enum_val) = T2::from_str(s) {
        let ctx = DetectUintData::<T1> {
            arg1: enum_val.into_u(),
            arg2: T1::min_value(),
            mode: DetectUintMode::DetectUintModeEqual,
        };
        return Some(ctx);
    }
    return None;
}

pub trait DetectIntType:
    std::str::FromStr
    + std::cmp::PartialOrd
    + num::PrimInt
    + num::Bounded
    + num::ToPrimitive
    + num::FromPrimitive
{
}
impl<T> DetectIntType for T where
    T: std::str::FromStr
        + std::cmp::PartialOrd
        + num::PrimInt
        + num::Bounded
        + num::ToPrimitive
        + num::FromPrimitive
{
}

pub fn detect_parse_uint_unit(i: &str) -> IResult<&str, u64> {
    let (i, unit) = alt((
        value(1024, tag_no_case("kb")),
        value(1024 * 1024, tag_no_case("mb")),
        value(1024 * 1024 * 1024, tag_no_case("gb")),
    ))(i)?;
    return Ok((i, unit));
}

pub fn detect_parse_uint_value_hex<T: DetectIntType>(i: &str) -> IResult<&str, T> {
    let (i, _) = tag("0x")(i)?;
    let (i, arg1s) = hex_digit1(i)?;
    match T::from_str_radix(arg1s, 16) {
        Ok(arg1) => Ok((i, arg1)),
        _ => Err(Err::Error(make_error(i, ErrorKind::Verify))),
    }
}

pub fn detect_parse_uint_value<T: DetectIntType>(i: &str) -> IResult<&str, T> {
    let (i, arg1) = alt((
        detect_parse_uint_value_hex,
        detect_parse_uint_with_unit,
    ))(i)?;
    Ok((i, arg1))
}

pub fn detect_parse_uint_with_unit<T: DetectIntType>(i: &str) -> IResult<&str, T> {
    let (i, arg1) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;
    let (i, unit) = opt(detect_parse_uint_unit)(i)?;
    if arg1 >= T::one() {
        if let Some(u) = unit {
            if T::max_value().to_u64().unwrap() / u < arg1.to_u64().unwrap() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
            let ru64 = arg1 * T::from_u64(u).unwrap();
            return Ok((i, ru64));
        }
    }
    Ok((i, arg1))
}

pub fn detect_parse_uint_start_equal<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;
    Ok((
        i,
        DetectUintData {
            arg1,
            arg2: T::min_value(),
            mode: DetectUintMode::DetectUintModeEqual,
        },
    ))
}

pub fn detect_parse_uint_start_interval<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, neg) = opt(char('!'))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = alt((tag("-"), tag("<>")))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = verify(detect_parse_uint_value, |x| {
        x > &arg1 && *x - arg1 > T::one()
    })(i)?;
    let mode = if neg.is_some() {
        DetectUintMode::DetectUintModeNegRg
    } else {
        DetectUintMode::DetectUintModeRange
    };
    Ok((
        i,
        DetectUintData {
            arg1,
            arg2,
            mode,
        },
    ))
}

pub fn detect_parse_uint_bitmask<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("&")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, neg) = opt(tag("!"))(i)?;
    let (i, _) = tag("=")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = detect_parse_uint_value(i)?;
    if arg2 & arg1 != arg2 {
        // could never match
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let mode = if neg.is_none() {
        DetectUintMode::DetectUintModeBitmask
    } else {
        DetectUintMode::DetectUintModeNegBitmask
    };
    Ok((
        i,
        DetectUintData {
            arg1,
            arg2,
            mode,
        },
    ))
}

fn detect_parse_uint_start_interval_inclusive<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, neg) = opt(char('!'))(i)?;
    let (i, arg1) = verify(detect_parse_uint_value::<T>, |x| {
        *x > T::min_value()
    })(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = alt((tag("-"), tag("<>")))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = verify(detect_parse_uint_value::<T>, |x| {
        *x > arg1 && *x < T::max_value()
    })(i)?;
    let mode = if neg.is_some() {
        DetectUintMode::DetectUintModeNegRg
    } else {
        DetectUintMode::DetectUintModeRange
    };
    Ok((
        i,
        DetectUintData {
            arg1: arg1 - T::one(),
            arg2: arg2 + T::one(),
            mode,
        },
    ))
}

pub fn detect_parse_uint_mode(i: &str) -> IResult<&str, DetectUintMode> {
    let (i, mode) = alt((
        value(DetectUintMode::DetectUintModeGte, tag(">=")),
        value(DetectUintMode::DetectUintModeLte, tag("<=")),
        value(DetectUintMode::DetectUintModeGt, tag(">")),
        value(DetectUintMode::DetectUintModeLt, tag("<")),
        value(DetectUintMode::DetectUintModeNe, tag("!=")),
        value(DetectUintMode::DetectUintModeNe, tag("!")),
        value(DetectUintMode::DetectUintModeEqual, tag("=")),
    ))(i)?;
    return Ok((i, mode));
}

fn detect_parse_uint_start_symbol<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, mode) = detect_parse_uint_mode(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;

    match mode {
        DetectUintMode::DetectUintModeNe => {}
        DetectUintMode::DetectUintModeLt => {
            if arg1 == T::min_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectUintMode::DetectUintModeLte => {
            if arg1 == T::max_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectUintMode::DetectUintModeGt => {
            if arg1 == T::max_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectUintMode::DetectUintModeGte => {
            if arg1 == T::min_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        _ => {
            return Err(Err::Error(make_error(i, ErrorKind::MapOpt)));
        }
    }

    Ok((
        i,
        DetectUintData {
            arg1,
            arg2: T::min_value(),
            mode,
        },
    ))
}

pub fn detect_match_uint<T: DetectIntType>(x: &DetectUintData<T>, val: T) -> bool {
    match x.mode {
        DetectUintMode::DetectUintModeEqual => {
            if val == x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeNe => {
            if val != x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeLt => {
            if val < x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeLte => {
            if val <= x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeGt => {
            if val > x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeGte => {
            if val >= x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeRange => {
            if val > x.arg1 && val < x.arg2 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeNegRg => {
            if val <= x.arg1 || val >= x.arg2 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeBitmask => {
            if val & x.arg1 == x.arg2 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeNegBitmask => {
            if val & x.arg1 != x.arg2 {
                return true;
            }
        }
    }
    return false;
}

pub fn detect_parse_uint_notending<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, uint) = alt((
        detect_parse_uint_bitmask,
        detect_parse_uint_start_interval,
        detect_parse_uint_start_equal,
        detect_parse_uint_start_symbol,
    ))(i)?;
    Ok((i, uint))
}

pub fn detect_parse_uint<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, uint) = detect_parse_uint_notending(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    Ok((i, uint))
}

pub fn detect_parse_uint_inclusive<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, uint) = alt((
        detect_parse_uint_start_interval_inclusive,
        detect_parse_uint_start_equal,
        detect_parse_uint_start_symbol,
    ))(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    Ok((i, uint))
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u64_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u64> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u64>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u64_match(
    arg: u64, ctx: &DetectUintData<u64>,
) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u64_free(ctx: &mut DetectUintData<u64>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u32_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u32>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u32_parse_inclusive(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint_inclusive::<u32>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u32_match(
    arg: u32, ctx: &DetectUintData<u32>,
) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u32_free(ctx: &mut DetectUintData<u32>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u8_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u8_match(
    arg: u8, ctx: &DetectUintData<u8>,
) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u8_free(ctx: &mut DetectUintData<u8>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u16_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u16> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u16>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u16_match(
    arg: u16, ctx: &DetectUintData<u16>,
) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u16_free(ctx: &mut DetectUintData<u16>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod tests {
    use super::*;

    use suricata_derive::EnumStringU8;

    #[derive(Clone, Debug, PartialEq, EnumStringU8)]
    #[repr(u8)]
    pub enum TestEnum {
        Zero = 0,
        BestValueEver = 42,
    }

    #[test]
    fn test_detect_parse_uint_enum() {
        let ctx = detect_parse_uint_enum::<u8, TestEnum>("best_value_ever").unwrap();
        assert_eq!(ctx.arg1, 42);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, TestEnum>(">1").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeGt);
    }

    #[test]
    fn test_parse_uint_bitmask() {
        let (_, val) = detect_parse_uint::<u64>("&0x40!=0").unwrap();
        assert_eq!(val.arg1, 0x40);
        assert_eq!(val.arg2, 0);
        assert_eq!(val.mode, DetectUintMode::DetectUintModeNegBitmask);
        assert!(!detect_match_uint(&val, 0xBF));
        assert!(detect_match_uint(&val, 0x40));
        let (_, val) = detect_parse_uint::<u64>("&0xc0=0x80").unwrap();
        assert_eq!(val.arg1, 0xc0);
        assert_eq!(val.arg2, 0x80);
        assert_eq!(val.mode, DetectUintMode::DetectUintModeBitmask);
        assert!(detect_match_uint(&val, 0x80));
        assert!(!detect_match_uint(&val, 0x40));
        assert!(!detect_match_uint(&val, 0xc0));
        // could never match
        assert!(detect_parse_uint::<u64>("&0xc0=12").is_err());
    }
    #[test]
    fn test_parse_uint_hex() {
        let (_, val) = detect_parse_uint::<u64>("0x100").unwrap();
        assert_eq!(val.arg1, 0x100);
        let (_, val) = detect_parse_uint::<u8>("0xFF").unwrap();
        assert_eq!(val.arg1, 255);
        let (_, val) = detect_parse_uint::<u8>("0xff").unwrap();
        assert_eq!(val.arg1, 255);
    }

    #[test]
    fn test_parse_uint_negated_range() {
        let (_, val) = detect_parse_uint::<u8>("!1-6").unwrap();
        assert_eq!(val.arg1, 1);
        assert_eq!(val.arg2, 6);
        assert_eq!(val.mode, DetectUintMode::DetectUintModeNegRg);
        assert!(detect_match_uint(&val, 1));
        assert!(!detect_match_uint(&val, 2));
        assert!(!detect_match_uint(&val, 5));
        assert!(detect_match_uint(&val, 6));
    }

    #[test]
    fn test_parse_uint_unit() {
        let (_, val) = detect_parse_uint::<u64>(" 2kb").unwrap();
        assert_eq!(val.arg1, 2048);

        assert!(detect_parse_uint::<u8>("2kb").is_err());

        let (_, val) = detect_parse_uint::<u32>("> 3MB").unwrap();
        assert_eq!(val.arg1, 3 * 1024 * 1024);
    }

    #[test]
    fn test_parse_uint_like_mqtt_protocol_version() {
        let (_, val) = detect_parse_uint::<u8>("3").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeEqual);
        assert_eq!(val.arg1, 3);
        let (_, val) = detect_parse_uint::<u8>("5").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeEqual);
        assert_eq!(val.arg1, 5);
        let (_, val) = detect_parse_uint::<u8>(">3").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeGt);
        assert_eq!(val.arg1, 3);
        let (_, val) = detect_parse_uint::<u8>("<44").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeLt);
        assert_eq!(val.arg1, 44);
        assert!(detect_parse_uint::<u8>("").is_err());
        assert!(detect_parse_uint::<u8>("<444").is_err());
    }
}
