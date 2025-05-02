/* Copyright (C) 2025 Open Information Security Foundation
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

use nom7::{
    branch::alt,
    bytes::complete::{is_a, tag, tag_no_case, take_while},
    character::complete::{char, digit1},
    combinator::{all_consuming, map, map_opt, opt, recognize, value, verify},
    error::{make_error, ErrorKind},
    sequence::tuple,
    Err, IResult,
};

use num::traits::float::FloatCore;
use num::traits::{FromPrimitive, ToPrimitive};
use num::Bounded;

use std::ffi::CStr;

#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(u8)]
pub enum DetectFloatMode {
    DetectFloatModeEqual,
    DetectFloatModeLt,
    DetectFloatModeLte,
    DetectFloatModeGt,
    DetectFloatModeGte,
    DetectFloatModeRange,
    DetectFloatModeNe,
    DetectFloatModeNegRg,
}

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct DetectFloatData<T> {
    pub arg1: T,
    pub arg2: T,
    pub mode: DetectFloatMode,
}

impl<T: Default> Default for DetectFloatData<T> {
    fn default() -> Self {
        Self {
            arg1: T::default(),
            arg2: T::default(),
            mode: DetectFloatMode::DetectFloatModeEqual,
        }
    }
}

pub trait DetectFloatType:
    FromPrimitive + ToPrimitive + std::str::FromStr + Bounded + PartialOrd + FloatCore + Sized
{
    fn from_str(s: &str) -> Option<Self>;
}

impl<T> DetectFloatType for T
where
    T: FromPrimitive + ToPrimitive + std::str::FromStr + Bounded + PartialOrd + FloatCore,
{
    fn from_str(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

pub fn parse_float_value<T: DetectFloatType>(input: &str) -> IResult<&str, T> {
    alt((
        // Handle special cases first
        map(tag_no_case("NaN"), |_| {
            <T as DetectFloatType>::from_str("NaN").unwrap()
        }),
        map(tag_no_case("+inf"), |_| {
            <T as DetectFloatType>::from_str("inf").unwrap()
        }),
        map(tag_no_case("inf"), |_| {
            <T as DetectFloatType>::from_str("inf").unwrap()
        }),
        map(tag_no_case("-inf"), |_| {
            <T as DetectFloatType>::from_str("-inf").unwrap()
        }),
        // Handle numeric parsing, including scientific notation
        map_opt(
            recognize(tuple((
                opt(alt((tag("+"), tag("-")))), // Handle optional signs
                alt((digit1, recognize(tuple((tag("."), digit1))))), // Handle integers & `.5`
                opt(tuple((tag("."), digit1))), // Handle decimals like `5.`
                opt(tuple((
                    tag_no_case("e"),
                    opt(alt((tag("+"), tag("-")))),
                    digit1,
                ))), // Handle `1e10`, `-1e-5`
            ))),
            |float_str: &str| <T as DetectFloatType>::from_str(float_str),
        ),
    ))(input)
}
fn detect_parse_float_start_equal<T: DetectFloatType>(
    i: &str,
) -> IResult<&str, DetectFloatData<T>> {
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = parse_float_value::<T>(i)?;
    Ok((
        i,
        DetectFloatData {
            arg1,
            arg2: <T as FloatCore>::min_value(),
            mode: DetectFloatMode::DetectFloatModeEqual,
        },
    ))
}

pub fn detect_parse_float_start_interval<T: DetectFloatType>(
    i: &str,
) -> IResult<&str, DetectFloatData<T>> {
    let (i, neg) = opt(char('!'))(i)?;
    let (i, arg1) = parse_float_value::<T>(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = alt((tag("-"), tag("<>")))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = verify(parse_float_value::<T>, |x| {
        *x > arg1 && *x - arg1 > <T as FloatCore>::epsilon()
    })(i)?;
    let mode = if neg.is_some() {
        DetectFloatMode::DetectFloatModeNegRg
    } else {
        DetectFloatMode::DetectFloatModeRange
    };
    Ok((i, DetectFloatData { arg1, arg2, mode }))
}

fn detect_parse_float_mode(i: &str) -> IResult<&str, DetectFloatMode> {
    let (i, mode) = alt((
        value(DetectFloatMode::DetectFloatModeGte, tag(">=")),
        value(DetectFloatMode::DetectFloatModeLte, tag("<=")),
        value(DetectFloatMode::DetectFloatModeGt, tag(">")),
        value(DetectFloatMode::DetectFloatModeLt, tag("<")),
        value(DetectFloatMode::DetectFloatModeNe, tag("!=")),
        value(DetectFloatMode::DetectFloatModeEqual, tag("=")),
    ))(i)?;
    Ok((i, mode))
}

fn detect_parse_float_start_symbol<T: DetectFloatType>(
    i: &str,
) -> IResult<&str, DetectFloatData<T>> {
    let (i, mode) = detect_parse_float_mode(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = parse_float_value::<T>(i)?;

    match mode {
        DetectFloatMode::DetectFloatModeNe => {}
        DetectFloatMode::DetectFloatModeLt => {
            if arg1 == <T as FloatCore>::min_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectFloatMode::DetectFloatModeLte => {
            if arg1 == <T as FloatCore>::max_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectFloatMode::DetectFloatModeGt => {
            if arg1 == <T as FloatCore>::max_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectFloatMode::DetectFloatModeGte => {
            if arg1 == <T as FloatCore>::min_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        _ => {
            return Err(Err::Error(make_error(i, ErrorKind::MapOpt)));
        }
    }

    Ok((
        i,
        DetectFloatData {
            arg1,
            arg2: <T as FloatCore>::min_value(),
            mode,
        },
    ))
}

pub fn detect_match_float<T: DetectFloatType>(x: &DetectFloatData<T>, val: T) -> bool {
    match x.mode {
        DetectFloatMode::DetectFloatModeEqual => val == x.arg1,
        DetectFloatMode::DetectFloatModeNe => val != x.arg1,
        DetectFloatMode::DetectFloatModeLt => val < x.arg1,
        DetectFloatMode::DetectFloatModeLte => val <= x.arg1,
        DetectFloatMode::DetectFloatModeGt => val > x.arg1,
        DetectFloatMode::DetectFloatModeGte => val >= x.arg1,
        DetectFloatMode::DetectFloatModeRange => val > x.arg1 && val < x.arg2,
        DetectFloatMode::DetectFloatModeNegRg => val <= x.arg1 || val >= x.arg2,
    }
}

pub fn detect_parse_float<T: DetectFloatType>(i: &str) -> IResult<&str, DetectFloatData<T>> {
    let (i, float) = detect_parse_float_notending(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    Ok((i, float))
}

fn detect_parse_float_notending<T: DetectFloatType>(i: &str) -> IResult<&str, DetectFloatData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, float) = alt((
        detect_parse_float_start_interval,
        detect_parse_float_start_equal,
        detect_parse_float_start_symbol,
    ))(i)?;
    Ok((i, float))
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectF64Parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectFloatData<f64> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_float::<f64>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectF64Match(
    arg: f64, ctx: &DetectFloatData<f64>,
) -> std::os::raw::c_int {
    if detect_match_float::<f64>(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectF64Free(ctx: &mut DetectFloatData<f64>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectParseF64(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectFloatData<f64> {
    let ft_name: &CStr = CStr::from_ptr(ustr);
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_float::<f64>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed);
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectMatchF64(
    arg: f64, ctx: &DetectFloatData<f64>,
) -> std::os::raw::c_int {
    if detect_match_float(ctx, arg) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectFreeF64(ctx: *mut DetectFloatData<f64>) {
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_parse_float_value() {
        assert!(parse_float_value::<f64>("NaN").is_ok());
        assert!(parse_float_value::<f64>("-inf").is_ok());
        assert!(parse_float_value::<f64>("inf").is_ok());
        assert!(parse_float_value::<f64>("+inf").is_ok());
        assert!(parse_float_value::<f64>("123.45").is_ok());
        assert!(parse_float_value::<f64>("-0.001").is_ok());
        assert!(parse_float_value::<f64>("1e10").is_ok());
        assert!(parse_float_value::<f64>("-1e-10").is_ok());
        assert!(parse_float_value::<f64>("0.5").is_ok());
        assert!(parse_float_value::<f64>("5.").is_ok());
        assert!(parse_float_value::<f64>("0+").is_ok());
        assert!(parse_float_value::<f64>("0-").is_ok());
        assert!(parse_float_value::<f32>("NaN").is_ok());
        assert!(parse_float_value::<f32>("-inf").is_ok());
        assert!(parse_float_value::<f32>("inf").is_ok());
        assert!(parse_float_value::<f32>("+inf").is_ok());
        assert!(parse_float_value::<f32>("123.45").is_ok());
        assert!(parse_float_value::<f32>("-0.001").is_ok());
        assert!(parse_float_value::<f32>("1e10").is_ok());
        assert!(parse_float_value::<f32>("-1e-10").is_ok());
        assert!(parse_float_value::<f32>("0.5").is_ok());
        assert!(parse_float_value::<f32>("5.").is_ok());
        assert!(parse_float_value::<f32>("0+").is_ok());
        assert!(parse_float_value::<f32>("0-").is_ok());

        assert!(parse_float_value::<f32>(".e10").is_err());
    }
    #[test]
    fn test_detect_parse_valid() {
        let _ = do_parse("1.0", 1.0, DetectFloatMode::DetectFloatModeEqual);
        let _ = do_parse(">1.0", 1.0, DetectFloatMode::DetectFloatModeGt);
        let _ = do_parse(">=1.0", 1.0, DetectFloatMode::DetectFloatModeGte);
        let _ = do_parse("<1.0", 1.0, DetectFloatMode::DetectFloatModeLt);
        let _ = do_parse("<=1.0", 1.0, DetectFloatMode::DetectFloatModeLte);
        let _ = do_parse("=1.0", 1.0, DetectFloatMode::DetectFloatModeEqual);
        let _ = do_parse("!=1.0", 1.0, DetectFloatMode::DetectFloatModeNe);
        let _ = do_parse_mult_args(
            "37.0-42.0",
            37.0,
            42.0,
            DetectFloatMode::DetectFloatModeRange,
        );
    }

    #[test]
    fn test_detect_parse_invalid() {
        assert!(detect_parse_float::<f64>("suricata").is_err());

        // range should be <lower-val> - <higher-val>
        assert!(detect_parse_float::<f64>("42-37").is_err());

        assert!(detect_parse_float::<f64>("< suricata").is_err());
        assert!(detect_parse_float::<f64>("<= suricata").is_err());
        assert!(detect_parse_float::<f64>("= suricata").is_err());
        assert!(detect_parse_float::<f64>("> suricata").is_err());
        assert!(detect_parse_float::<f64>(">= suricata").is_err());
        assert!(detect_parse_float::<f64>("! suricata").is_err());
        assert!(detect_parse_float::<f64>("!= suricata").is_err());
    }

    fn do_parse<T: DetectFloatType + std::fmt::Display>(
        val: &str, fval: T, mode: DetectFloatMode,
    ) -> DetectFloatData<T> {
        let str_val = format!("{:.3}", fval);
        let (_, val) = detect_parse_float::<T>(val).unwrap();
        let str_arg1 = format!("{:.3}", val.arg1);
        assert_eq!(str_arg1, str_val);
        assert_eq!(val.mode, mode);
        val
    }

    fn do_parse_mult_args<T: DetectFloatType + std::fmt::Display>(
        val: &str, fval1: T, fval2: T, mode: DetectFloatMode,
    ) -> DetectFloatData<T> {
        let str_val = format!("{:.3}", fval1);
        let (_, val) = detect_parse_float::<T>(val).unwrap();
        let str_arg = format!("{:.3}", val.arg1);
        assert_eq!(str_arg, str_val);
        let str_val = format!("{:.3}", fval2);
        let str_arg = format!("{:.3}", val.arg2);
        assert_eq!(str_arg, str_val);
        assert_eq!(val.mode, mode);
        val
    }

    #[test]
    fn test_detect_match_valid() {
        let val = do_parse("= 1.264", 1.264, DetectFloatMode::DetectFloatModeEqual);
        assert!(detect_match_float(&val, 1.264));

        let val = do_parse("> 1.0", 1.0, DetectFloatMode::DetectFloatModeGt);
        assert!(detect_match_float(&val, 1.1));
        assert!(!detect_match_float(&val, 1.0));

        let val = do_parse(">= 1.0", 1.0, DetectFloatMode::DetectFloatModeGte);
        assert!(detect_match_float(&val, 1.0));
        assert!(detect_match_float(&val, 1.5));
        assert!(!detect_match_float(&val, 0.5));

        let val = do_parse("<= 1.0", 1.0, DetectFloatMode::DetectFloatModeLte);
        assert!(detect_match_float(&val, 1.0));
        assert!(detect_match_float(&val, 0.5));
        assert!(!detect_match_float(&val, 1.5));

        let val = do_parse("< 1.0", 1.0, DetectFloatMode::DetectFloatModeLt);
        assert!(detect_match_float(&val, 0.9));
        assert!(!detect_match_float(&val, 1.0));

        let val = do_parse("= 1.0", 1.0, DetectFloatMode::DetectFloatModeEqual);
        assert!(detect_match_float(&val, 1.0));
        assert!(!detect_match_float(&val, 0.9));
        assert!(!detect_match_float(&val, 1.1));

        let val = do_parse("!= 1.0", 1.0, DetectFloatMode::DetectFloatModeNe);
        assert!(detect_match_float(&val, 0.9));
        assert!(detect_match_float(&val, 1.1));
        assert!(!detect_match_float(&val, 1.0));

        let val = do_parse_mult_args(
            "37.0-42.0",
            37.0,
            42.0,
            DetectFloatMode::DetectFloatModeRange,
        );
        assert!(detect_match_float(&val, 37.1));
        assert!(detect_match_float(&val, 41.9));
        assert!(!detect_match_float(&val, 35.0));
        assert!(!detect_match_float(&val, 43.0));

        let val = do_parse_mult_args(
            "!37.0-42.0",
            37.0,
            42.0,
            DetectFloatMode::DetectFloatModeNegRg,
        );
        assert!(detect_match_float(&val, 37.0));
        assert!(detect_match_float(&val, 42.0));
        assert!(detect_match_float(&val, 35.0));
        assert!(detect_match_float(&val, 43.0));
        assert!(!detect_match_float(&val, 37.1));
        assert!(!detect_match_float(&val, 41.9));
    }

    fn do_match_test(val: &str, arg1: f64, arg1_cmp: f64, arg2: f64, mode: DetectFloatMode) {
        let c_string = CString::new(val).expect("CString::new failed");
        unsafe {
            let val = SCDetectF64Parse(c_string.as_ptr());
            let str_arg_a = format!("{:.3}", (*val).arg1);
            let str_arg_b = format!("{:.3}", arg1);
            assert_eq!(str_arg_a, str_arg_b);
            let str_arg_a = format!("{:.3}", (*val).arg2);
            let str_arg_b = format!("{:.3}", arg2);
            assert_eq!(str_arg_a, str_arg_b);

            assert_eq!((*val).mode, mode);
            assert_eq!(1, SCDetectF64Match(arg1_cmp, &*val));
        }
    }

    fn do_match_test_arg1(val: &str, arg1: f64, arg1_cmp: f64, mode: DetectFloatMode) {
        do_match_test(val, arg1, arg1_cmp, FloatCore::min_value(), mode);
    }

    fn do_parse_test(val: &str, arg1: f64, arg2: f64, mode: DetectFloatMode) {
        let c_string = CString::new(val).expect("CString::new failed");
        unsafe {
            let val = SCDetectF64Parse(c_string.as_ptr());
            let str_arg_a = format!("{:.3}", (*val).arg1);
            let str_arg_b = format!("{:.3}", arg1);
            assert_eq!(str_arg_a, str_arg_b);
            let str_arg_a = format!("{:.3}", (*val).arg2);
            let str_arg_b = format!("{:.3}", arg2);
            assert_eq!(str_arg_a, str_arg_b);

            assert_eq!((*val).mode, mode);
        }
    }

    fn do_parse_test_arg1(val: &str, arg1: f64, mode: DetectFloatMode) {
        do_parse_test(val, arg1, FloatCore::min_value(), mode);
    }

    #[test]
    fn test_ffi_detect_match_valid() {
        do_match_test_arg1("1.0", 1.0, 1.0, DetectFloatMode::DetectFloatModeEqual);
        do_match_test_arg1("> 1.0", 1.0, 1.1, DetectFloatMode::DetectFloatModeGt);
        do_match_test_arg1(">= 1.0", 1.0, 1.0, DetectFloatMode::DetectFloatModeGte);
        do_match_test_arg1("<= 1.0", 1.0, 1.0, DetectFloatMode::DetectFloatModeLte);
        do_match_test_arg1("< 1.0", 1.0, 0.9, DetectFloatMode::DetectFloatModeLt);
        do_match_test_arg1("= 1.0", 1.0, 1.0, DetectFloatMode::DetectFloatModeEqual);
        do_match_test_arg1("!= 1.0", 1.0, 1.1, DetectFloatMode::DetectFloatModeNe);
        do_match_test(
            "37.0-42.0",
            37.0,
            37.1,
            42.0,
            DetectFloatMode::DetectFloatModeRange,
        );
        do_match_test(
            "37.0-42.0",
            37.0,
            41.9,
            42.0,
            DetectFloatMode::DetectFloatModeRange,
        );
        do_match_test_arg1(
            ">= 4.15",
            4.15,
            4.150007324019584,
            DetectFloatMode::DetectFloatModeGte,
        );
        do_match_test_arg1(
            "> 4.15",
            4.15,
            4.150007324019584,
            DetectFloatMode::DetectFloatModeGt,
        );
    }

    #[test]
    fn test_ffi_detect_parse_valid() {
        do_parse_test_arg1("1.0", 1.0, DetectFloatMode::DetectFloatModeEqual);
        do_parse_test_arg1("> 1.0", 1.0, DetectFloatMode::DetectFloatModeGt);
        do_parse_test_arg1(">= 1.0", 1.0, DetectFloatMode::DetectFloatModeGte);
        do_parse_test_arg1("<= 1.0", 1.0, DetectFloatMode::DetectFloatModeLte);
        do_parse_test_arg1("< 1.0", 1.0, DetectFloatMode::DetectFloatModeLt);
        do_parse_test_arg1("= 1.0", 1.0, DetectFloatMode::DetectFloatModeEqual);
        do_parse_test_arg1("!= 1.0", 1.0, DetectFloatMode::DetectFloatModeNe);
        do_parse_test(
            "37.0-42.0",
            37.0,
            42.0,
            DetectFloatMode::DetectFloatModeRange,
        );
    }
}
