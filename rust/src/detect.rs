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
use nom7::bytes::complete::{is_a, tag, take_while};
use nom7::character::complete::{alpha0, char, digit1};
use nom7::combinator::{all_consuming, map_opt, map_res, opt, value, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::Err;
use nom7::IResult;

use std::ffi::{CStr, CString};
use std::str::FromStr;

#[derive(PartialEq, Clone, Debug)]
#[repr(u8)]
pub enum DetectUintMode {
    DetectUintModeEqual,
    DetectUintModeLt,
    DetectUintModeLte,
    DetectUintModeGt,
    DetectUintModeGte,
    DetectUintModeRange,
    DetectUintModeNe,
}

#[derive(Debug)]
#[repr(C)]
pub struct DetectUintData<T> {
    pub arg1: T,
    pub arg2: T,
    pub mode: DetectUintMode,
}

pub trait DetectIntType:
    std::str::FromStr + std::cmp::PartialOrd + num::PrimInt + num::Bounded
{
}
impl<T> DetectIntType for T where
    T: std::str::FromStr + std::cmp::PartialOrd + num::PrimInt + num::Bounded
{
}

fn detect_parse_uint_start_equal<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;
    Ok((
        i,
        DetectUintData {
            arg1,
            arg2: T::min_value(),
            mode: DetectUintMode::DetectUintModeEqual,
        },
    ))
}

fn detect_parse_uint_start_interval<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, arg1) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = alt((tag("-"), tag("<>")))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = verify(map_opt(digit1, |s: &str| s.parse::<T>().ok()), |x| {
        x > &arg1 && *x - arg1 > T::one()
    })(i)?;
    Ok((
        i,
        DetectUintData {
            arg1,
            arg2,
            mode: DetectUintMode::DetectUintModeRange,
        },
    ))
}

fn detect_parse_uint_mode(i: &str) -> IResult<&str, DetectUintMode> {
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
    let (i, arg1) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;

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
            mode: mode,
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
    }
    return false;
}

pub fn detect_parse_uint_notending<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, uint) = alt((
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
pub unsafe extern "C" fn rs_detect_u64_free(ctx: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx as *mut DetectUintData<u64>));
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

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, FromPrimitive, Debug)]
pub enum DetectStreamSizeDataFlags {
    StreamSizeServer = 1,
    StreamSizeClient = 2,
    StreamSizeBoth = 3,
    StreamSizeEither = 4,
}

impl std::str::FromStr for DetectStreamSizeDataFlags {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "server" => Ok(DetectStreamSizeDataFlags::StreamSizeServer),
            "client" => Ok(DetectStreamSizeDataFlags::StreamSizeClient),
            "both" => Ok(DetectStreamSizeDataFlags::StreamSizeBoth),
            "either" => Ok(DetectStreamSizeDataFlags::StreamSizeEither),
            _ => Err(format!(
                "'{}' is not a valid value for DetectStreamSizeDataFlags",
                s
            )),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct DetectStreamSizeData {
    pub flags: DetectStreamSizeDataFlags,
    pub du32: DetectUintData<u32>,
}

pub fn detect_parse_stream_size(i: &str) -> IResult<&str, DetectStreamSizeData> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, flags) = map_res(alpha0, |s: &str| DetectStreamSizeDataFlags::from_str(s))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = char(',')(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, mode) = detect_parse_uint_mode(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = char(',')(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    let du32 = DetectUintData::<u32> {
        arg1: arg1,
        arg2: 0,
        mode: mode,
    };
    Ok((i, DetectStreamSizeData { flags, du32 }))
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_stream_size_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectStreamSizeData {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_stream_size(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_stream_size_free(ctx: &mut DetectStreamSizeData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[derive(Debug)]
#[repr(C)]
pub struct DetectUrilenData {
    pub du16: DetectUintData<u16>,
    pub raw_buffer: bool,
}

pub fn detect_parse_urilen_raw(i: &str) -> IResult<&str, bool> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = char(',')(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    return alt((value(true, tag("raw")), value(false, tag("norm"))))(i);
}

pub fn detect_parse_urilen(i: &str) -> IResult<&str, DetectUrilenData> {
    let (i, du16) = detect_parse_uint_notending::<u16>(i)?;
    let (i, raw) = opt(detect_parse_urilen_raw)(i)?;
    match raw {
        Some(raw_buffer) => {
            return Ok((i, DetectUrilenData { du16, raw_buffer }));
        }
        None => {
            return Ok((
                i,
                DetectUrilenData {
                    du16,
                    raw_buffer: false,
                },
            ));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_urilen_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUrilenData {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_urilen(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_urilen_free(ctx: &mut DetectUrilenData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, FromPrimitive, Debug)]
pub enum DetectIPRepDataCmd {
    IPRepCmdAny = 0,
    IPRepCmdBoth = 1,
    IPRepCmdSrc = 2,
    IPRepCmdDst = 3,
}

impl std::str::FromStr for DetectIPRepDataCmd {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "any" => Ok(DetectIPRepDataCmd::IPRepCmdAny),
            "both" => Ok(DetectIPRepDataCmd::IPRepCmdBoth),
            "src" => Ok(DetectIPRepDataCmd::IPRepCmdSrc),
            "dst" => Ok(DetectIPRepDataCmd::IPRepCmdDst),
            _ => Err(format!(
                "'{}' is not a valid value for DetectIPRepDataCmd",
                s
            )),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct DetectIPRepData {
    pub du8: DetectUintData<u8>,
    pub cat: u8,
    pub cmd: DetectIPRepDataCmd,
}

pub fn is_alphanumeric_or_slash(chr: char) -> bool {
    if chr.is_ascii_alphanumeric() {
        return true;
    }
    if chr == '_' || chr == '-' {
        return true;
    }
    return false;
}

extern "C" {
    pub fn SRepCatGetByShortname(name: *const i8) -> u8;
}

pub fn detect_parse_iprep(i: &str) -> IResult<&str, DetectIPRepData> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, cmd) = map_res(alpha0, |s: &str| DetectIPRepDataCmd::from_str(s))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = char(',')(i)?;
    let (i, _) = opt(is_a(" "))(i)?;

    let (i, name) = take_while(is_alphanumeric_or_slash)(i)?;
    // copy as to have final zero
    let namez = CString::new(name).unwrap();
    let cat = unsafe { SRepCatGetByShortname(namez.as_ptr() as *const i8) };
    if cat == 0 {
        return Err(Err::Error(make_error(i, ErrorKind::MapOpt)));
    }

    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = char(',')(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, mode) = detect_parse_uint_mode(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = char(',')(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = map_opt(digit1, |s: &str| s.parse::<u8>().ok())(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    let du8 = DetectUintData::<u8> {
        arg1: arg1,
        arg2: 0,
        mode: mode,
    };
    return Ok((i, DetectIPRepData { du8, cat, cmd }));
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_iprep_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectIPRepData {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_iprep(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_iprep_free(ctx: &mut DetectIPRepData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}
