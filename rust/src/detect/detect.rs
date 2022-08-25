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

use nom7::bytes::complete::{is_a, take_while};
use nom7::character::complete::{alpha0, char, digit1};
use nom7::combinator::{all_consuming, map_opt, map_res, opt};
use nom7::error::{make_error, ErrorKind};
use nom7::Err;
use nom7::IResult;
use super::uint::*;

use std::ffi::{CStr, CString};
use std::str::FromStr;

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
