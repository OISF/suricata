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

use super::uint::*;
use nom8::branch::alt;
use nom8::bytes::complete::{is_a, tag, take_while};
use nom8::character::complete::char;
use nom8::combinator::{all_consuming, opt, value};
use nom8::{IResult, Parser};

use std::ffi::CStr;

#[derive(Debug)]
#[repr(C)]
pub struct DetectUrilenData {
    pub du16: DetectUintData<u16>,
    pub raw_buffer: bool,
}

pub fn detect_parse_urilen_raw(i: &str) -> IResult<&str, bool> {
    let (i, _) = opt(is_a(" ")).parse(i)?;
    let (i, _) = char(',').parse(i)?;
    let (i, _) = opt(is_a(" ")).parse(i)?;
    let (i, v) = alt((value(true, tag("raw")), value(false, tag("norm")))).parse(i)?;
    let (i, _) = opt(is_a(" ")).parse(i)?;
    Ok((i, v))
}

pub fn detect_parse_urilen(i: &str) -> IResult<&str, DetectUrilenData> {
    let (i, du16) = detect_parse_uint_notending::<u16>(i)?;
    let (i, _) = take_while(|c| c == ' ').parse(i)?;
    if i.is_empty() {
        return Ok((
            i,
            DetectUrilenData {
                du16,
                raw_buffer: false,
            },
        ));
    }
    let (i, raw_buffer) = all_consuming(detect_parse_urilen_raw).parse(i)?;
    return Ok((i, DetectUrilenData { du16, raw_buffer }));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectUrilenParse(
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
pub unsafe extern "C" fn SCDetectUrilenFree(ctx: &mut DetectUrilenData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_urilen() {
        let (_, ctx) = detect_parse_urilen("1<>3").unwrap();
        assert_eq!(ctx.du16.arg1, 1);
        assert_eq!(ctx.du16.arg2, 3);
        assert_eq!(ctx.du16.mode, DetectUintMode::DetectUintModeRange);
        assert!(detect_parse_urilen("1<>2").is_err());
    }
}
