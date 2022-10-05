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
use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag};
use nom7::character::complete::char;
use nom7::combinator::{opt, value};
use nom7::IResult;

use std::ffi::CStr;

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
    alt((value(true, tag("raw")), value(false, tag("norm"))))(i)
}

pub fn detect_parse_urilen(i: &str) -> IResult<&str, DetectUrilenData> {
    let (i, du16) = detect_parse_uint_notending::<u16>(i)?;
    let (i, raw) = opt(detect_parse_urilen_raw)(i)?;
    match raw {
        Some(raw_buffer) => {
            Ok((i, DetectUrilenData { du16, raw_buffer }))
        }
        None => {
            Ok((
                i,
                DetectUrilenData {
                    du16,
                    raw_buffer: false,
                },
            ))
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
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_urilen_free(ctx: &mut DetectUrilenData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}
