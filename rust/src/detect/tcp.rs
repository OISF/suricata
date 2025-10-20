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

use crate::detect::uint::{
    detect_parse_uint, parse_bitchars_modifier, DetectBitflagModifier, DetectUintData,
    DetectUintMode,
};
use crate::detect::EnumString;
use nom7::bytes::complete::take;
use nom7::error::Error;

use std::ffi::CStr;

#[repr(u8)]
#[derive(EnumStringU8)]
#[allow(non_camel_case_types)]
enum TcpFlag {
    C = 0x80,
    E = 0x40,
    U = 0x20,
    A = 0x10,
    P = 0x08,
    R = 0x04,
    S = 0x02,
    F = 0x01,
}

pub fn tcp_flags_parse(s: &str) -> Option<DetectUintData<u8>> {
    // first try numeric form
    if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
        return Some(ctx);
    }
    // otherwise, try strings
    let mut modifier = DetectBitflagModifier::Equal;
    let mut modset = false;
    let mut ignoring = false;
    let mut arg1 = 0u8;
    let mut arg2 = 0xffu8;
    let mut s2 = s;
    while !s2.is_empty() {
        let (s, vals) = take::<usize, &str, Error<_>>(1usize)(s2).ok()?;
        s2 = s;
        let vals = match vals {
            "1" => "C",
            "2" => "E",
            _ => vals,
        };
        if vals == "," {
            if ignoring {
                SCLogError!("Too many commas");
                return None;
            }
            if modifier != DetectBitflagModifier::Equal {
                SCLogError!("Ignored flags are only meaningful with equal mode");
                return None;
            }
            ignoring = true;
        } else if let Some(enum_val) = TcpFlag::from_str(vals) {
            let val = enum_val.into_u();
            if (arg1 & val) != 0 {
                SCLogError!("Repeated bitflag for {}", vals);
                return None;
            }
            if ignoring {
                arg2 &= 0xff ^ val;
            } else {
                arg1 |= val;
            }
        } else if let Ok((rems, newmod)) =
            parse_bitchars_modifier(vals, DetectBitflagModifier::Equal)
        {
            if !rems.is_empty() {
                SCLogError!("Bad character {} for tcp.flags", vals);
                return None;
            }
            if modset || ignoring {
                SCLogError!("Cannot have multiple modifiers");
                return None;
            }
            modifier = newmod;
            modset = true;
        } // else unreachable
    }
    let ctx = match modifier {
        DetectBitflagModifier::Equal => DetectUintData::<u8> {
            arg1: arg2,
            arg2: arg1,
            mode: DetectUintMode::DetectUintModeBitmask,
        },
        DetectBitflagModifier::Plus => DetectUintData::<u8> {
            arg1,
            arg2: arg1,
            mode: DetectUintMode::DetectUintModeBitmask,
        },
        DetectBitflagModifier::Any => DetectUintData::<u8> {
            arg1,
            arg2: 0,
            mode: DetectUintMode::DetectUintModeNegBitmask,
        },
        DetectBitflagModifier::Not => DetectUintData::<u8> {
            arg1,
            arg2: arg1,
            mode: DetectUintMode::DetectUintModeNegBitmask,
        },
    };
    return Some(ctx);
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectTcpFlagsParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = tcp_flags_parse(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fragbits_parse() {
        let ctx = tcp_flags_parse("S").unwrap();
        assert_eq!(ctx.arg2, 2);
        assert!(tcp_flags_parse("G").is_none());
        assert!(tcp_flags_parse("+S*").is_none());
        let ctx = tcp_flags_parse("CE").unwrap();
        assert_eq!(ctx.arg2, 0xC0);
        assert!(tcp_flags_parse("A,A").is_none());
        assert!(tcp_flags_parse("+A,U").is_none());
        assert!(tcp_flags_parse("*A,U").is_none());
        assert!(tcp_flags_parse("-A,U").is_none());
    }
}
