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
    detect_parse_uint, DetectBitflagModifier, DetectUintData, DetectUintMode,
};

use std::ffi::CStr;

pub fn tcp_flags_parse(s: &str) -> Option<DetectUintData<u8>> {
    // first try numeric form
    if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
        return Some(ctx);
    }
    // otherwise, try strings, maybe prefixed by modifier
    let mut modifier = DetectBitflagModifier::Equal;
    let mut modset = false;
    let mut ignoring = false;
    let mut arg1 = 0u8;
    let mut arg2 = 0xffu8;
    for c in s.bytes() {
        match c {
            b'+' => {
                if modset || ignoring {
                    SCLogError!("Cannot have multiple modifiers");
                    return None;
                }
                modifier = DetectBitflagModifier::Plus;
                modset = true;
            }
            b'!' | b'-' => {
                if modset || ignoring {
                    SCLogError!("Cannot have multiple modifiers");
                    return None;
                }
                modifier = DetectBitflagModifier::Not;
                modset = true;
            }
            b'=' => {
                if modset || ignoring {
                    SCLogError!("Cannot have multiple modifiers");
                    return None;
                }
                modifier = DetectBitflagModifier::Equal;
                modset = true;
            }
            b'*' => {
                if modset || ignoring {
                    SCLogError!("Cannot have multiple modifiers");
                    return None;
                }
                modifier = DetectBitflagModifier::Any;
                modset = true;
            }
            b',' => {
                if ignoring {
                    SCLogError!("Too many commas");
                    return None;
                } else if modifier != DetectBitflagModifier::Equal {
                    SCLogError!("Ignored flags are only useful for equal modifier");
                    return None;
                }
                ignoring = true;
            }
            b'F' | b'f' => {
                if (arg1 & 1) != 0 {
                    SCLogError!("Repeated bitflag for F");
                    return None;
                }
                if ignoring {
                    arg2 &= 0xfe;
                } else {
                    arg1 |= 1;
                }
            }
            b'S' | b's' => {
                if (arg1 & 2) != 0 {
                    SCLogError!("Repeated bitflag for S");
                    return None;
                }
                if ignoring {
                    arg2 &= 0xfd;
                } else {
                    arg1 |= 2;
                }
            }
            b'R' | b'r' => {
                if (arg1 & 4) != 0 {
                    SCLogError!("Repeated bitflag for R");
                    return None;
                }
                if ignoring {
                    arg2 &= 0xfb;
                } else {
                    arg1 |= 4;
                }
            }
            b'P' | b'p' => {
                if (arg1 & 8) != 0 {
                    SCLogError!("Repeated bitflag for P");
                    return None;
                }
                if ignoring {
                    arg2 &= 0xf7;
                } else {
                    arg1 |= 8;
                }
            }
            b'A' | b'a' => {
                if (arg1 & 0x10) != 0 {
                    SCLogError!("Repeated bitflag for A");
                    return None;
                }
                if ignoring {
                    arg2 &= 0xef;
                } else {
                    arg1 |= 0x10;
                }
            }
            b'U' | b'u' => {
                if (arg1 & 0x20) != 0 {
                    SCLogError!("Repeated bitflag for U");
                    return None;
                }
                if ignoring {
                    arg2 &= 0xdf;
                } else {
                    arg1 |= 0x20;
                }
            }
            b'E' | b'e' => {
                if (arg1 & 0x40) != 0 {
                    SCLogError!("Repeated bitflag for U");
                    return None;
                }
                if ignoring {
                    arg2 &= 0xbf;
                } else {
                    arg1 |= 0x40;
                }
            }
            b'C' | b'c' => {
                if (arg1 & 0x80) != 0 {
                    SCLogError!("Repeated bitflag for U");
                    return None;
                }
                if ignoring {
                    arg2 &= 0x7f;
                } else {
                    arg1 |= 0x80;
                }
            }
            _ => {
                SCLogError!("Bad character {} for tcp.flags", c);
                return None;
            }
        }
    }
    let ctx = match modifier {
        DetectBitflagModifier::Equal => DetectUintData::<u8> {
            arg1,
            arg2: arg1 & arg2,
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
        assert_eq!(ctx.arg1, 2);
        assert!(tcp_flags_parse("G").is_none());
        assert!(tcp_flags_parse("+S*").is_none());
        let ctx = tcp_flags_parse("CE").unwrap();
        assert_eq!(ctx.arg1, 0xC0);
    }
}
