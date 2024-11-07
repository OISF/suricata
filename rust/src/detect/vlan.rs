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

use super::uint::{detect_parse_uint, DetectUintData};
use std::ffi::CStr;
use std::str::FromStr;

pub const DETECT_VLAN_ID_ANY: i8 = i8::MIN;
pub const DETECT_VLAN_ID_ALL: i8 = i8::MAX;
pub static VLAN_MAX_LAYERS: i8 = 3;

#[repr(C)]
#[derive(Debug, PartialEq)]
/// This data structure is also used in detect-vlan.c
pub struct DetectVlanIdData {
    /// Vlan id
    pub du16: DetectUintData<u16>,
    /// Layer can be DETECT_VLAN_ID_ANY to match with any vlan layer
    /// DETECT_VLAN_ID_ALL to match if all layers match, or an integer
    /// within the range -VLAN_MAX_LAYERS to VLAN_MAX_LAYERS-1 for indexing.
    /// Negative values represent back to front indexing.
    pub layer: i8,
}

pub fn detect_parse_vlan_id(s: &str) -> Option<DetectVlanIdData> {
    let parts: Vec<&str> = s.split(',').collect();
    let du16 = detect_parse_uint(parts[0]).ok()?.1;
    if parts.len() > 2 {
        return None;
    }
    if du16.arg1 > 0xFFF || du16.arg2 > 0xFFF {
        // vlan id is encoded on 12 bits
        return None;
    }
    let layer = if parts.len() == 2 {
        if parts[1] == "all" {
            DETECT_VLAN_ID_ALL
        } else if parts[1] == "any" {
            DETECT_VLAN_ID_ANY
        } else {
            let u8_layer = i8::from_str(parts[1]).ok()?;
            if !(-VLAN_MAX_LAYERS..=VLAN_MAX_LAYERS - 1).contains(&u8_layer) {
                return None;
            }
            u8_layer
        }
    } else {
        DETECT_VLAN_ID_ANY
    };
    return Some(DetectVlanIdData { du16, layer });
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectVlanIdParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectVlanIdData {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_vlan_id(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectVlanIdFree(ctx: &mut DetectVlanIdData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    #[test]
    fn test_detect_parse_vlan_id() {
        assert_eq!(
            detect_parse_vlan_id("300").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 300,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                layer: DETECT_VLAN_ID_ANY
            }
        );
        assert_eq!(
            detect_parse_vlan_id("300,any").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 300,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                layer: DETECT_VLAN_ID_ANY
            }
        );
        assert_eq!(
            detect_parse_vlan_id("300,all").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 300,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                layer: DETECT_VLAN_ID_ALL
            }
        );
        assert_eq!(
            detect_parse_vlan_id("200,1").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                layer: 1
            }
        );
        assert_eq!(
            detect_parse_vlan_id("200,-1").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                layer: -1
            }
        );
        assert_eq!(
            detect_parse_vlan_id("!200,2").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeNe,
                },
                layer: 2
            }
        );
        assert_eq!(
            detect_parse_vlan_id(">200,2").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeGt,
                },
                layer: 2
            }
        );
        assert_eq!(
            detect_parse_vlan_id("200-300,0").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 200,
                    arg2: 300,
                    mode: DetectUintMode::DetectUintModeRange,
                },
                layer: 0
            }
        );
        assert_eq!(
            detect_parse_vlan_id("0xC8,2").unwrap(),
            DetectVlanIdData {
                du16: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                layer: 2
            }
        );
        assert!(detect_parse_vlan_id("200abc").is_none());
        assert!(detect_parse_vlan_id("4096").is_none());
        assert!(detect_parse_vlan_id("600,abc").is_none());
        assert!(detect_parse_vlan_id("600,100").is_none());
        assert!(detect_parse_vlan_id("123,-4").is_none());
        assert!(detect_parse_vlan_id("1,2,3").is_none());
    }
}
