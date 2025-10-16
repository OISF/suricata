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

use super::uint::{
    detect_parse_array_uint, detect_uint_match_at_index, DetectUintArrayData, DetectUintData,
    DetectUintIndex,
};
use std::ffi::{c_int, c_void, CStr};

pub const DETECT_VLAN_ID_ANY: i8 = i8::MIN;
pub const DETECT_VLAN_ID_ALL: i8 = i8::MAX;
pub const DETECT_VLAN_ID_ALL_OR_ABSENT: i8 = i8::MAX - 1;
pub const DETECT_VLAN_ID_OR_ABSENT: i8 = i8::MAX - 2;
pub const DETECT_VLAN_ID_ERROR: i8 = i8::MAX - 3;
pub static VLAN_MAX_LAYERS: i32 = 3;

#[repr(C)]
#[derive(Debug, PartialEq)]
/// This data structure is also used in detect-vlan.c
pub struct DetectVlanIdDataPrefilter {
    /// Vlan id
    pub du16: DetectUintData<u16>,
    /// Layer can be DETECT_VLAN_ID_ANY to match with any vlan layer
    /// DETECT_VLAN_ID_ALL to match if all layers match, or an integer
    /// within the range -VLAN_MAX_LAYERS to VLAN_MAX_LAYERS-1 for indexing.
    /// Negative values represent back to front indexing.
    pub layer: i8,
}

pub fn detect_parse_vlan_id(s: &str) -> Option<DetectUintArrayData<u16>> {
    let r = detect_parse_array_uint(s);
    if let Some(a) = &r {
        if a.du.arg1 > 0xFFF || a.du.arg2 > 0xFFF {
            // vlan id is encoded on 12 bits
            SCLogError!("vlan id should be less than 4096");
            return None;
        }
        match a.index {
            DetectUintIndex::All => {
                // keep previous behavior that vlan.id: all matched only if there was vlan
                return Some(DetectUintArrayData {
                    du: a.du.clone(),
                    index: DetectUintIndex::All,
                    start: a.start,
                    end: a.end,
                });
            }
            DetectUintIndex::Index((_, i)) => {
                if !(-VLAN_MAX_LAYERS..=VLAN_MAX_LAYERS - 1).contains(&i) {
                    SCLogError!(
                        "vlan id index should belong in range {:?}",
                        (-VLAN_MAX_LAYERS..=VLAN_MAX_LAYERS - 1)
                    );
                    return None;
                }
            }
            _ => {}
        }
    }
    return r;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectVlanIdParse(ustr: *const std::os::raw::c_char) -> *mut c_void {
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
pub unsafe extern "C" fn SCDetectVlanIdFree(ctx: &mut DetectUintArrayData<u16>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectVlanIdMatch(
    vlan_idx: u16, vlan_id: *const u16, ctx: *const c_void,
) -> c_int {
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u16>);
    let vlans = std::slice::from_raw_parts(vlan_id, vlan_idx as usize);
    return detect_uint_match_at_index::<u16, u16>(vlans, ctx, |vi| Some(*vi), true);
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectVlanIdPrefilterMatch(
    vlan_idx: u16, vlan_id: *const u16, ctx: &DetectVlanIdDataPrefilter,
) -> c_int {
    let index = match ctx.layer {
        DETECT_VLAN_ID_ANY => DetectUintIndex::Any,
        DETECT_VLAN_ID_ALL => DetectUintIndex::All,
        DETECT_VLAN_ID_ALL_OR_ABSENT => DetectUintIndex::AllOrAbsent,
        DETECT_VLAN_ID_OR_ABSENT => DetectUintIndex::OrAbsent,
        i => DetectUintIndex::Index((false, i.into())),
    };

    let ctx = DetectUintArrayData {
        du: ctx.du16.clone(),
        index,
        start: 0,
        end: 0,
    };
    let vlans = std::slice::from_raw_parts(vlan_id, vlan_idx as usize);
    return detect_uint_match_at_index::<u16, u16>(vlans, &ctx, |vi| Some(*vi), true);
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectVlanIdPrefilter(
    ctx: &DetectUintArrayData<u16>,
) -> DetectVlanIdDataPrefilter {
    let layer = match ctx.index {
        DetectUintIndex::Any => DETECT_VLAN_ID_ANY,
        DetectUintIndex::All => DETECT_VLAN_ID_ALL,
        DetectUintIndex::AllOrAbsent => DETECT_VLAN_ID_ALL_OR_ABSENT,
        DetectUintIndex::OrAbsent => DETECT_VLAN_ID_OR_ABSENT,
        DetectUintIndex::Index((_, i)) => i as i8,
        DetectUintIndex::NumberMatches(_) => DETECT_VLAN_ID_ERROR,
        DetectUintIndex::Count(_) => DETECT_VLAN_ID_ERROR,
    };
    DetectVlanIdDataPrefilter {
        du16: ctx.du.clone(),
        layer,
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectVlanIdPrefilterable(ctx: *const c_void) -> bool {
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u16>);
    if ctx.start != 0 || ctx.end != 0 {
        return false;
    }
    match ctx.index {
        DetectUintIndex::Any => true,
        DetectUintIndex::All => true,
        DetectUintIndex::AllOrAbsent => true,
        DetectUintIndex::OrAbsent => true,
        // do not prefilter for precise index with "or out of bounds"
        DetectUintIndex::Index((oob, _)) => !oob,
        DetectUintIndex::NumberMatches(_) => false,
        DetectUintIndex::Count(_) => false,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    #[test]
    fn test_detect_parse_vlan_id() {
        assert_eq!(
            detect_parse_vlan_id("300").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 300,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                index: DetectUintIndex::Any,
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id("300,any").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 300,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                index: DetectUintIndex::Any,
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id("300,all").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 300,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                index: DetectUintIndex::All,
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id("200,1").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                index: DetectUintIndex::Index((false, 1)),
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id("200,-1").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                index: DetectUintIndex::Index((false, -1)),
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id("!200,2").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeNe,
                },
                index: DetectUintIndex::Index((false, 2)),
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id(">200,2").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeGt,
                },
                index: DetectUintIndex::Index((false, 2)),
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id("200-300,0").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 200,
                    arg2: 300,
                    mode: DetectUintMode::DetectUintModeRange,
                },
                index: DetectUintIndex::Index((false, 0)),
                start: 0,
                end: 0,
            }
        );
        assert_eq!(
            detect_parse_vlan_id("0xC8,2").unwrap(),
            DetectUintArrayData {
                du: DetectUintData {
                    arg1: 200,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                index: DetectUintIndex::Index((false, 2)),
                start: 0,
                end: 0,
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
