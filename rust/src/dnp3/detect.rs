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

use crate::detect::uint::{detect_parse_uint_bitflags, DetectBitflagModifier, DetectUintData};

use std::ffi::CStr;

#[repr(u16)]
#[derive(EnumStringU16)]
#[allow(non_camel_case_types)]
pub enum Dnp3IndFlag {
    Device_restart = 0x8000,
    Device_trouble = 0x4000,
    Local_control = 0x2000,
    Need_time = 0x1000,
    Class_3_events = 0x0800,
    Class_2_events = 0x0400,
    Class_1_events = 0x0200,
    All_stations = 0x0100,
    Reserved_1 = 0x0080,
    Reserved_2 = 0x0040,
    Config_corrupt = 0x0020,
    Already_executing = 0x0010,
    Event_buffer_overflow = 0x0008,
    Parameter_error = 0x0004,
    Object_unknown = 0x0002,
    No_func_code_support = 0x0001,
}

fn dnp3_detect_ind_parse(s: &str) -> Option<DetectUintData<u16>> {
    detect_parse_uint_bitflags::<u16, Dnp3IndFlag>(s, DetectBitflagModifier::Any, false)
}

#[no_mangle]
pub unsafe extern "C" fn SCDnp3DetectIndParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u16> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = dnp3_detect_ind_parse(s) {
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
    fn dnp3_ind_parse() {
        let ctx = dnp3_detect_ind_parse("0").unwrap();
        assert_eq!(ctx.arg1, 0);
        let ctx = dnp3_detect_ind_parse("1").unwrap();
        assert_eq!(ctx.arg1, 1);
        let ctx = dnp3_detect_ind_parse("0x0").unwrap();
        assert_eq!(ctx.arg1, 0);
        let ctx = dnp3_detect_ind_parse("0x0000").unwrap();
        assert_eq!(ctx.arg1, 0);
        let ctx = dnp3_detect_ind_parse("0x0001").unwrap();
        assert_eq!(ctx.arg1, 1);
        let ctx = dnp3_detect_ind_parse("0x8421").unwrap();
        assert_eq!(ctx.arg1, 0x8421);
        assert!(dnp3_detect_ind_parse("a").is_none());
        let ctx = dnp3_detect_ind_parse("all_stations").unwrap();
        assert_eq!(ctx.arg1, 0x0100);
        let ctx = dnp3_detect_ind_parse("class_1_events , class_2_events").unwrap();
        assert_eq!(ctx.arg1, 0x600);
        assert!(dnp3_detect_ind_parse("something",).is_none());
    }
}
