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
pub enum Ipv4FragBits {
    R = 0x8000,
    D = 0x4000,
    M = 0x2000,
}

fn detect_ipv4_fragbits(s: &str) -> Option<DetectUintData<u16>> {
    detect_parse_uint_bitflags::<u16, Ipv4FragBits>(s, DetectBitflagModifier::Equal, true)
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectIpv4FragbitsParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u16> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_ipv4_fragbits(s) {
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
        let ctx = detect_ipv4_fragbits("M").unwrap();
        assert_eq!(ctx.arg1, 0x2000);
        assert!(detect_ipv4_fragbits("G").is_none());
    }
}
