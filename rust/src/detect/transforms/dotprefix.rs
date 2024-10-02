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

use super::{
    DetectHelperTransformRegister, DetectSignatureAddTransform, InspectionBufferCopy,
    InspectionBufferLength, InspectionBufferPtr, SCTransformTableElmt,
};
use crate::detect::SIGMATCH_NOOPT;

use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_TRANSFORM_DOT_PREFIX_ID: c_int = 0;

#[no_mangle]
unsafe extern "C" fn dot_prefix_setup(
    _de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    return DetectSignatureAddTransform(s, G_TRANSFORM_DOT_PREFIX_ID, ptr::null_mut());
}

fn dot_prefix_transform_do(input: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(input.len() + 1);
    r.push(b'.');
    r.extend_from_slice(input);
    return r;
}

#[no_mangle]
unsafe extern "C" fn dot_prefix_transform(buffer: *mut c_void, _ctx: *mut c_void) {
    let input = InspectionBufferPtr(buffer);
    let input_len = InspectionBufferLength(buffer);
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = dot_prefix_transform_do(input);

    unsafe {
        InspectionBufferCopy(buffer, output.as_ptr(), output.len() as u32);
    }
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformDotPrefixRegister() {
    let kw = SCTransformTableElmt {
        name: b"dotprefix\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to extract the dotprefix\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#dotprefix\0".as_ptr() as *const libc::c_char,
        Setup: dot_prefix_setup,
        flags: SIGMATCH_NOOPT,
        Transform: dot_prefix_transform,
        Free: None,
        TransformValidate: None,
    };
    unsafe {
        G_TRANSFORM_DOT_PREFIX_ID = DetectHelperTransformRegister(&kw);
        if G_TRANSFORM_DOT_PREFIX_ID < 0 {
            SCLogWarning!("Failed registering transform dot_prefix");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_prefix_transform() {
        let buf = b"example.com";
        let out = dot_prefix_transform_do(buf);
        assert_eq!(out, b".example.com");
        let buf = b"hello.example.com";
        let out = dot_prefix_transform_do(buf);
        assert_eq!(out, b".hello.example.com");
    }
}
