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
    DetectHelperTransformRegister, DetectSignatureAddTransform, InspectionBufferCheckAndExpand,
    InspectionBufferLength, InspectionBufferPtr, InspectionBufferTruncate, SCTransformTableElmt,
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

fn dot_prefix_transform_do(input: &[u8], output: &mut [u8]) {
    output[0] = b'.';
    output[1..].copy_from_slice(input);
}

#[no_mangle]
unsafe extern "C" fn dot_prefix_transform(buffer: *mut c_void, _ctx: *mut c_void) {
    let input = InspectionBufferPtr(buffer);
    let input_len = InspectionBufferLength(buffer);
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = InspectionBufferCheckAndExpand(buffer, input_len + 1);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, (input_len + 1) as usize);

    dot_prefix_transform_do(input, output);

    InspectionBufferTruncate(buffer, input_len + 1);
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
        let mut out = vec![0; b"example.com".len() + 1];
        dot_prefix_transform_do(buf, &mut out);
        assert_eq!(out, b".example.com");
        let buf = b"hello.example.com";
        let mut out = vec![0; b"hello.example.com".len() + 1];
        dot_prefix_transform_do(buf, &mut out);
        assert_eq!(out, b".hello.example.com");
    }
}
