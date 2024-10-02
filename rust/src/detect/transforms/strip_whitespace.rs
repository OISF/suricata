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

static mut G_TRANSFORM_STRIP_WHITESPACE_ID: c_int = 0;

#[no_mangle]
unsafe extern "C" fn strip_whitespace_setup(
    _de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    return DetectSignatureAddTransform(s, G_TRANSFORM_STRIP_WHITESPACE_ID, ptr::null_mut());
}

fn strip_whitespace_transform_do(input: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(input.len());
    for i in 0..input.len() {
        if !input[i].is_ascii_whitespace() {
            r.push(input[i]);
        }
    }
    return r;
}

#[no_mangle]
unsafe extern "C" fn strip_whitespace_transform(buffer: *mut c_void, _ctx: *mut c_void) {
    let input = InspectionBufferPtr(buffer);
    let input_len = InspectionBufferLength(buffer);
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = strip_whitespace_transform_do(input);

    unsafe {
        InspectionBufferCopy(buffer, output.as_ptr(), output.len() as u32);
    }
}

#[no_mangle]
unsafe extern "C" fn strip_whitespace_validate(
    content: *const u8, len: u16, _ctx: *mut c_void,
) -> bool {
    let input = build_slice!(content, len as usize);
    for i in 0..input.len() {
        if input[i].is_ascii_whitespace() {
            return false;
        }
    }
    return true;
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformStripWhitespaceRegister() {
    let kw = SCTransformTableElmt {
        name: b"strip_whitespace\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to strip whitespace before inspection\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/transforms.html#strip-whitespace\0".as_ptr() as *const libc::c_char,
        Setup: strip_whitespace_setup,
        flags: SIGMATCH_NOOPT,
        Transform: strip_whitespace_transform,
        Free: None,
        TransformValidate: Some(strip_whitespace_validate),
    };
    unsafe {
        G_TRANSFORM_STRIP_WHITESPACE_ID = DetectHelperTransformRegister(&kw);
        if G_TRANSFORM_STRIP_WHITESPACE_ID < 0 {
            SCLogWarning!("Failed registering transform strip_whitespace");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_whitespace_transform() {
        let buf = b" A B C D ";
        let out = strip_whitespace_transform_do(buf);
        assert_eq!(out, b"ABCD");
        let buf = b"EFGH";
        let out = strip_whitespace_transform_do(buf);
        assert_eq!(out, b"EFGH");
        let buf = b"I   J";
        let out = strip_whitespace_transform_do(buf);
        assert_eq!(out, b"IJ");
    }
}