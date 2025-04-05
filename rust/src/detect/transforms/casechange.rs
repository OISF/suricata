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

static mut G_TRANSFORM_TOLOWER_ID: c_int = 0;
static mut G_TRANSFORM_TOUPPER_ID: c_int = 0;

unsafe extern "C" fn tolower_setup(
    _de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    return DetectSignatureAddTransform(s, G_TRANSFORM_TOLOWER_ID, ptr::null_mut());
}

fn tolower_transform_do(input: &[u8], output: &mut [u8]) {
    for (i, o) in input.iter().zip(output.iter_mut()) {
        *o = (*i).to_ascii_lowercase();
    }
}

unsafe extern "C" fn tolower_transform(_det: *mut c_void, buffer: *mut c_void, _ctx: *mut c_void) {
    let input = InspectionBufferPtr(buffer);
    let input_len = InspectionBufferLength(buffer);
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = InspectionBufferCheckAndExpand(buffer, input_len);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, input_len as usize);

    tolower_transform_do(input, output);

    InspectionBufferTruncate(buffer, input_len);
}

unsafe extern "C" fn tolower_validate(content: *const u8, len: u16, _ctx: *mut c_void) -> bool {
    let input = build_slice!(content, len as usize);
    for &c in input {
        if c.is_ascii_uppercase() {
            return false;
        }
    }
    return true;
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformToLowerRegister() {
    let kw = SCTransformTableElmt {
        name: b"to_lowercase\0".as_ptr() as *const libc::c_char,
        desc: b"convert buffer to lowercase\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#to_lowercase\0".as_ptr() as *const libc::c_char,
        Setup: tolower_setup,
        flags: SIGMATCH_NOOPT,
        Transform: tolower_transform,
        Free: None,
        TransformValidate: Some(tolower_validate),
        TransformSerialize: None,
    };
    G_TRANSFORM_TOLOWER_ID = DetectHelperTransformRegister(&kw);
    if G_TRANSFORM_TOLOWER_ID < 0 {
        SCLogWarning!("Failed registering transform tolower");
    }
}

unsafe extern "C" fn toupper_setup(
    _de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    return DetectSignatureAddTransform(s, G_TRANSFORM_TOUPPER_ID, ptr::null_mut());
}

fn toupper_transform_do(input: &[u8], output: &mut [u8]) {
    for (i, o) in input.iter().zip(output.iter_mut()) {
        *o = (*i).to_ascii_uppercase();
    }
}

unsafe extern "C" fn toupper_transform(_det: *mut c_void, buffer: *mut c_void, _ctx: *mut c_void) {
    let input = InspectionBufferPtr(buffer);
    let input_len = InspectionBufferLength(buffer);
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = InspectionBufferCheckAndExpand(buffer, input_len);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, input_len as usize);

    toupper_transform_do(input, output);

    InspectionBufferTruncate(buffer, input_len);
}

unsafe extern "C" fn toupper_validate(content: *const u8, len: u16, _ctx: *mut c_void) -> bool {
    let input = build_slice!(content, len as usize);
    for &c in input {
        if c.is_ascii_lowercase() {
            return false;
        }
    }
    return true;
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformToUpperRegister() {
    let kw = SCTransformTableElmt {
        name: b"to_uppercase\0".as_ptr() as *const libc::c_char,
        desc: b"convert buffer to uppercase\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#to_uppercase\0".as_ptr() as *const libc::c_char,
        Setup: toupper_setup,
        flags: SIGMATCH_NOOPT,
        Transform: toupper_transform,
        Free: None,
        TransformValidate: Some(toupper_validate),
        TransformSerialize: None,
    };
    G_TRANSFORM_TOUPPER_ID = DetectHelperTransformRegister(&kw);
    if G_TRANSFORM_TOUPPER_ID < 0 {
        SCLogWarning!("Failed registering transform toupper");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tolower_transform() {
        let buf = b" A b C D ";
        let mut out = vec![0; buf.len()];
        tolower_transform_do(buf, &mut out);
        assert_eq!(out, b" a b c d ");
    }

    #[test]
    fn test_toupper_transform() {
        let buf = b" A b C D ";
        let mut out = vec![0; buf.len()];
        toupper_transform_do(buf, &mut out);
        assert_eq!(out, b" A B C D ");
    }
}
