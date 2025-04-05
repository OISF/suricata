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

use crate::detect::SIGMATCH_NOOPT;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCTransformTableElmt, Signature, SCInspectionBufferCheckAndExpand,
    SCInspectionBufferTruncate,
};

use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_TRANSFORM_DOT_PREFIX_ID: c_int = 0;

unsafe extern "C" fn dot_prefix_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_DOT_PREFIX_ID, ptr::null_mut());
}

fn dot_prefix_transform_do(input: &[u8], output: &mut [u8]) {
    if std::ptr::eq(output.as_ptr(), input.as_ptr()) {
        output.copy_within(0..input.len(), 1);
    } else {
        output[1..].copy_from_slice(input);
    }
    output[0] = b'.';
}

unsafe extern "C" fn dot_prefix_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *mut c_void,
) {
    let input_len = (*buffer).inspect_len;
    if input_len == 0 {
        return;
    }
    let output = SCInspectionBufferCheckAndExpand(buffer, input_len + 1);
    if output.is_null() {
        // allocation failure
        return;
    }
    // get input after possible realloc
    let input = (*buffer).inspect;
    if input.is_null() {
        // allocation failure
        return;
    }
    let input = build_slice!(input, input_len as usize);
    let output = std::slice::from_raw_parts_mut(output, (input_len + 1) as usize);

    dot_prefix_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, input_len + 1);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformDotPrefixRegister() {
    let kw = SCTransformTableElmt {
        name: b"dotprefix\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to extract the dotprefix\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#dotprefix\0".as_ptr() as *const libc::c_char,
        Setup: Some(dot_prefix_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(dot_prefix_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    unsafe {
        G_TRANSFORM_DOT_PREFIX_ID = SCDetectHelperTransformRegister(&kw);
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
        let mut buf = Vec::with_capacity(b"hello.example.com".len() + 1);
        buf.extend_from_slice(b"hello.example.com");
        let mut out = vec![0; b"hello.example.com".len() + 1];
        dot_prefix_transform_do(&buf, &mut out);
        assert_eq!(out, b".hello.example.com");
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        buf.push(b'.');
        dot_prefix_transform_do(still_buf, &mut buf);
        assert_eq!(&buf, b".hello.example.com");
    }
}
