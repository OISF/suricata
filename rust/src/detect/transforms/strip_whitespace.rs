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
    SCDetectSignatureAddTransform, SCInspectionBufferCheckAndExpand, SCInspectionBufferTruncate,
    SCTransformTableElmt, Signature,
};

use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_TRANSFORM_STRIP_WHITESPACE_ID: c_int = 0;

unsafe extern "C" fn strip_whitespace_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_STRIP_WHITESPACE_ID, ptr::null_mut());
}

fn strip_whitespace_transform_do(input: &[u8], output: &mut [u8]) -> u32 {
    let mut nb = 0;
    for (i, o) in input
        .iter()
        .filter(|c| !matches!(*c, b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' | b' '))
        .zip(output)
    {
        *o = *i;
        nb += 1;
    }
    // do not use faster copy_from_slice because input and output may overlap (point to the same data)
    return nb as u32;
}

unsafe extern "C" fn strip_whitespace_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = SCInspectionBufferCheckAndExpand(buffer, input_len);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, input_len as usize);

    let output_len = strip_whitespace_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, output_len);
}

unsafe extern "C" fn strip_whitespace_validate(
    content: *const u8, len: u16, _ctx: *mut c_void,
) -> bool {
    let input = build_slice!(content, len as usize);
    for &c in input {
        if matches!(c, b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' | b' ') {
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
        Setup: Some(strip_whitespace_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(strip_whitespace_transform),
        Free: None,
        TransformValidate: Some(strip_whitespace_validate),
        TransformId: None,
    };
    unsafe {
        G_TRANSFORM_STRIP_WHITESPACE_ID = SCDetectHelperTransformRegister(&kw);
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
        let mut out = vec![0; buf.len()];
        let exp = b"ABCD";
        assert_eq!(
            strip_whitespace_transform_do(buf, &mut out),
            exp.len() as u32
        );
        assert_eq!(&out[..exp.len()], exp);

        let buf = b"EFGH";
        let mut out = vec![0; buf.len()];
        let exp = b"EFGH";
        assert_eq!(
            strip_whitespace_transform_do(buf, &mut out),
            exp.len() as u32
        );
        assert_eq!(&out[..exp.len()], exp);

        let mut buf = Vec::new();
        buf.extend_from_slice(b"I  \t J");
        let mut out = vec![0; buf.len()];
        let exp = b"IJ";
        assert_eq!(
            strip_whitespace_transform_do(&buf, &mut out),
            exp.len() as u32
        );
        assert_eq!(&out[..exp.len()], exp);
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        assert_eq!(
            strip_whitespace_transform_do(still_buf, &mut buf),
            exp.len() as u32
        );
        assert_eq!(&still_buf[..exp.len()], b"IJ");
    }
}
