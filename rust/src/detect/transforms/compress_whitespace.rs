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

static mut G_TRANSFORM_COMPRESS_WHITESPACE_ID: c_int = 0;

#[no_mangle]
unsafe extern "C" fn compress_whitespace_setup(
    _de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    return DetectSignatureAddTransform(s, G_TRANSFORM_COMPRESS_WHITESPACE_ID, ptr::null_mut());
}

fn compress_whitespace_transform_do(input: &[u8], output: &mut [u8]) -> u32 {
    let mut nb = 0;
    // seems faster than writing one byte at a time via
    // for (i, o) in input.iter().filter(|c| !matches!(*c, b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' | b' ')).zip(output)
    for subslice in
        input.split_inclusive(|c| matches!(*c, b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' | b' '))
    {
        // a subslice of length 1 not at the beginning is a space following another space
        if nb == 0
            || subslice.len() > 1
            || !matches!(
                subslice[0],
                b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' | b' '
            )
        {
            output[nb..nb + subslice.len()].copy_from_slice(subslice);
            nb += subslice.len();
        }
    }
    return nb as u32;
}

#[no_mangle]
unsafe extern "C" fn compress_whitespace_transform(buffer: *mut c_void, _ctx: *mut c_void) {
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

    let output_len = compress_whitespace_transform_do(input, output);

    InspectionBufferTruncate(buffer, output_len);
}

fn compress_whitespace_validate_do(input: &[u8]) -> bool {
    let mut space = false;
    for &c in input {
        if space {
            if matches!(c, b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' | b' ') {
                return false;
            }
            space = false;
        } else if matches!(c, b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' | b' ') {
            space = true;
        }
    }
    return true;
}

#[no_mangle]
unsafe extern "C" fn compress_whitespace_validate(
    content: *const u8, len: u16, _ctx: *mut c_void,
) -> bool {
    let input = build_slice!(content, len as usize);
    return compress_whitespace_validate_do(input);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformCompressWhitespaceRegister() {
    let kw = SCTransformTableElmt {
        name: b"compress_whitespace\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to compress consecutive whitespace characters into a single one before inspection\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/transforms.html#compress-whitespace\0".as_ptr() as *const libc::c_char,
        Setup: compress_whitespace_setup,
        flags: SIGMATCH_NOOPT,
        Transform: compress_whitespace_transform,
        Free: None,
        TransformValidate: Some(compress_whitespace_validate),
    };
    unsafe {
        G_TRANSFORM_COMPRESS_WHITESPACE_ID = DetectHelperTransformRegister(&kw);
        if G_TRANSFORM_COMPRESS_WHITESPACE_ID < 0 {
            SCLogWarning!("Failed registering transform compress_whitespace");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_whitespace_transform() {
        let buf = b" A B C D ";
        let mut out = vec![0; buf.len()];
        let exp = b" A B C D ";
        assert_eq!(
            compress_whitespace_transform_do(buf, &mut out),
            exp.len() as u32
        );
        assert_eq!(&out[..exp.len()], exp);
        let buf = b"EFGH";
        let mut out = vec![0; buf.len()];
        let exp = b"EFGH";
        assert_eq!(
            compress_whitespace_transform_do(buf, &mut out),
            exp.len() as u32
        );
        assert_eq!(&out[..exp.len()], exp);
        let buf = b"I  \t J";
        let mut out = vec![0; buf.len()];
        let exp = b"I J";
        assert_eq!(
            compress_whitespace_transform_do(buf, &mut out),
            exp.len() as u32
        );
        assert_eq!(&out[..exp.len()], exp);
    }

    #[test]
    fn test_compress_whitespace_validate() {
        assert!(compress_whitespace_validate_do(b" A B C D "));
        assert!(!compress_whitespace_validate_do(b" A B C D  "));
    }
}
