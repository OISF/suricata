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

static mut G_TRANSFORM_HEADER_LOWER_ID: c_int = 0;
static mut G_TRANSFORM_STRIP_PSEUDO_ID: c_int = 0;

unsafe extern "C" fn header_lowersetup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_HEADER_LOWER_ID, ptr::null_mut());
}

fn header_lowertransform_do(input: &[u8], output: &mut [u8]) {
    let mut state_value = false; // false in name, true in value
    for (i, o) in input.iter().zip(output.iter_mut()) {
        if !state_value {
            if (*i) == b':' {
                state_value = true;
                *o = *i;
            } else {
                *o = (*i).to_ascii_lowercase();
            }
        } else {
            *o = *i;
            if (*i) == b'\n' {
                state_value = false;
            }
        }
    }
}

unsafe extern "C" fn header_lowertransform(
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

    header_lowertransform_do(input, output);

    SCInspectionBufferTruncate(buffer, input_len);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformHeaderLowercaseRegister() {
    let kw = SCTransformTableElmt {
        name: b"header_lowercase\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer via lowercaseing header names\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#header_lowercase\0".as_ptr() as *const libc::c_char,
        Setup: Some(header_lowersetup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(header_lowertransform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    G_TRANSFORM_HEADER_LOWER_ID = SCDetectHelperTransformRegister(&kw);
    if G_TRANSFORM_HEADER_LOWER_ID < 0 {
        SCLogWarning!("Failed registering transform tolower");
    }
}

unsafe extern "C" fn strip_pseudo_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_STRIP_PSEUDO_ID, ptr::null_mut());
}

fn strip_pseudo_transform_do(input: &[u8], output: &mut [u8]) -> u32 {
    let mut nb = 0;
    let mut inb = 0;
    let same = std::ptr::eq(output.as_ptr(), input.as_ptr());
    for subslice in input.split_inclusive(|c| *c == b'\n') {
        if !subslice.is_empty() && subslice[0] != b':' {
            if same {
                output.copy_within(inb..inb + subslice.len(), nb);
            } else {
                output[nb..nb + subslice.len()].copy_from_slice(subslice);
            }
            nb += subslice.len();
        }
        inb += subslice.len();
    }
    return nb as u32;
}

unsafe extern "C" fn strip_pseudo_transform(
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

    let out_len = strip_pseudo_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, out_len);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformStripPseudoHeadersRegister() {
    let kw = SCTransformTableElmt {
        name: b"strip_pseudo_headers\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer via stripping pseudo headers\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#strip_pseudo_headers\0".as_ptr() as *const libc::c_char,
        Setup: Some(strip_pseudo_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(strip_pseudo_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    G_TRANSFORM_STRIP_PSEUDO_ID = SCDetectHelperTransformRegister(&kw);
    if G_TRANSFORM_STRIP_PSEUDO_ID < 0 {
        SCLogWarning!("Failed registering transform toupper");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_lowertransform() {
        let buf = b"Header1: Value1\nheader2:Value2\n";
        let mut out = vec![0; buf.len()];
        header_lowertransform_do(buf, &mut out);
        assert_eq!(out, b"header1: Value1\nheader2:Value2\n");
    }

    #[test]
    fn test_strip_pseudo_transform() {
        let buf = b"Header1: Value1\n:method:get\nheader2:Value2\n";
        let mut out = vec![0; buf.len()];
        let nb = strip_pseudo_transform_do(buf, &mut out);
        assert_eq!(&out[..nb as usize], b"Header1: Value1\nheader2:Value2\n");
        let buf = b":method:get";
        let mut out = vec![0; buf.len()];
        let nb = strip_pseudo_transform_do(buf, &mut out);
        assert_eq!(nb, 0);
        let buf = b"Header1: Value1\n:method:get";
        let mut out = vec![0; buf.len()];
        let nb = strip_pseudo_transform_do(buf, &mut out);
        assert_eq!(&out[..nb as usize], b"Header1: Value1\n");
        let buf = b":method:get\nheader2:Value2";
        let mut out = vec![0; buf.len()];
        let nb = strip_pseudo_transform_do(buf, &mut out);
        assert_eq!(&out[..nb as usize], b"header2:Value2");
        let mut buf = Vec::new();
        buf.extend_from_slice(
            b"Header1: Value1\n:method:get\nheader2:Value2\n:scheme:https\nheader3:Value3\n",
        );
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        let nb = strip_pseudo_transform_do(still_buf, &mut buf);
        assert_eq!(
            &still_buf[..nb as usize],
            b"Header1: Value1\nheader2:Value2\nheader3:Value3\n"
        );
    }
}
