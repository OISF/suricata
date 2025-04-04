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
use crate::detect::SIGMATCH_QUOTES_MANDATORY;

use std::ffi::CStr;
use std::os::raw::{c_int, c_void};

static mut G_TRANSFORM_XOR_ID: c_int = 0;

#[derive(Debug, PartialEq)]
struct DetectTransformXorData {
    key: Vec<u8>,
}

fn xor_parse_do(i: &str) -> Option<DetectTransformXorData> {
    if i.len() % 2 != 0 {
        SCLogError!("XOR transform key's length must be an even number");
        return None;
    }
    if i.len() / 2 > usize::from(u8::MAX) {
        SCLogError!("Key length too big for XOR transform");
        return None;
    }
    if let Ok(key) = hex::decode(i) {
        return Some(DetectTransformXorData { key });
    }
    SCLogError!("XOR transform key must be hexadecimal characters only");
    return None;
}

unsafe fn xor_parse(raw: *const std::os::raw::c_char) -> *mut c_void {
    let raw: &CStr = CStr::from_ptr(raw); //unsafe
    if let Ok(s) = raw.to_str() {
        if let Some(ctx) = xor_parse_do(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn xor_setup(
    de: *mut c_void, s: *mut c_void, opt_str: *const std::os::raw::c_char,
) -> c_int {
    let ctx = xor_parse(opt_str);
    if ctx.is_null() {
        return -1;
    }
    let r = DetectSignatureAddTransform(s, G_TRANSFORM_XOR_ID, ctx);
    if r != 0 {
        xor_free(de, ctx);
    }
    return r;
}

fn xor_transform_do(input: &[u8], output: &mut [u8], ctx: &DetectTransformXorData) {
    let mut ki = 0;
    for (i, o) in input.iter().zip(output.iter_mut()) {
        *o = (*i) ^ ctx.key[ki];
        ki = (ki + 1) % ctx.key.len();
    }
}

unsafe extern "C" fn xor_transform(_det: *mut c_void, buffer: *mut c_void, ctx: *mut c_void) {
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

    let ctx = cast_pointer!(ctx, DetectTransformXorData);
    xor_transform_do(input, output, ctx);

    InspectionBufferTruncate(buffer, input_len);
}

unsafe extern "C" fn xor_free(_de: *mut c_void, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut DetectTransformXorData));
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformXorRegister() {
    let kw = SCTransformTableElmt {
        name: b"xor\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer via XOR decoding before inspection\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#xor\0".as_ptr() as *const libc::c_char,
        Setup: xor_setup,
        flags: SIGMATCH_QUOTES_MANDATORY,
        Transform: xor_transform,
        Free: Some(xor_free),
        TransformValidate: None,
    };
    unsafe {
        G_TRANSFORM_XOR_ID = DetectHelperTransformRegister(&kw);
        if G_TRANSFORM_XOR_ID < 0 {
            SCLogWarning!("Failed registering transform dot_prefix");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_parse() {
        assert!(xor_parse_do("nohexa").is_none());
        let key = b"\x0a\x0d\xc8\xff";
        assert_eq!(
            xor_parse_do("0a0DC8ff"),
            Some(DetectTransformXorData { key: key.to_vec() })
        );
    }

    #[test]
    fn test_xor_transform() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"example.com");
        let mut out = vec![0; buf.len()];
        let ctx = xor_parse_do("0a0DC8ff").unwrap();
        xor_transform_do(&buf, &mut out, &ctx);
        assert_eq!(out, b"ou\xa9\x92za\xad\xd1ib\xa5");
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        xor_transform_do(still_buf, &mut buf, &ctx);
        assert_eq!(&still_buf, b"ou\xa9\x92za\xad\xd1ib\xa5");
    }
}
