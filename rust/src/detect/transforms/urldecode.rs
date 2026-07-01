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

use crate::detect::SIGMATCH_OPTIONAL_OPT;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCInspectionBufferCheckAndExpand, SCInspectionBufferTruncate,
    SCTransformTableElmt, Signature,
};

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

static mut G_TRANSFORM_URL_DECODE_ID: c_int = 0;

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
struct DetectTransformUrlDecodeData {
    only_decode_plus_after_query: bool,
}

fn url_decode_parse_do(input: &str) -> Option<DetectTransformUrlDecodeData> {
    let input = input.trim();
    if input == "only_decode_plus_after_query" {
        return Some(DetectTransformUrlDecodeData {
            only_decode_plus_after_query: true,
        });
    }
    return None;
}

unsafe fn url_decode_parse(c_arg: *const c_char) -> *mut DetectTransformUrlDecodeData {
    if c_arg.is_null() {
        let detect = DetectTransformUrlDecodeData::default();
        return Box::into_raw(Box::new(detect));
    }

    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match url_decode_parse_do(arg) {
            Some(detect) => return Box::into_raw(Box::new(detect)),
            None => return std::ptr::null_mut(),
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn url_decode_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, opt_str: *const c_char,
) -> c_int {
    let ctx = url_decode_parse(opt_str) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    let r = SCDetectSignatureAddTransform(s, G_TRANSFORM_URL_DECODE_ID, ctx);
    if r != 0 {
        url_decode_free(de, ctx);
    }
    return r;
}

unsafe extern "C" fn url_decode_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut DetectTransformUrlDecodeData));
}

fn hex_value(i: u8) -> Option<u8> {
    match i {
        0x30..=0x39 => Some(i - 0x30),
        0x41..=0x46 => Some(i - 0x41 + 10),
        0x61..=0x66 => Some(i - 0x61 + 10),
        _ => None,
    }
}
fn url_decode_transform_do(
    input: &[u8], output: &mut [u8], ctx: &DetectTransformUrlDecodeData,
) -> u32 {
    let mut state = (0u8, 0u8);
    let mut nb = 0;
    let mut in_query = false;
    for &i in input.iter() {
        if state.0 > 0 {
            if let Some(v) = hex_value(i) {
                if state.0 == 1 {
                    state = (2, i);
                } else {
                    output[nb] = v | (hex_value(state.1).unwrap() << 4);
                    nb += 1;
                    state = (0u8, 0u8);
                }
            } else {
                output[nb] = b'%';
                nb += 1;
                if state.0 > 1 {
                    output[nb] = state.1;
                    nb += 1;
                }
                output[nb] = i;
                nb += 1;
                state = (0u8, 0u8);
            }
        } else if i == b'%' {
            state = (1u8, 0u8);
        } else {
            if i == b'+' && (!ctx.only_decode_plus_after_query || in_query) {
                output[nb] = b' ';
            } else {
                if i == b'?' {
                    in_query = true;
                }
                output[nb] = i;
            }
            nb += 1;
        }
    }
    if state.0 > 0 {
        output[nb] = b'%';
        nb += 1;
        if state.0 == 2 {
            output[nb] = state.1;
            nb += 1;
        }
    }
    return nb as u32;
}

unsafe extern "C" fn url_decode_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, ctx: *const c_void,
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
    let ctx = cast_pointer!(ctx, DetectTransformUrlDecodeData);

    let out_len = url_decode_transform_do(input, output, ctx);

    SCInspectionBufferTruncate(buffer, out_len);
}

unsafe extern "C" fn url_decode_id(data: *mut *const u8, length: *mut u32, ctx: *const c_void) {
    if data.is_null() || length.is_null() || ctx.is_null() {
        return;
    }

    *data = ctx as *const u8;
    *length = std::mem::size_of::<DetectTransformUrlDecodeData>() as u32;
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformUrlDecodeRegister() {
    let kw = SCTransformTableElmt {
        name: b"url_decode\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to decode urlencoded data before inspection\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/transforms.html#url-decode\0".as_ptr() as *const libc::c_char,
        Setup: Some(url_decode_setup),
        flags: SIGMATCH_OPTIONAL_OPT,
        Transform: Some(url_decode_transform),
        Free: Some(url_decode_free),
        TransformValidate: None,
        TransformId: Some(url_decode_id),
    };
    G_TRANSFORM_URL_DECODE_ID = SCDetectHelperTransformRegister(&kw);
    if G_TRANSFORM_URL_DECODE_ID < 0 {
        SCLogWarning!("Failed registering transform dot_prefix");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode_transform() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"Suricata%20is+%27%61wesome%21%27%25%30%30%ZZ%4");
        let mut out = vec![0; buf.len()];
        let ctx = DetectTransformUrlDecodeData {
            only_decode_plus_after_query: false,
        };
        let nb = url_decode_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..nb as usize], b"Suricata is 'awesome!'%00%ZZ%4");
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        let nb = url_decode_transform_do(still_buf, &mut buf, &ctx);
        assert_eq!(&still_buf[..nb as usize], b"Suricata is 'awesome!'%00%ZZ%4");
    }
}
