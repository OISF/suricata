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

static mut G_TRANSFORM_URL_DECODE_ID: c_int = 0;

unsafe extern "C" fn url_decode_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _opt: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_URL_DECODE_ID, ptr::null_mut());
}

fn hex_value(i: u8) -> Option<u8> {
    match i {
        0x30..=0x39 => Some(i - 0x30),
        0x41..=0x46 => Some(i - 0x41 + 10),
        0x61..=0x66 => Some(i - 0x61 + 10),
        _ => None,
    }
}
fn url_decode_transform_do(input: &[u8], output: &mut [u8]) -> u32 {
    let mut state = (0u8, 0u8);
    let mut nb = 0;
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
            if i == b'+' {
                output[nb] = b' ';
            } else {
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

    let out_len = url_decode_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, out_len);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformUrlDecodeRegister() {
    let kw = SCTransformTableElmt {
        name: b"url_decode\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to decode urlencoded data before inspection\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/transforms.html#url-decode\0".as_ptr() as *const libc::c_char,
        Setup: Some(url_decode_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(url_decode_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
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
        let nb = url_decode_transform_do(&buf, &mut out);
        assert_eq!(&out[..nb as usize], b"Suricata is 'awesome!'%00%ZZ%4");
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        let nb = url_decode_transform_do(still_buf, &mut buf);
        assert_eq!(&still_buf[..nb as usize], b"Suricata is 'awesome!'%00%ZZ%4");
    }
}
