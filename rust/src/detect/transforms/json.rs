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

static mut G_TRANSFORM_JSON_DECODE_ID: c_int = 0;

unsafe extern "C" fn json_decode_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _opt: *const std::os::raw::c_char,
) -> c_int {
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_JSON_DECODE_ID, ptr::null_mut());
}

enum JsonParseState {
    OutsideString,
    InsideString,
    Escape,
    UnicodeEscape(u8, [u8; 4]),
}

fn json_hex_u16(hex: &[u8; 4]) -> Option<u16> {
    let mut value = 0u16;
    for &c in hex.iter() {
        value <<= 4;
        match c {
            b'0'..=b'9' => value |= (c - b'0') as u16,
            b'a'..=b'f' => value |= (c - b'a' + 10) as u16,
            b'A'..=b'F' => value |= (c - b'A' + 10) as u16,
            _ => return None,
        }
    }
    Some(value)
}

fn fill_high_surrogate(output: &mut [u8], nb: &mut usize, hs: u16) {
    output[*nb] = 0xe0 | ((hs >> 12) as u8);
    *nb += 1;
    output[*nb] = 0x80 | (((hs >> 6) & 0x3f) as u8);
    *nb += 1;
    output[*nb] = 0x80 | ((hs & 0x3f) as u8);
    *nb += 1;
}

fn json_decode_transform_do(input: &[u8], output: &mut [u8]) -> u32 {
    let mut state = JsonParseState::OutsideString;
    let mut nb = 0;
    let mut hs = None;
    for &i in input.iter() {
        match state {
            JsonParseState::OutsideString => {
                if i.is_ascii_whitespace() {
                    continue;
                }
                output[nb] = i;
                nb += 1;
                if i == b'"' {
                    state = JsonParseState::InsideString;
                }
            }
            JsonParseState::InsideString => {
                if i == b'\\' {
                    state = JsonParseState::Escape;
                    continue;
                }
                if let Some(h) = hs {
                    // we were waiting for a low surrogate, but got something else
                    fill_high_surrogate(output, &mut nb, h);
                    hs = None;
                }
                output[nb] = i;
                nb += 1;
                if i == b'"' {
                    state = JsonParseState::OutsideString;
                }
            }
            JsonParseState::Escape => {
                // see rfc8259 section 7
                if i != b'u' {
                    if let Some(h) = hs {
                        fill_high_surrogate(output, &mut nb, h);
                        hs = None;
                    }
                }
                match i {
                    b'"' | b'\\' | b'/' => {
                        output[nb] = i;
                        nb += 1;
                        state = JsonParseState::InsideString;
                    }
                    b'b' => {
                        output[nb] = b'\x08';
                        nb += 1;
                        state = JsonParseState::InsideString;
                    }
                    b'f' => {
                        output[nb] = b'\x0c';
                        nb += 1;
                        state = JsonParseState::InsideString;
                    }
                    b'n' => {
                        output[nb] = b'\n';
                        nb += 1;
                        state = JsonParseState::InsideString;
                    }
                    b'r' => {
                        output[nb] = b'\r';
                        nb += 1;
                        state = JsonParseState::InsideString;
                    }
                    b't' => {
                        output[nb] = b'\t';
                        nb += 1;
                        state = JsonParseState::InsideString;
                    }
                    b'u' => {
                        state = JsonParseState::UnicodeEscape(0, [0u8; 4]);
                    }
                    _ => {
                        // invalid escape sequence
                        // To handle in https://redmine.openinfosecfoundation.org/issues/8433
                        output[nb] = b'\\';
                        nb += 1;
                        output[nb] = i;
                        nb += 1;
                        state = JsonParseState::InsideString;
                    }
                }
            }
            JsonParseState::UnicodeEscape(n, mut r) => {
                r[n as usize] = i;
                // fill r with 4 characters
                if n < 3 {
                    state = JsonParseState::UnicodeEscape(n + 1, r);
                    // then try to hex-decode it
                } else if let Some(enc) = json_hex_u16(&r) {
                    // see rfc2044 UTF-8 definition
                    if let Some(h) = hs {
                        if enc >= 0xdc00 && enc <= 0xdfff {
                            // low surrogate
                            let codepoint: u32 =
                                0x10000 + (((h as u32 - 0xd800) << 10) | (enc as u32 - 0xdc00));
                            output[nb] = 0xf0 | ((codepoint >> 18) as u8);
                            nb += 1;
                            output[nb] = 0x80 | (((codepoint >> 12) & 0x3f) as u8);
                            nb += 1;
                            output[nb] = 0x80 | (((codepoint >> 6) & 0x3f) as u8);
                            nb += 1;
                            output[nb] = 0x80 | ((codepoint & 0x3f) as u8);
                            nb += 1;
                            state = JsonParseState::InsideString;
                            hs = None;
                            continue;
                        } else {
                            fill_high_surrogate(output, &mut nb, h);
                            hs = None;
                        }
                    }

                    if enc < 0x80 {
                        output[nb] = enc as u8;
                        nb += 1;
                    } else if enc < 0x800 {
                        output[nb] = 0xc0 | ((enc >> 6) as u8);
                        nb += 1;
                        output[nb] = 0x80 | ((enc & 0x3f) as u8);
                        nb += 1;
                    } else if enc < 0xd800 || enc > 0xdbff {
                        output[nb] = 0xe0 | ((enc >> 12) as u8);
                        nb += 1;
                        output[nb] = 0x80 | (((enc >> 6) & 0x3f) as u8);
                        nb += 1;
                        output[nb] = 0x80 | ((enc & 0x3f) as u8);
                        nb += 1;
                    } else {
                        // high surrogate
                        hs = Some(enc);
                    }
                    state = JsonParseState::InsideString;
                } else {
                    if let Some(h) = hs {
                        fill_high_surrogate(output, &mut nb, h);
                        hs = None;
                    }

                    // invalid escape sequence
                    // To handle in https://redmine.openinfosecfoundation.org/issues/8433
                    output[nb] = b'\\';
                    nb += 1;
                    output[nb] = b'u';
                    nb += 1;
                    for i in 0..4 {
                        output[nb] = r[i as usize];
                        nb += 1;
                    }
                    state = JsonParseState::InsideString;
                }
            }
        }
    }
    if let Some(h) = hs {
        fill_high_surrogate(output, &mut nb, h);
    }

    match state {
        // invalid state for finishing
        JsonParseState::Escape => {
            output[nb] = b'\\';
            nb += 1;
        }
        JsonParseState::UnicodeEscape(n, r) => {
            output[nb] = b'\\';
            nb += 1;
            output[nb] = b'u';
            nb += 1;
            for i in 0..=n {
                output[nb] = r[i as usize];
                nb += 1;
            }
        }
        _ => {}
    }
    return nb as u32;
}

unsafe extern "C" fn json_decode_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *const c_void,
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

    let out_len = json_decode_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, out_len);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformJsonDecodeRegister() {
    let kw = SCTransformTableElmt {
        name: b"json_decode\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer to decode and compact json-encoded data\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/transforms.html#json-decode\0".as_ptr() as *const libc::c_char,
        Setup: Some(json_decode_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(json_decode_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    G_TRANSFORM_JSON_DECODE_ID = SCDetectHelperTransformRegister(&kw);
    if G_TRANSFORM_JSON_DECODE_ID < 0 {
        SCLogWarning!("Failed registering transform json_decode");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_decode_transform() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"  \"remove space\"\t");
        let mut out = vec![0; buf.len()];
        let nb = json_decode_transform_do(&buf, &mut out);
        assert_eq!(&out[..nb as usize], b"\"remove space\"");
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        let nb = json_decode_transform_do(still_buf, &mut buf);
        assert_eq!(&still_buf[..nb as usize], b"\"remove space\"");

        buf = Vec::new();
        buf.extend_from_slice(b"\"decode\\tindent\"");
        let mut out = vec![0; buf.len()];
        let nb = json_decode_transform_do(&buf, &mut out);
        assert_eq!(&out[..nb as usize], b"\"decode\tindent\"");

        buf = Vec::new();
        buf.extend_from_slice(b"\"decod\\u0065 uni\"");
        let mut out = vec![0; buf.len()];
        let nb = json_decode_transform_do(&buf, &mut out);
        assert_eq!(&out[..nb as usize], b"\"decode uni\"");
        buf = Vec::new();

        buf.extend_from_slice(b"\"decode \\ud83d\\ude80 surrogate\"");
        let mut out = vec![0; buf.len()];
        let nb = json_decode_transform_do(&buf, &mut out);
        assert_eq!(
            &out[..nb as usize],
            b"\"decode \xf0\x9f\x9a\x80 surrogate\""
        );
    }
}
