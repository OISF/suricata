/* Copyright (C) 2026 Open Information Security Foundation
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

use crate::detect::transforms::{
    get_byte_extract_buffer_location, resolve_byte_var, ByteExtractLocation, ByteVarError,
};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCInspectionBufferCheckAndExpand, SCInspectionBufferTruncate,
    SCTransformTableElmt, Signature, SIGMATCH_QUOTES_OPTIONAL,
};

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

static mut G_TRANSFORM_XOR_ID: c_int = 0;

/// Where to obtain the XOR key at transform time.
#[derive(Debug)]
enum XorKeySource {
    /// A static hex key provided in the rule.
    Static(Vec<u8>),
    /// Key from a byte_extract variable. The transform reads raw bytes from
    /// the buffer at the variable's location.
    Variable(ByteExtractLocation),
}

#[derive(Debug)]
struct DetectTransformXorData {
    key_source: XorKeySource,
    /// Offset in the buffer where XOR decoding starts. Bytes before this
    /// offset are copied unchanged. This allows skipping embedded key bytes.
    xor_offset: u32,
}

/// Intermediate parse result before variable resolution.
#[derive(Debug, PartialEq)]
struct XorParseResult {
    /// The key specifier — either a hex string or a variable name.
    key_str: String,
    /// Optional offset where XOR decoding starts.
    xor_offset: Option<u32>,
}

/// Parse the xor option string. Accepts:
///   - `"<hex_or_varname>"`
///   - `"offset <N>,<hex_or_varname>"`
fn xor_parse_options(input: &str) -> Option<XorParseResult> {
    let input = input.trim();
    if input.is_empty() {
        SCLogError!("XOR transform: empty argument");
        return None;
    }

    // Check for "offset" keyword followed by whitespace.
    if let Some(rest) = input
        .strip_prefix("offset")
        .filter(|r| r.starts_with(|c: char| c.is_ascii_whitespace()))
    {
        let rest = rest.trim_start();
        if let Some((offset_str, key_str)) = rest.split_once(',') {
            let offset_str = offset_str.trim();
            let key_str = key_str.trim();
            let offset: u32 = match offset_str.parse() {
                Ok(v) => v,
                Err(_) => {
                    SCLogError!("XOR transform: invalid offset value '{}'", offset_str);
                    return None;
                }
            };
            let key_str = strip_quotes(key_str);
            if key_str.is_empty() {
                SCLogError!("XOR transform: missing key after offset");
                return None;
            }
            return Some(XorParseResult {
                key_str: key_str.to_string(),
                xor_offset: Some(offset),
            });
        }
        SCLogError!("XOR transform: 'offset' requires format 'offset <N>,<key>'");
        return None;
    }

    Some(XorParseResult {
        key_str: input.to_string(),
        xor_offset: None,
    })
}

/// Strip surrounding double quotes from a string if present.
fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// Try to decode a string as a hex key. Returns `None` if the string is not
/// valid even-length hexadecimal or exceeds the maximum key length.
fn try_parse_hex_key(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(s)
        .ok()
        .filter(|k| k.len() <= usize::from(u8::MAX))
}

unsafe extern "C" fn xor_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, opt_str: *const c_char,
) -> c_int {
    let input = match CStr::from_ptr(opt_str).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let parsed = match xor_parse_options(input) {
        Some(p) => p,
        None => return -1,
    };

    let xor_offset = parsed.xor_offset.unwrap_or(0);

    // Try resolving as a byte variable first (avoids hex/variable ambiguity).
    let key_source = match resolve_byte_var(&parsed.key_str, s) {
        Ok(_index) => {
            // Get the buffer location for pre-transform extraction.
            match get_byte_extract_buffer_location(&parsed.key_str, s) {
                Some(location) => XorKeySource::Variable(location),
                None => {
                    SCLogError!(
                        "XOR transform: variable '{}' not found on the same buffer with an \
                         absolute offset (only byte_extract with absolute offset on the same \
                         buffer is currently supported)",
                        parsed.key_str
                    );
                    return -1;
                }
            }
        }
        Err(ByteVarError::NotFound) => {
            // Not a variable — try as a hex key.
            match try_parse_hex_key(&parsed.key_str) {
                Some(key) => XorKeySource::Static(key),
                None => {
                    SCLogError!(
                        "XOR transform: '{}' is not a known byte variable or valid hex key",
                        parsed.key_str
                    );
                    return -1;
                }
            }
        }
        Err(ByteVarError::InvalidName) => return -1,
    };

    let data = DetectTransformXorData {
        key_source,
        xor_offset,
    };
    let ctx = Box::into_raw(Box::new(data)) as *mut c_void;
    let r = SCDetectSignatureAddTransform(s, G_TRANSFORM_XOR_ID, ctx);
    if r != 0 {
        xor_free(de, ctx);
    }
    r
}

/// Apply XOR to `input[xor_offset..]`, copying `input[..xor_offset]` unchanged.
fn xor_transform_do(input: &[u8], output: &mut [u8], key: &[u8], xor_offset: usize) {
    output[..xor_offset].copy_from_slice(&input[..xor_offset]);
    let input = &input[xor_offset..];
    let output = &mut output[xor_offset..];
    for (chunk_in, chunk_out) in input.chunks(key.len()).zip(output.chunks_mut(key.len())) {
        for (inp, (out, k)) in chunk_in.iter().zip(chunk_out.iter_mut().zip(key.iter())) {
            *out = *inp ^ *k;
        }
    }
}

unsafe extern "C" fn xor_transform(
    _det_ctx: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = SCInspectionBufferCheckAndExpand(buffer, input_len);
    if output.is_null() {
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, input_len as usize);

    let ctx = cast_pointer!(ctx, DetectTransformXorData);
    let xor_offset = ctx.xor_offset as usize;

    if xor_offset > input.len() {
        return;
    }

    let key: &[u8] = match &ctx.key_source {
        XorKeySource::Static(key) => key,
        XorKeySource::Variable(location) => {
            let start = location.offset as usize;
            let end = start + location.nbytes as usize;
            if location.nbytes == 0 || end > input.len() {
                return;
            }
            &input[start..end]
        }
    };

    xor_transform_do(input, output, key, xor_offset);
    SCInspectionBufferTruncate(buffer, input_len);
}

unsafe extern "C" fn xor_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut DetectTransformXorData));
}

unsafe extern "C" fn xor_id(data: *mut *const u8, length: *mut u32, ctx: *mut c_void) {
    if data.is_null() || length.is_null() || ctx.is_null() {
        return;
    }

    let ctx = cast_pointer!(ctx, DetectTransformXorData);
    match &ctx.key_source {
        XorKeySource::Static(key) => {
            *data = key.as_ptr();
            *length = key.len() as u32;
        }
        _ => {
            *data = std::ptr::null();
            *length = 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformXorRegister() {
    let kw = SCTransformTableElmt {
        name: b"xor\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer via XOR decoding before inspection\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#xor\0".as_ptr() as *const libc::c_char,
        Setup: Some(xor_setup),
        flags: SIGMATCH_QUOTES_OPTIONAL,
        Transform: Some(xor_transform),
        Free: Some(xor_free),
        TransformValidate: None,
        TransformId: Some(xor_id),
    };
    unsafe {
        G_TRANSFORM_XOR_ID = SCDetectHelperTransformRegister(&kw);
        if G_TRANSFORM_XOR_ID < 0 {
            SCLogWarning!("Failed registering transform xor");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_key() {
        let r = xor_parse_options("0a0DC8ff").unwrap();
        assert_eq!(r.key_str, "0a0DC8ff");
        assert_eq!(r.xor_offset, None);
        assert_eq!(
            try_parse_hex_key(&r.key_str),
            Some(vec![0x0a, 0x0d, 0xc8, 0xff])
        );
    }

    #[test]
    fn test_parse_variable() {
        let r = xor_parse_options("xor_key").unwrap();
        assert_eq!(r.key_str, "xor_key");
        assert_eq!(r.xor_offset, None);
        assert!(try_parse_hex_key(&r.key_str).is_none());
    }

    #[test]
    fn test_parse_offset_variable() {
        let r = xor_parse_options("offset 1,xor_key").unwrap();
        assert_eq!(r.key_str, "xor_key");
        assert_eq!(r.xor_offset, Some(1));
    }

    #[test]
    fn test_parse_offset_quoted_variable() {
        let r = xor_parse_options("offset 1,\"xor_key\"").unwrap();
        assert_eq!(r.key_str, "xor_key");
        assert_eq!(r.xor_offset, Some(1));
    }

    #[test]
    fn test_parse_offset_hex() {
        let r = xor_parse_options("offset 4,0d0ac8ff").unwrap();
        assert_eq!(r.key_str, "0d0ac8ff");
        assert_eq!(r.xor_offset, Some(4));
        assert!(try_parse_hex_key(&r.key_str).is_some());
    }

    #[test]
    fn test_parse_empty() {
        assert!(xor_parse_options("").is_none());
    }

    #[test]
    fn test_parse_offset_missing_key() {
        assert!(xor_parse_options("offset 1,").is_none());
    }

    #[test]
    fn test_parse_offset_no_comma() {
        assert!(xor_parse_options("offset 1").is_none());
    }

    #[test]
    fn test_xor_transform_no_offset() {
        let input = b"example.com";
        let mut out = vec![0u8; input.len()];
        let key = hex::decode("0a0DC8ff").unwrap();
        xor_transform_do(input, &mut out, &key, 0);
        assert_eq!(out, b"ou\xa9\x92za\xad\xd1ib\xa5");
    }

    #[test]
    fn test_xor_transform_with_offset() {
        let key_byte = 0x42u8;
        let plaintext = b"hello";
        let mut body = vec![key_byte];
        for &b in plaintext {
            body.push(b ^ key_byte);
        }
        let mut out = vec![0u8; body.len()];
        xor_transform_do(&body, &mut out, &[key_byte], 1);
        assert_eq!(out[0], key_byte);
        assert_eq!(&out[1..], plaintext);
    }

    #[test]
    fn test_xor_transform_inplace() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"example.com");
        let mut out = vec![0; buf.len()];
        let key = hex::decode("0a0DC8ff").unwrap();
        xor_transform_do(&buf, &mut out, &key, 0);
        assert_eq!(out, b"ou\xa9\x92za\xad\xd1ib\xa5");
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        xor_transform_do(still_buf, &mut buf, &key, 0);
        assert_eq!(&still_buf, b"ou\xa9\x92za\xad\xd1ib\xa5");
    }

    #[test]
    fn test_xor_id() {
        let ctx = Box::new(DetectTransformXorData {
            key_source: XorKeySource::Static(vec![1, 2, 3, 4, 5]),
            xor_offset: 0,
        });

        let ctx_ptr: *const c_void = &*ctx as *const _ as *const c_void;

        let mut data_ptr: *const u8 = std::ptr::null();
        let mut length: u32 = 0;

        unsafe {
            xor_id(
                &mut data_ptr as *mut *const u8,
                &mut length as *mut u32,
                ctx_ptr as *mut c_void,
            );

            assert!(!data_ptr.is_null(), "data_ptr should not be null");
            assert_eq!(length, 5);

            let actual = std::slice::from_raw_parts(data_ptr, length as usize);
            assert_eq!(actual, &[1, 2, 3, 4, 5]);
        }
    }
}
