/* Copyright (C) 2024-2026 Open Information Security Foundation
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

use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCInspectionBufferCheckAndExpand, SCInspectionBufferTruncate,
    SCTransformTableElmt, Signature, SIGMATCH_QUOTES_OPTIONAL,
};

use super::varkey::{parse_var_spec, strip_keyword_prefix, var_key_bytes, VarKeyLocation};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

static mut G_TRANSFORM_XOR_ID: c_int = 0;

/// Where to obtain the XOR key at transform time.
#[derive(Debug)]
enum XorKeySource {
    /// A static hex key provided in the rule.
    Static(Vec<u8>),
    /// Key read directly from the inspection buffer at a fixed location.
    Variable(VarKeyLocation),
}

#[derive(Debug)]
struct DetectTransformXorData {
    key_source: XorKeySource,
    /// Offset in the buffer where XOR decoding starts. Bytes before this
    /// offset are copied unchanged. This allows skipping embedded key bytes.
    xor_offset: u32,
    /// Precomputed identity bytes returned by xor_id. Layout:
    ///   Static:   [0x00, key_bytes..., xor_offset_le4]
    ///   Variable: [0x01, key_offset_lo, key_offset_hi, nbytes, xor_offset_le4]
    /// The leading discriminant byte ensures static and variable identities
    /// can never collide. Including xor_offset ensures rules with the same
    /// key but different decode-start positions get independent buffers.
    id_buf: Vec<u8>,
}

/// Parsed key specifier — either decoded key bytes or an inline buffer location.
#[derive(Debug, PartialEq)]
enum XorKeySpec {
    Hex(Vec<u8>),
    Var(VarKeyLocation),
}

/// Intermediate parse result.
#[derive(Debug, PartialEq)]
struct XorParseResult {
    key_spec: XorKeySpec,
    /// Optional offset where XOR decoding starts.
    xor_offset: Option<u32>,
}

/// Try to decode a string as a hex key. Returns `None` if the string is not
/// valid hexadecimal, is empty, or exceeds 255 bytes.
fn try_parse_hex_key(s: &str) -> Option<Vec<u8>> {
    hex::decode(s)
        .ok()
        .filter(|k| !k.is_empty() && k.len() <= usize::from(u8::MAX))
}

/// Parse a key specifier — either `var <nbytes> <offset>` or a hex string.
fn parse_key_part(s: &str) -> Option<XorKeySpec> {
    if let Some(rest) = strip_keyword_prefix(s, "var") {
        if let Some(loc) = parse_var_spec(rest) {
            return Some(XorKeySpec::Var(loc));
        }
        SCLogError!("XOR transform: 'var' requires format 'var <nbytes> <offset>'");
        return None;
    }
    let s = strip_quotes(s);
    if s.is_empty() {
        SCLogError!("XOR transform: missing hex key");
        return None;
    }
    match try_parse_hex_key(s) {
        Some(key) => Some(XorKeySpec::Hex(key)),
        None => {
            SCLogError!("XOR transform: '{}' is not a valid hex key", s);
            None
        }
    }
}

/// Parse the xor option string. Accepts:
///   - `<hex_key>`
///   - `var <nbytes> <offset>`
///   - `offset <N>,<hex_key>`
///   - `offset <N>,var <nbytes> <offset>`
fn xor_parse_options(input: &str) -> Option<XorParseResult> {
    let input = input.trim();
    if input.is_empty() {
        SCLogError!("XOR transform: empty argument");
        return None;
    }

    if let Some(rest) = strip_keyword_prefix(input, "offset") {
        let (offset_str, key_part) = match rest.split_once(',') {
            Some(pair) => pair,
            None => {
                SCLogError!("XOR transform: 'offset' requires format 'offset <N>,<key>'");
                return None;
            }
        };
        let xor_offset: u32 = match offset_str.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                SCLogError!(
                    "XOR transform: invalid offset value '{}'",
                    offset_str.trim()
                );
                return None;
            }
        };
        return Some(XorParseResult {
            key_spec: parse_key_part(key_part.trim())?,
            xor_offset: Some(xor_offset),
        });
    }

    Some(XorParseResult {
        key_spec: parse_key_part(input)?,
        xor_offset: None,
    })
}

/// Strip surrounding double quotes from a string if present.
fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

fn xor_build_ctx(input: &str) -> Option<DetectTransformXorData> {
    let parsed = xor_parse_options(input)?;
    let xor_offset = parsed.xor_offset.unwrap_or(0);
    let key_source = match parsed.key_spec {
        XorKeySpec::Hex(key) => XorKeySource::Static(key),
        XorKeySpec::Var(loc) => XorKeySource::Variable(loc),
    };
    let id_buf = match &key_source {
        XorKeySource::Static(key) => {
            let mut buf = vec![0x00];
            buf.extend_from_slice(key);
            buf.extend_from_slice(&xor_offset.to_le_bytes());
            buf
        }
        XorKeySource::Variable(loc) => {
            let [lo, hi] = loc.offset.to_le_bytes();
            let mut buf = vec![0x01, lo, hi, loc.nbytes];
            buf.extend_from_slice(&xor_offset.to_le_bytes());
            buf
        }
    };
    Some(DetectTransformXorData {
        key_source,
        xor_offset,
        id_buf,
    })
}

unsafe extern "C" fn xor_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, opt_str: *const c_char,
) -> c_int {
    let input = match CStr::from_ptr(opt_str).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let ctx = match xor_build_ctx(input) {
        Some(d) => Box::into_raw(Box::new(d)) as *mut c_void,
        None => return -1,
    };
    let r = SCDetectSignatureAddTransform(s, G_TRANSFORM_XOR_ID, ctx);
    if r != 0 {
        xor_free(de, ctx);
    }
    r
}

/// Apply XOR to `input[xor_offset..]`, copying `input[..xor_offset]` unchanged.
/// The copy is required because the output is a freshly allocated buffer that
/// must contain the complete result at the same length as input.
fn xor_transform_do(input: &[u8], output: &mut [u8], key: &[u8], xor_offset: usize) {
    output[..xor_offset].copy_from_slice(&input[..xor_offset]);
    for (i, (inp, out)) in input[xor_offset..]
        .iter()
        .zip(output[xor_offset..].iter_mut())
        .enumerate()
    {
        *out = *inp ^ key[i % key.len()];
    }
}

unsafe extern "C" fn xor_transform(
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
        XorKeySource::Variable(location) => match var_key_bytes(input, location) {
            Some(k) => k,
            None => return,
        },
    };

    xor_transform_do(input, output, key, xor_offset);
    SCInspectionBufferTruncate(buffer, input_len);
}

unsafe extern "C" fn xor_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut DetectTransformXorData));
}

unsafe extern "C" fn xor_id(data: *mut *const u8, length: *mut u32, ctx: *const c_void) {
    if data.is_null() || length.is_null() || ctx.is_null() {
        return;
    }

    let ctx = cast_pointer!(ctx, DetectTransformXorData);
    *data = ctx.id_buf.as_ptr();
    *length = ctx.id_buf.len() as u32;
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
        assert_eq!(r.key_spec, XorKeySpec::Hex(vec![0x0a, 0x0d, 0xc8, 0xff]));
        assert_eq!(r.xor_offset, None);
        assert_eq!(
            try_parse_hex_key("0a0DC8ff"),
            Some(vec![0x0a, 0x0d, 0xc8, 0xff])
        );
    }

    #[test]
    fn test_parse_variable() {
        let r = xor_parse_options("var 1 0").unwrap();
        assert_eq!(
            r.key_spec,
            XorKeySpec::Var(VarKeyLocation {
                nbytes: 1,
                offset: 0
            })
        );
        assert_eq!(r.xor_offset, None);
    }

    #[test]
    fn test_parse_variable_large_offset() {
        let r = xor_parse_options("var 4 1024").unwrap();
        assert_eq!(
            r.key_spec,
            XorKeySpec::Var(VarKeyLocation {
                nbytes: 4,
                offset: 1024
            })
        );
    }

    #[test]
    fn test_parse_offset_variable() {
        let r = xor_parse_options("offset 1,var 1 0").unwrap();
        assert_eq!(
            r.key_spec,
            XorKeySpec::Var(VarKeyLocation {
                nbytes: 1,
                offset: 0
            })
        );
        assert_eq!(r.xor_offset, Some(1));
    }

    #[test]
    fn test_parse_offset_hex() {
        let r = xor_parse_options("offset 4,0d0ac8ff").unwrap();
        assert_eq!(r.key_spec, XorKeySpec::Hex(vec![0x0d, 0x0a, 0xc8, 0xff]));
        assert_eq!(r.xor_offset, Some(4));
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
    fn test_parse_empty_hex_key() {
        assert!(try_parse_hex_key("").is_none());
    }

    #[test]
    fn test_parse_hex_key_odd_length() {
        assert!(try_parse_hex_key("abc").is_none());
    }

    #[test]
    fn test_parse_variable_missing_offset() {
        assert!(xor_parse_options("var 1").is_none());
    }

    #[test]
    fn test_parse_variable_nbytes_overflow() {
        // 256 does not fit in u8.
        assert!(xor_parse_options("var 256 0").is_none());
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
    fn test_xor_transform_roundtrip() {
        // XOR is its own inverse: applying the same key twice recovers the original.
        let input = b"example.com";
        let key = hex::decode("0a0DC8ff").unwrap();
        let mut encrypted = vec![0u8; input.len()];
        xor_transform_do(input, &mut encrypted, &key, 0);
        let mut recovered = vec![0u8; encrypted.len()];
        xor_transform_do(&encrypted, &mut recovered, &key, 0);
        assert_eq!(recovered, input);
    }

    // Build an id_buf for a variable key the same way xor_build_ctx does.
    fn make_id_buf_var(key_offset: u16, nbytes: u8, xor_offset: u32) -> Vec<u8> {
        let [lo, hi] = key_offset.to_le_bytes();
        let mut buf = vec![0x01, lo, hi, nbytes];
        buf.extend_from_slice(&xor_offset.to_le_bytes());
        buf
    }

    // Build an id_buf for a static key the same way xor_build_ctx does.
    fn make_id_buf_static(key: &[u8], xor_offset: u32) -> Vec<u8> {
        let mut buf = vec![0x00];
        buf.extend_from_slice(key);
        buf.extend_from_slice(&xor_offset.to_le_bytes());
        buf
    }

    #[test]
    fn test_xor_id_variable_key() {
        // key_offset=0, nbytes=1, xor_offset=0 → [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        let id_buf = make_id_buf_var(0, 1, 0);
        let ctx = Box::new(DetectTransformXorData {
            key_source: XorKeySource::Variable(VarKeyLocation {
                offset: 0,
                nbytes: 1,
            }),
            xor_offset: 0,
            id_buf,
        });
        let ctx_ptr: *const c_void = &*ctx as *const _ as *const c_void;
        let mut data_ptr: *const u8 = std::ptr::null();
        let mut length: u32 = 0;
        unsafe {
            xor_id(&mut data_ptr, &mut length, ctx_ptr as *mut c_void);
            assert!(!data_ptr.is_null());
            assert_eq!(length, 8);
            assert_eq!(
                std::slice::from_raw_parts(data_ptr, 8),
                &[0x01u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
            );
        }
    }

    #[test]
    fn test_xor_id_variable_key_large_offset() {
        // key_offset=300 (0x012c LE = [0x2c, 0x01]), nbytes=4, xor_offset=0
        let id_buf = make_id_buf_var(300, 4, 0);
        let ctx = Box::new(DetectTransformXorData {
            key_source: XorKeySource::Variable(VarKeyLocation {
                offset: 300,
                nbytes: 4,
            }),
            xor_offset: 0,
            id_buf,
        });
        let ctx_ptr: *const c_void = &*ctx as *const _ as *const c_void;
        let mut data_ptr: *const u8 = std::ptr::null();
        let mut length: u32 = 0;
        unsafe {
            xor_id(&mut data_ptr, &mut length, ctx_ptr as *mut c_void);
            assert!(!data_ptr.is_null());
            assert_eq!(length, 8);
            assert_eq!(
                std::slice::from_raw_parts(data_ptr, 8),
                &[0x01u8, 0x2c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]
            );
        }
    }

    #[test]
    fn test_xor_id_variable_key_nonzero_xor_offset() {
        // Verify that two rules with the same key location but different xor_offset
        // produce distinct id_bufs and therefore get independent buffers.
        let id_a = make_id_buf_var(0, 1, 0);
        let id_b = make_id_buf_var(0, 1, 5);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn test_var_key_transform() {
        // Buffer: [key_byte, encoded[0], encoded[1], ...]
        // Key is 1 byte at offset 0; XOR starts at offset 1.
        let key_byte = 0x42u8;
        let plaintext = b"world";
        let mut buf = vec![key_byte];
        buf.extend(plaintext.iter().map(|&b| b ^ key_byte));

        let loc = VarKeyLocation {
            offset: 0,
            nbytes: 1,
        };
        let key = var_key_bytes(&buf, &loc).expect("key should be in bounds");

        let mut out = vec![0u8; buf.len()];
        xor_transform_do(&buf, &mut out, key, 1);

        assert_eq!(out[0], key_byte);
        assert_eq!(&out[1..], plaintext.as_ref());
    }

    #[test]
    fn test_xor_id() {
        // Static key [1,2,3,4,5] with xor_offset=0: id = [0x00, key_bytes..., 0,0,0,0]
        let key = vec![1u8, 2, 3, 4, 5];
        let id_buf = make_id_buf_static(&key, 0);
        let ctx = Box::new(DetectTransformXorData {
            key_source: XorKeySource::Static(key),
            xor_offset: 0,
            id_buf,
        });

        let ctx_ptr: *const c_void = &*ctx as *const _ as *const c_void;
        let mut data_ptr: *const u8 = std::ptr::null();
        let mut length: u32 = 0;

        unsafe {
            xor_id(&mut data_ptr, &mut length, ctx_ptr as *mut c_void);
            assert!(!data_ptr.is_null());
            assert_eq!(length, 10);
            let actual = std::slice::from_raw_parts(data_ptr, length as usize);
            assert_eq!(actual, &[0, 1, 2, 3, 4, 5, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn test_xor_id_static_key_nonzero_xor_offset() {
        // Two rules with the same static key but different xor_offset must
        // produce distinct identities.
        let key = vec![0x42u8];
        let id_a = make_id_buf_static(&key, 0);
        let id_b = make_id_buf_static(&key, 1);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn test_xor_id_static_vs_variable_no_collision() {
        // A 3-byte static key whose bytes happen to equal [offset_lo, offset_hi, nbytes]
        // of a variable key must still produce a distinct identity.
        let key = vec![0x00u8, 0x00, 0x01];
        let static_id = make_id_buf_static(&key, 0);
        let var_id = make_id_buf_var(0, 1, 0);
        assert_ne!(static_id, var_id);
    }

    #[test]
    fn test_parse_offset_hex_quoted() {
        // The inner hex key in "offset N,..." may be quoted; strip_quotes must handle it.
        let r = xor_parse_options("offset 4,\"0d0ac8ff\"").unwrap();
        assert_eq!(r.key_spec, XorKeySpec::Hex(vec![0x0d, 0x0a, 0xc8, 0xff]));
        assert_eq!(r.xor_offset, Some(4));
    }
}
