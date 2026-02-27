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

use crate::detect::uint::detect_parse_uint_with_unit;
use crate::detect::SIGMATCH_OPTIONAL_OPT;
use flate2::bufread::{GzDecoder, ZlibDecoder};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCInspectionBufferCheckAndExpand, SCInspectionBufferTruncate,
    SCTransformTableElmt, Signature,
};

use std::ffi::CStr;
use std::io::Read;
use std::os::raw::{c_int, c_void};

static mut G_TRANSFORM_GUNZIP_ID: c_int = 0;
static mut G_TRANSFORM_ZLIB_DEFLATE_ID: c_int = 0;

#[derive(Debug, PartialEq)]
struct DetectTransformDecompressData {
    max_size: u32,
}

const DEFAULT_MAX_SIZE: u32 = 1024;
// 16 MiB
const ABSOLUTE_MAX_SIZE: u32 = 16 * 1024 * 1024;

fn decompress_parse_do(s: &str) -> Option<DetectTransformDecompressData> {
    let mut max_size_parsed = None;
    for p in s.split(',') {
        let kv: Vec<&str> = p.split(' ').collect();
        if kv.len() != 2 {
            SCLogError!("Bad key value for decompress transform {}", p);
            return None;
        }
        match kv[0] {
            "max-size" => {
                if max_size_parsed.is_some() {
                    SCLogError!("Multiple max-size values for decompress transform");
                    return None;
                }
                if let Ok((_, val)) = detect_parse_uint_with_unit::<u32>(kv[1]) {
                    if val == 0 {
                        SCLogError!("max-size 0 for decompress transform would always produce an empty buffer");
                        return None;
                    } else if val > ABSOLUTE_MAX_SIZE {
                        SCLogError!("max-size is too big > {}", ABSOLUTE_MAX_SIZE);
                        return None;
                    }
                    max_size_parsed = Some(val);
                } else {
                    SCLogError!("Invalid max-size value for decompress transform {}", kv[1]);
                    return None;
                }
            }
            _ => {
                SCLogError!("Unknown key for decompress transform {}", kv[0]);
                return None;
            }
        }
    }
    let max_size = if let Some(val) = max_size_parsed {
        val
    } else {
        DEFAULT_MAX_SIZE
    };
    return Some(DetectTransformDecompressData { max_size });
}

unsafe fn decompress_parse(raw: *const std::os::raw::c_char) -> *mut c_void {
    if raw.is_null() {
        let ctx = DetectTransformDecompressData {
            max_size: DEFAULT_MAX_SIZE,
        };
        let boxed = Box::new(ctx);
        return Box::into_raw(boxed) as *mut _;
    }
    let raw: &CStr = CStr::from_ptr(raw); //unsafe
    if let Ok(s) = raw.to_str() {
        if let Some(ctx) = decompress_parse_do(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn gunzip_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, opt_str: *const std::os::raw::c_char,
) -> c_int {
    let ctx = decompress_parse(opt_str);
    if ctx.is_null() {
        return -1;
    }
    let r = SCDetectSignatureAddTransform(s, G_TRANSFORM_GUNZIP_ID, ctx);
    if r != 0 {
        decompress_free(de, ctx);
    }
    return r;
}

fn gunzip_transform_do(input: &[u8], output: &mut [u8]) -> Option<u32> {
    let mut gz = GzDecoder::new(input);
    return match gz.read(output) {
        Ok(n) => Some(n as u32),
        _ => None,
    };
}

pub type DecompressFn = fn(input: &[u8], output: &mut [u8]) -> Option<u32>;

unsafe fn decompress_transform(
    buffer: *mut InspectionBuffer, ctx: &DetectTransformDecompressData, decompress_fn: DecompressFn,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);
    let output = SCInspectionBufferCheckAndExpand(buffer, ctx.max_size);
    if output.is_null() {
        // allocation failure
        return;
    }
    let buf = std::slice::from_raw_parts_mut(output, ctx.max_size as usize);
    let mut tmp = Vec::new();
    let input = if std::ptr::eq(output, input.as_ptr()) {
        // need a temporary buffer as we cannot do the transfom in place
        // rather copy the input which should be smaller than the decompressed output
        // (Transform is tried in place when there are multiple chaines transforms)
        tmp.extend_from_slice(input);
        &tmp
    } else {
        input
    };

    //  this succeeds if decompressed data > max_size, but we get nb = max_size
    if let Some(nb) = decompress_fn(input, buf) {
        SCInspectionBufferTruncate(buffer, nb);
    } else {
        // decompression failure
        SCInspectionBufferTruncate(buffer, 0);
    }
}

unsafe extern "C" fn gunzip_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, ctx: *mut c_void,
) {
    let ctx = cast_pointer!(ctx, DetectTransformDecompressData);
    decompress_transform(buffer, ctx, gunzip_transform_do);
}

unsafe extern "C" fn decompress_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut DetectTransformDecompressData));
}

unsafe extern "C" fn decompress_id(data: *mut *const u8, length: *mut u32, ctx: *mut c_void) {
    if data.is_null() || length.is_null() || ctx.is_null() {
        return;
    }

    *data = ctx as *const u8;
    *length = std::mem::size_of::<DetectTransformDecompressData>() as u32; // 4
}

unsafe extern "C" fn zlib_deflate_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, opt_str: *const std::os::raw::c_char,
) -> c_int {
    let ctx = decompress_parse(opt_str);
    if ctx.is_null() {
        return -1;
    }
    let r = SCDetectSignatureAddTransform(s, G_TRANSFORM_ZLIB_DEFLATE_ID, ctx);
    if r != 0 {
        decompress_free(de, ctx);
    }
    return r;
}

fn zlib_deflate_transform_do(input: &[u8], output: &mut [u8]) -> Option<u32> {
    let mut gz = ZlibDecoder::new(input);
    return match gz.read(output) {
        Ok(n) => Some(n as u32),
        _ => None,
    };
}

unsafe extern "C" fn zlib_deflate_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, ctx: *mut c_void,
) {
    let ctx = cast_pointer!(ctx, DetectTransformDecompressData);
    decompress_transform(buffer, ctx, zlib_deflate_transform_do);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformGunzipRegister() {
    let kw = SCTransformTableElmt {
        name: b"gunzip\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer via gunzip decompression\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#gunzip\0".as_ptr() as *const libc::c_char,
        Setup: Some(gunzip_setup),
        flags: SIGMATCH_OPTIONAL_OPT,
        Transform: Some(gunzip_transform),
        Free: Some(decompress_free),
        TransformValidate: None,
        TransformId: Some(decompress_id),
    };
    unsafe {
        G_TRANSFORM_GUNZIP_ID = SCDetectHelperTransformRegister(&kw);
        if G_TRANSFORM_GUNZIP_ID < 0 {
            SCLogWarning!("Failed registering transform gunzip");
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformZlibDeflateRegister() {
    let kw = SCTransformTableElmt {
        name: b"zlib_deflate\0".as_ptr() as *const libc::c_char,
        desc: b"modify buffer via zlib decompression\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#zlib_deflate\0".as_ptr() as *const libc::c_char,
        Setup: Some(zlib_deflate_setup),
        flags: SIGMATCH_OPTIONAL_OPT,
        Transform: Some(zlib_deflate_transform),
        Free: Some(decompress_free),
        TransformValidate: None,
        TransformId: Some(decompress_id),
    };
    unsafe {
        G_TRANSFORM_ZLIB_DEFLATE_ID = SCDetectHelperTransformRegister(&kw);
        if G_TRANSFORM_ZLIB_DEFLATE_ID < 0 {
            SCLogWarning!("Failed registering transform zlib_deflate");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_parse() {
        assert!(decompress_parse_do("keywithoutvalue").is_none());
        assert!(decompress_parse_do("unknown 1").is_none());
        assert!(decompress_parse_do("max-size 0").is_none());
        assert!(decompress_parse_do("max-size 1,max-size 1").is_none());
        assert!(decompress_parse_do("max-size toto").is_none());
        assert_eq!(
            decompress_parse_do("max-size 1MiB"),
            Some(DetectTransformDecompressData {
                max_size: 1024 * 1024
            })
        );
    }
}
