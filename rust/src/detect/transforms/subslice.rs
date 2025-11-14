/* Copyright (C) 2025 Open Information Security Foundation
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

use num::abs;
use std::os::raw::{c_int, c_void};

use std::ffi::CStr;

static mut G_TRANSFORM_SUBSLICE_ID: c_int = 0;

#[derive(Debug, PartialEq)]
struct DetectTransformSubsliceData {
    pub start: isize,
    pub end: Option<isize>,
}

impl Default for DetectTransformSubsliceData {
    fn default() -> Self {
        DetectTransformSubsliceData {
            start: 0,
            end: None,
        }
    }
}

fn subslice_do_parse(i: &str) -> Option<DetectTransformSubsliceData> {
    let i = i.trim().strip_prefix('[')?.strip_suffix(']')?;
    let parts: Vec<_> = i.split(',').map(str::trim).collect();

    match parts.as_slice() {
        [start] => {
            let start = start.parse::<isize>().ok()?;
            Some(DetectTransformSubsliceData { start, end: None })
        }
        [start, end] => {
            let start = start.parse::<isize>().ok()?;
            let end = end.parse::<isize>().ok()?;
            Some(DetectTransformSubsliceData {
                start,
                end: Some(end),
            })
        }
        _ => None,
    }
}

unsafe fn subslice_parse(raw: *const std::os::raw::c_char) -> *mut c_void {
    let raw: &CStr = CStr::from_ptr(raw);
    if let Ok(s) = raw.to_str() {
        if let Some(ctx) = subslice_do_parse(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn subslice_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut DetectTransformSubsliceData));
}

unsafe extern "C" fn subslice_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, opt_str: *const std::os::raw::c_char,
) -> c_int {
    if opt_str.is_null() {
        return -1;
    }

    let ctx = subslice_parse(opt_str);
    if ctx.is_null() {
        return -1;
    }

    let r = SCDetectSignatureAddTransform(s, G_TRANSFORM_SUBSLICE_ID, ctx);
    if r != 0 {
        subslice_free(de, ctx);
    }

    return r;
}

fn subslice_apply<'a>(data: &'a [u8], ctx: &DetectTransformSubsliceData) -> Option<&'a [u8]> {
    let len = data.len() as isize;

    if abs(ctx.start) > len {
        return None;
    }

    let mut start = if ctx.start >= 0 { ctx.start } else { len - (-ctx.start) };
    let mut end = match ctx.end {
        None => len,
        Some(e) if e < 0 => {
            let abs_end = start + e;
            if abs_end < 0 {
                return None;
            }
            abs_end
        }
        Some(e) => {
            let end_pos = start + e;
            if end_pos > len {
                return None;
            }
            end_pos
        }
    };

    // Rearrange start/end when offset is negative
    let t = start;
    if end < start {
        start = end;
        end = t;
    }

    Some(&data[start as usize..end as usize])
}

fn subslice_transform_do(
    input: &[u8], output: &mut [u8], ctx: &DetectTransformSubsliceData,
) -> u32 {
    let Some(slice) = subslice_apply(input, ctx) else {
        return 0;
    };

    // copy result into output
    let len = slice.len();
    output[..len].copy_from_slice(slice);

    len as u32
}

unsafe extern "C" fn subslice_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }

    let output = SCInspectionBufferCheckAndExpand(buffer, input_len);
    if output.is_null() {
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, input_len as usize);
    let ctx = cast_pointer!(ctx, DetectTransformSubsliceData);
    let input = build_slice!(input, input_len as usize);
    let out_length = subslice_transform_do(input, output, ctx);
    SCInspectionBufferTruncate(buffer, out_length);
}

unsafe extern "C" fn subslice_id(data: *mut *const u8, length: *mut u32, ctx: *mut c_void) {
    if data.is_null() || length.is_null() || ctx.is_null() {
        return;
    }

    // This works because the structure is flat
    // Once variables are really implemented, we should investigate if the structure should own
    // its serialization or just borrow it to a caller
    *data = ctx as *const u8;
    *length = std::mem::size_of::<DetectTransformSubsliceData>() as u32;
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformSubsliceRegister() {
    let kw = SCTransformTableElmt {
        name: b"subslice\0".as_ptr() as *const libc::c_char,
        desc: b"create a subslice from the current buffer\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#subslice\0".as_ptr() as *const libc::c_char,
        Setup: Some(subslice_setup),
        flags: SIGMATCH_OPTIONAL_OPT,
        Transform: Some(subslice_transform),
        Free: Some(subslice_free),
        TransformValidate: None,
        TransformId: Some(subslice_id),
    };
    unsafe {
        G_TRANSFORM_SUBSLICE_ID = SCDetectHelperTransformRegister(&kw);
        if G_TRANSFORM_SUBSLICE_ID < 0 {
            SCLogWarning!("Failed registering transform subslice");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subslice_parse_invalid() {
        assert!(subslice_do_parse("f, y").is_none());
        assert!(subslice_do_parse("0, 1").is_none());
        assert!(subslice_do_parse("[0:-10]").is_none());
        assert!(subslice_do_parse("[1 1").is_none());
        assert!(subslice_do_parse("").is_none());
    }

    #[test]
    fn test_subslice_parse_valid() {
        assert!(subslice_do_parse("[0, 9]").is_some());
        assert!(subslice_do_parse("[0,9]").is_some());
        assert!(subslice_do_parse("[1, 1]").is_some());
        assert!(subslice_do_parse("[1]").is_some());
        assert!(subslice_do_parse("[-1]").is_some());
        assert!(subslice_do_parse("[0, -3]").is_some());
        assert!(subslice_do_parse("[-10, -2]").is_some());
    }

    #[test]
    fn test_subslice_transform_offset() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; buf.len() - 1];
        let ctx = subslice_do_parse("[1]").unwrap();
        subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..15], b"his is suricata");
    }

    #[test]
    fn test_subslice_transform_nbytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; 10];
        let ctx = subslice_do_parse("[00,9]").unwrap();
        subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..9], b"this is s");
    }

    #[test]
    fn test_subslice_transform_nbytes_2() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OISF provides architecture and infrastructure to open source security software communities and to projects like Suricata, the world-class threat-detection engine. As the need for robust and relevant security technologies grows, OISF serves to protect and maintain the authenticity of open source space. We welcome participation from diverse groups to generate networks and build active communities. We strengthen our communal space by offering user and developer training sessions around the world. OISF hosts SuriCon, the dynamic annual OISF/Suricata User Conference which gives our entire community a unique opportunity to collaborate together.

OISF is funded by donations from world-class security organizations committed to our mission. A list of these organizations is available on our Consortium Members page.");
        let mut out = vec![0u8; 24];
        if let Some(ctx) = subslice_do_parse("[15, 24]") {
            subslice_transform_do(&buf, &mut out, &ctx);
        }
        assert_eq!(&out[..24], b"rchitecture and infrastr");
    }

    #[test]
    fn test_subslice_transform_nbytes_3() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; buf.len() - 3]; // Starting at index 3
        let ctx = subslice_do_parse("[3]").unwrap();
        subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..buf.len() - 3], b"s is suricata");
    }

    #[test]
    fn test_subslice_transform_offset_nbytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; 12];
        let ctx = subslice_do_parse("[1,12]").unwrap();
        subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..12], b"his is suric");
    }

    #[test]
    fn test_subslice_transform_offset_neg_nbytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; 12];
        let ctx = subslice_do_parse("[13,-12]").unwrap();
        subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..12], b"his is suric");
    }

    // Positive offset with nbytes out of range
    #[test]
    fn test_subslice_transform_offset_neg_nbytes_2() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; 12];
        let ctx = subslice_do_parse("[13,-15]").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(cnt, 0);
    }

    // Positive offset with nbytes out of range
    #[test]
    fn test_subslice_transform_offset_neg_nbytes_3() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; 12];
        let ctx = subslice_do_parse("[10,-5]").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..5], b"is su");
        assert_eq!(5, cnt);
    }

    #[test]
    fn test_subslice_transform_offset_neg_offset() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; 3];
        let ctx = subslice_do_parse("[-3]").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(&out[..3], b"ata");
        assert_eq!(3, cnt);
    }

    // abs(offset) exceeds length
    #[test]
    fn test_subslice_transform_offset_neg_offset_2() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"this is suricata");
        let mut out = vec![0u8; 3];
        let ctx = subslice_do_parse("[-17]").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(0, cnt);
    }
}
