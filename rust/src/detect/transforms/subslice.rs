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

use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCInspectionBufferCheckAndExpand, SCInspectionBufferTruncate,
    SCTransformTableElmt, Signature,
};

use std::os::raw::{c_int, c_void};

use std::ffi::CStr;

static mut G_TRANSFORM_SUBSLICE_ID: c_int = 0;

#[derive(Debug, PartialEq)]
#[repr(C)]
struct DetectTransformSubsliceData {
    pub offset: isize,
    pub nbytes: Option<isize>,
    pub truncate: bool,
}

impl Default for DetectTransformSubsliceData {
    fn default() -> Self {
        DetectTransformSubsliceData {
            offset: 0,
            nbytes: None,
            truncate: false,
        }
    }
}

fn subslice_do_parse(i: &str) -> Option<DetectTransformSubsliceData> {
    let parts: Vec<_> = i.trim().split(',').map(str::trim).collect();

    match parts.as_slice() {
        [offset] => {
            let offset = offset.parse::<isize>().ok()?;
            Some(DetectTransformSubsliceData {
                offset,
                nbytes: None,
                truncate: false,
            })
        }
        // offset, truncate OR offset, nbytes
        [first, second] => {
            let offset = first.parse::<isize>().ok()?;

            if second.eq_ignore_ascii_case("truncate") {
                // offset, truncate
                Some(DetectTransformSubsliceData {
                    offset,
                    nbytes: None,
                    truncate: true,
                })
            } else {
                // offset, nbytes
                let nbytes = second.parse::<isize>().ok()?;
                if nbytes == 0 {
                    return None;
                }
                Some(DetectTransformSubsliceData {
                    offset,
                    nbytes: Some(nbytes),
                    truncate: false,
                })
            }
        }
        // offset, nbytes, truncate
        [first, second, third] => {
            let offset = first.parse::<isize>().ok()?;
            let nbytes = second.parse::<isize>().ok()?;

            if !third.eq_ignore_ascii_case("truncate") {
                return None;
            }

            if nbytes == 0 {
                return None;
            }

            Some(DetectTransformSubsliceData {
                offset,
                nbytes: Some(nbytes),
                truncate: true,
            })
        }
        _ => {
            SCLogError!("Invalid subslice options; use: 'offset' or 'offset, nbytes' or 'offset, truncate' or 'offset, nbytes, truncate'");
            None
        }
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

    // Handle offset - clamp if truncate, reject if not
    let offset = ctx.offset;
    if offset.abs() > len && !ctx.truncate {
        return None;
    }

    // Compute start index from offset (clamped if needed)
    let start = if offset >= 0 {
        offset.min(len)
    } else {
        len + offset.max(-len)
    };

    // Compute end index from nbytes
    let end = match ctx.nbytes {
        None => len,
        Some(0) => return None,
        Some(n) if n < 0 => {
            let candidate = len + n;
            if candidate < 0 {
                if !ctx.truncate {
                    return None;
                }
                0
            } else {
                candidate
            }
        }
        Some(n) => {
            let candidate = start + n;
            if candidate > len && !ctx.truncate {
                return None;
            }
            candidate.min(len)
        }
    };

    // Normalize if indices reversed
    let (start, end) = if end < start {
        (end, start)
    } else {
        (start, end)
    };

    // Convert to usize - both are guaranteed to be in [0, len]
    let (start, end) = (start as usize, end as usize);

    Some(&data[start..end])
}

fn subslice_transform_do(
    input: &[u8], output: &mut [u8], ctx: &DetectTransformSubsliceData,
) -> u32 {
    let Some(slice) = subslice_apply(input, ctx) else {
        return 0;
    };

    let len = slice.len();

    // Use ptr::copy which handles both overlapping and non-overlapping memory correctly.
    unsafe {
        std::ptr::copy(slice.as_ptr(), output.as_mut_ptr(), len);
    }

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
        flags: 0,
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

    static TEST_STRING: &[u8] = b"this is suricata";

    #[test]
    fn test_subslice_parse_invalid() {
        assert!(subslice_do_parse("f, y").is_none());
        assert!(subslice_do_parse("0:-10").is_none());
        assert!(subslice_do_parse("1 1").is_none());
        assert!(subslice_do_parse("1,0").is_none());
        assert!(subslice_do_parse("").is_none());
        assert!(subslice_do_parse("1, 2, nottruncate").is_none());
        // Test with too many arguments
        assert!(subslice_do_parse("1, 2, 3, 4").is_none());
        assert!(subslice_do_parse("1, 2, truncate, extra").is_none());
    }

    #[test]
    fn test_subslice_parse_valid() {
        assert_eq!(
            subslice_do_parse("       0      ,     9       ").unwrap(),
            DetectTransformSubsliceData {
                offset: 0,
                nbytes: Some(9),
                truncate: false
            }
        );
        assert_eq!(
            subslice_do_parse("0, 9").unwrap(),
            DetectTransformSubsliceData {
                offset: 0,
                nbytes: Some(9),
                truncate: false
            }
        );
        assert_eq!(
            subslice_do_parse("1, 1").unwrap(),
            DetectTransformSubsliceData {
                offset: 1,
                nbytes: Some(1),
                truncate: false
            }
        );
        assert_eq!(
            subslice_do_parse("1").unwrap(),
            DetectTransformSubsliceData {
                offset: 1,
                nbytes: None,
                truncate: false
            }
        );
        assert_eq!(
            subslice_do_parse("-1").unwrap(),
            DetectTransformSubsliceData {
                offset: -1,
                nbytes: None,
                truncate: false
            }
        );
        assert_eq!(
            subslice_do_parse("0, -3").unwrap(),
            DetectTransformSubsliceData {
                offset: 0,
                nbytes: Some(-3),
                truncate: false
            }
        );
        assert_eq!(
            subslice_do_parse("-10, -2").unwrap(),
            DetectTransformSubsliceData {
                offset: -10,
                nbytes: Some(-2),
                truncate: false
            }
        );
        assert_eq!(
            subslice_do_parse("1, truncate").unwrap(),
            DetectTransformSubsliceData {
                offset: 1,
                nbytes: None,
                truncate: true
            }
        );
        assert_eq!(
            subslice_do_parse("1, TRUNCATE").unwrap(),
            DetectTransformSubsliceData {
                offset: 1,
                nbytes: None,
                truncate: true
            }
        );
        assert_eq!(
            subslice_do_parse("2, 10, truncate").unwrap(),
            DetectTransformSubsliceData {
                offset: 2,
                nbytes: Some(10),
                truncate: true
            }
        );
    }

    #[test]
    fn test_subslice_transform_offset() {
        let expected_output = b"his is suricata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);

        let mut out = vec![0u8; expected_output_len];
        let ctx = subslice_do_parse("1").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_transform_nbytes() {
        let expected_output = b"this is s";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("00,9").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_transform_nbytes_2() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OISF provides architecture and infrastructure to open source security software communities and to projects like Suricata, the world-class threat-detection engine. As the need for robust and relevant security technologies grows, OISF serves to protect and maintain the authenticity of open source space. We welcome participation from diverse groups to generate networks and build active communities. We strengthen our communal space by offering user and developer training sessions around the world. OISF hosts SuriCon, the dynamic annual OISF/Suricata User Conference which gives our entire community a unique opportunity to collaborate together.

OISF is funded by donations from world-class security organizations committed to our mission. A list of these organizations is available on our Consortium Members page.");
        let mut out = vec![0u8; 24];
        if let Some(ctx) = subslice_do_parse("15, 24") {
            subslice_transform_do(&buf, &mut out, &ctx);
        }
        assert_eq!(&out[..24], b"rchitecture and infrastr");
    }

    #[test]
    fn test_subslice_transform_nbytes_3() {
        let expected_output = b"s is suricata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("3").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_transform_offset_nbytes() {
        let expected_output = b"his is suric";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("1,12").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_transform_offset_neg_nbytes() {
        let expected_output = b" is suric";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("13,-12").unwrap();
        assert!(!ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // offset + nbytes > data_len() [NO TRUNCATE]
    #[test]
    fn test_subslice_transform_offset_and_nbytes_exceeds_len_00() {
        let expected_output = b"";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("2, 30").unwrap();
        assert!(!ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // offset + nbytes > data_len() [TRUNCATE]
    #[test]
    fn test_subslice_transform_offset_and_nbytes_exceeds_len_01() {
        let expected_output = b"is is suricata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("2, 30, truncate").unwrap();
        assert!(ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // Positive offset with nbytes out of range
    #[test]
    fn test_subslice_transform_offset_neg_nbytes_2() {
        let expected_output = b"his is suric";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("13,-15").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // Positive offset with nbytes out of range
    #[test]
    fn test_subslice_transform_offset_neg_nbytes_3() {
        let expected_output = b"r";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("10,-5").unwrap();
        assert!(!ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_transform_offset_neg_offset() {
        let expected_output = b"ata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("-3").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // abs(offset) exceeds length
    #[test]
    fn test_subslice_transform_offset_neg_offset_2() {
        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; 3];

        let ctx = subslice_do_parse("-17").unwrap();
        assert!(!ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, 0);
    }

    #[test]
    fn test_subslice_with_truncate_literal() {
        let expected_output = b"is is suricata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("2, truncate").unwrap();
        assert!(ctx.truncate);
        assert_eq!(ctx.offset, 2);
        assert_eq!(ctx.nbytes, None);

        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_with_nbytes_and_truncate_01() {
        let expected_output = b"is is suricata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("2, 20, truncate").unwrap();
        assert!(ctx.truncate);
        assert_eq!(ctx.offset, 2);
        assert_eq!(ctx.nbytes, Some(20));

        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_with_nbytes_and_truncate_02() {
        let expected_output = b"curl/7.64.1";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        let test_string: &[u8] = b"curl/7.64.1";
        buf.extend_from_slice(test_string);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("0, 30, truncate").unwrap();
        assert!(ctx.truncate);
        assert_eq!(ctx.offset, 0);
        assert_eq!(ctx.nbytes, Some(30));
        assert!(ctx.truncate);

        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_with_offset_and_truncate_01() {
        let expected_output = b"url/7.64.1";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        let test_string: &[u8] = b"curl/7.64.1";
        buf.extend_from_slice(test_string);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("1, truncate").unwrap();
        assert!(ctx.truncate);
        assert_eq!(ctx.offset, 1);
        assert_eq!(ctx.nbytes, None);
        assert!(ctx.truncate);

        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    #[test]
    fn test_subslice_with_offset_and_truncate_02() {
        let expected_output = b"curl/7.64.1";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        let test_string: &[u8] = b"curl/7.64.1";
        buf.extend_from_slice(test_string);
        let mut out = vec![0u8; expected_output_len];

        let ctx = subslice_do_parse("0, truncate").unwrap();
        assert!(ctx.truncate);
        assert_eq!(ctx.offset, 0);
        assert_eq!(ctx.nbytes, None);
        assert!(ctx.truncate);

        let cnt = subslice_transform_do(&buf, &mut out, &ctx);
        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // Test that when truncate is enabled, excessive negative offset is clamped
    #[test]
    fn test_subslice_transform_truncate_excessive_negative_offset() {
        let expected_output = b"This is Suricata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; expected_output_len];

        // -17 should be clamped to -16 (or 0) when truncate is enabled
        let ctx = subslice_do_parse("-17, truncate").unwrap();
        assert!(ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // Test that when truncate is NOT enabled, excessive negative offset returns empty
    #[test]
    fn test_subslice_transform_no_truncate_excessive_negative_offset() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; 16];

        // -17 without truncate should fail
        let ctx = subslice_do_parse("-17").unwrap();
        assert!(!ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, 0);
    }

    // Test that when truncate is enabled, excessive positive offset is clamped
    #[test]
    fn test_subslice_transform_truncate_excessive_positive_offset() {
        let expected_output = b"";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; 16];

        // 17 should be clamped to 16 when truncate is enabled (results in empty slice)
        let ctx = subslice_do_parse("17, truncate").unwrap();
        assert!(ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // Test with nbytes and excessive negative offset with truncate
    #[test]
    fn test_subslice_transform_truncate_excessive_negative_offset_with_nbytes() {
        let expected_output = b"This is Su";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; expected_output_len];

        // -17 should be clamped to -16 (start at 0), then take 10 bytes
        let ctx = subslice_do_parse("-17, 10, truncate").unwrap();
        assert!(ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // Test edge case: offset exactly at -length with truncate
    #[test]
    fn test_subslice_transform_truncate_exact_negative_offset() {
        let expected_output = b"This is Suricata";
        let expected_output_len = expected_output.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; expected_output_len];

        // -16 should work normally (start at position 0)
        let ctx = subslice_do_parse("-16, truncate").unwrap();
        assert!(ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output_len as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }

    // Test that overlapping buffers work correctly (input == output)
    // This simulates the case where C code may pass the same buffer
    #[test]
    fn test_subslice_transform_overlapping_buffer() {
        let expected_output = b"is is suricata";

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);

        // Simulate overlapping buffers using unsafe code
        let ctx = subslice_do_parse("2").unwrap();
        unsafe {
            let ptr = buf.as_mut_ptr();
            let len = buf.len();
            let input_slice = std::slice::from_raw_parts(ptr, len);
            let output_slice = std::slice::from_raw_parts_mut(ptr, len);
            let cnt = subslice_transform_do(input_slice, output_slice, &ctx);
            assert_eq!(cnt, expected_output.len() as u32);
            assert_eq!(&buf[..cnt as usize], expected_output);
        }
    }

    // Test overlapping buffer with negative offset
    #[test]
    fn test_subslice_transform_overlapping_buffer_negative_offset() {
        let expected_output = b"ata";

        let mut buf = Vec::new();
        buf.extend_from_slice(TEST_STRING);

        // Simulate overlapping buffers using unsafe code
        let ctx = subslice_do_parse("-3").unwrap();
        unsafe {
            let ptr = buf.as_mut_ptr();
            let len = buf.len();
            let input_slice = std::slice::from_raw_parts(ptr, len);
            let output_slice = std::slice::from_raw_parts_mut(ptr, len);
            let cnt = subslice_transform_do(input_slice, output_slice, &ctx);
            assert_eq!(cnt, expected_output.len() as u32);
            assert_eq!(&buf[..cnt as usize], expected_output);
        }
    }

    // Test excessive negative nbytes with truncate
    #[test]
    fn test_excessive_negative_nbytes_with_truncate() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; 16];

        // offset: -20 (clamped to -16, start at 0)
        // nbytes: -30 (would end at -14, clamped to 0)
        // Result: empty buffer (start=0, end=0)
        let ctx = subslice_do_parse("-20, -30, truncate").unwrap();
        assert!(ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        // With truncate, this should produce empty buffer (start == end)
        assert_eq!(cnt, 0);
    }

    // Test excessive negative nbytes without truncate
    #[test]
    fn test_excessive_negative_nbytes_no_truncate() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; 16];

        // nbytes: -30 (would end at -14, which is invalid)
        let ctx = subslice_do_parse("0, -30").unwrap();
        assert!(!ctx.truncate);
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        // Without truncate, this should fail
        assert_eq!(cnt, 0);
    }

    // Test moderate negative nbytes with truncate
    #[test]
    fn test_moderate_negative_nbytes_with_truncate() {
        let expected_output = b"This is ";

        let mut buf = Vec::new();
        buf.extend_from_slice(b"This is Suricata");
        let mut out = vec![0u8; 16];

        // offset: 0, nbytes: -8 (end at position 8)
        let ctx = subslice_do_parse("0, -8, truncate").unwrap();
        let cnt = subslice_transform_do(&buf, &mut out, &ctx);

        assert_eq!(cnt, expected_output.len() as u32);
        assert_eq!(&out[..cnt as usize], expected_output);
    }
}
