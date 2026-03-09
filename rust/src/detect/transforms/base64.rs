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

// Author: Jeff Lucovsky <jlucovsky@oisf.net>

use crate::detect::error::RuleParseError;
use crate::detect::parser::{parse_var, take_until_whitespace, ResultValue};
use crate::detect::{SIGMATCH_OPTIONAL_OPT, SIGMATCH_TRANSFORM_CAN_FAIL};
use crate::ffi::base64::{SCBase64Decode, SCBase64Mode};
use crate::utils::base64::get_decoded_buffer_size;

use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCInspectionBufferCheckAndExpand, SCInspectionBufferSetError,
    SCInspectionBufferTruncate, SCTransformTableElmt, Signature,
};

use nom8::bytes::complete::tag;
use nom8::character::complete::multispace0;
use nom8::sequence::preceded;
use nom8::{Err, IResult, Parser};

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::str;

const TRANSFORM_FROM_BASE64_MODE_DEFAULT: SCBase64Mode = SCBase64Mode::SCBase64ModeRFC4648;

const DETECT_TRANSFORM_BASE64_MAX_PARAM_COUNT: usize = 3;
const DETECT_TRANSFORM_BASE64_FLAG_MODE: u8 = 0x01;
const DETECT_TRANSFORM_BASE64_FLAG_NBYTES: u8 = 0x02;
const DETECT_TRANSFORM_BASE64_FLAG_OFFSET: u8 = 0x04;

// repr C to ensure a stable layout
// good field ordering to avoid padding as rust does not have stable zeroed allocs
#[repr(C)]
#[derive(Debug, PartialEq)]
struct DetectTransformFromBase64Data {
    nbytes: u32,
    offset: u32,
    mode: SCBase64Mode, // repr u8
    flags: u8,
}

impl Default for DetectTransformFromBase64Data {
    fn default() -> Self {
        DetectTransformFromBase64Data {
            mode: TRANSFORM_FROM_BASE64_MODE_DEFAULT,
            nbytes: 0,
            offset: 0,
            flags: 0,
        }
    }
}

fn get_mode_value(value: &str) -> Option<SCBase64Mode> {
    let res = match value {
        "rfc4648" => Some(SCBase64Mode::SCBase64ModeRFC4648),
        "rfc2045" => Some(SCBase64Mode::SCBase64ModeRFC2045),
        "strict" => Some(SCBase64Mode::SCBase64ModeStrict),
        _ => None,
    };

    res
}

fn parse_transform_base64(
    input: &str,
) -> IResult<&str, DetectTransformFromBase64Data, RuleParseError<&str>> {
    // Inner utility function for easy error creation.
    fn make_error(reason: String) -> nom8::Err<RuleParseError<&'static str>> {
        Err::Error(RuleParseError::InvalidTransformBase64(reason))
    }
    let mut transform_base64 = DetectTransformFromBase64Data::default();

    // No options so return defaults
    if input.is_empty() {
        return Ok((input, transform_base64));
    }
    let (_, values) = nom8::multi::separated_list1(
        tag(","),
        preceded(multispace0, nom8::bytes::complete::is_not(",")),
    )
    .parse(input)?;

    // Too many options?
    if values.len() > DETECT_TRANSFORM_BASE64_MAX_PARAM_COUNT {
        return Err(make_error(format!("Incorrect argument string; at least 1 value must be specified but no more than {}: {:?}",
            DETECT_TRANSFORM_BASE64_MAX_PARAM_COUNT, input)));
    }

    for value in values {
        let (mut val, mut name) = take_until_whitespace(value)?;
        val = val.trim();
        name = name.trim();
        match name {
            "mode" => {
                if 0 != (transform_base64.flags & DETECT_TRANSFORM_BASE64_FLAG_MODE) {
                    return Err(make_error("mode already set".to_string()));
                }
                if let Some(mode) = get_mode_value(val) {
                    transform_base64.mode = mode;
                } else {
                    return Err(make_error(format!("invalid mode value: {}", val)));
                }
                transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_MODE;
            }

            "offset" => {
                if 0 != (transform_base64.flags & DETECT_TRANSFORM_BASE64_FLAG_OFFSET) {
                    return Err(make_error("offset already set".to_string()));
                }

                let (_, res) = parse_var(val)?;
                match res {
                    ResultValue::Numeric(val) => {
                        if val <= u64::from(u16::MAX) {
                            transform_base64.offset = val as u32
                        } else {
                            return Err(make_error(format!(
                                "invalid offset value: must be between 0 and {}: {}",
                                u16::MAX,
                                val
                            )));
                        }
                    }
                    ResultValue::String(_val) => {
                        SCLogError!("offset value must be a value, not a variable name");
                        return Err(make_error(
                            "offset value must be a value, not a variable name".to_string(),
                        ));
                    }
                }

                transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_OFFSET;
            }

            "bytes" => {
                if 0 != (transform_base64.flags & DETECT_TRANSFORM_BASE64_FLAG_NBYTES) {
                    return Err(make_error("bytes already set".to_string()));
                }
                let (_, res) = parse_var(val)?;
                match res {
                    ResultValue::Numeric(val) => {
                        if val as u32 <= u32::from(u16::MAX) {
                            transform_base64.nbytes = val as u32
                        } else {
                            return Err(make_error(format!(
                                "invalid bytes value: must be between {} and {}: {}",
                                0,
                                u16::MAX,
                                val
                            )));
                        }
                    }
                    ResultValue::String(_val) => {
                        SCLogError!("byte value must be a value, not a variable name");
                        return Err(make_error(
                            "byte value must be a value, not a variable name".to_string(),
                        ));
                    }
                }
                transform_base64.flags |= DETECT_TRANSFORM_BASE64_FLAG_NBYTES;
            }
            _ => {
                return Err(make_error(format!("unknown base64 keyword: {}", name)));
            }
        };
    }

    Ok((input, transform_base64))
}

unsafe fn base64_parse(c_arg: *const c_char) -> *mut DetectTransformFromBase64Data {
    if c_arg.is_null() {
        let detect = DetectTransformFromBase64Data::default();
        return Box::into_raw(Box::new(detect));
    }

    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_transform_base64(arg) {
            Ok((_, detect)) => return Box::into_raw(Box::new(detect)),
            Err(_) => return std::ptr::null_mut(),
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn base64_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut DetectTransformFromBase64Data));
}

static mut G_TRANSFORM_BASE64_ID: c_int = 0;

unsafe extern "C" fn base64_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, opt_str: *const std::os::raw::c_char,
) -> c_int {
    let ctx = base64_parse(opt_str) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    let r = SCDetectSignatureAddTransform(s, G_TRANSFORM_BASE64_ID, ctx);
    if r != 0 {
        base64_free(de, ctx);
    }
    return r;
}

unsafe extern "C" fn base64_id(data: *mut *const u8, length: *mut u32, ctx: *const c_void) {
    if data.is_null() || length.is_null() || ctx.is_null() {
        return;
    }

    // This works because the structure is flat
    // Once variables are really implemented, we should investigate if the structure should own
    // its serialization or just borrow it to a caller
    *data = ctx as *const u8;
    *length = std::mem::size_of::<DetectTransformFromBase64Data>() as u32;
}

/// Outcome of a base64 decode against an input slice.
///
/// The pure decode logic is separated from the FFI shim so tests can drive
/// it directly with a `&[u8]` and assert against a plain Rust value, rather
/// than mocking the InspectionBuffer helpers.
#[derive(Debug, PartialEq, Eq)]
enum Base64TransformOutcome {
    /// No decode was attempted: empty input, offset past end, or nbytes
    /// covers all remaining input. The inspection buffer is left untouched.
    Skip,
    /// Decoder produced at least one byte. The FFI shim copies these into
    /// the inspection buffer scratch and calls `SCInspectionBufferTruncate`.
    Decoded(Vec<u8>),
    /// Decoder produced zero bytes from a non-empty input. The FFI shim
    /// calls `SCInspectionBufferSetError` to signal the failure.
    Error,
}

fn base64_transform_pure(
    input: &[u8], ctx: &DetectTransformFromBase64Data,
) -> Base64TransformOutcome {
    if input.is_empty() {
        return Base64TransformOutcome::Skip;
    }
    let mut slice = input;
    if ctx.offset > 0 {
        if ctx.offset as usize >= slice.len() {
            return Base64TransformOutcome::Skip;
        }
        slice = &slice[ctx.offset as usize..];
    }
    if ctx.nbytes > 0 {
        if ctx.nbytes as usize >= slice.len() {
            return Base64TransformOutcome::Skip;
        }
        slice = &slice[..ctx.nbytes as usize];
    }
    let output_len = get_decoded_buffer_size(slice.len() as u32) as usize;
    let mut output = vec![0u8; output_len];
    // SAFETY: SCBase64Decode is a Rust implementation exported to C. We
    // pass valid pointers and lengths derived from live slices.
    let num_decoded =
        unsafe { SCBase64Decode(slice.as_ptr(), slice.len(), ctx.mode, output.as_mut_ptr()) }
            as usize;
    if num_decoded == 0 {
        return Base64TransformOutcome::Error;
    }
    output.truncate(num_decoded);
    Base64TransformOutcome::Decoded(output)
}

unsafe extern "C" fn base64_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, ctx: *const c_void,
) {
    let input_ptr = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input_ptr.is_null() {
        return;
    }
    let input = build_slice!(input_ptr, input_len as usize);
    let ctx = cast_pointer!(ctx, DetectTransformFromBase64Data);

    match base64_transform_pure(input, ctx) {
        Base64TransformOutcome::Skip => {}
        Base64TransformOutcome::Decoded(decoded) => {
            let scratch = SCInspectionBufferCheckAndExpand(buffer, decoded.len() as u32);
            if scratch.is_null() {
                // allocation failure
                return;
            }
            std::ptr::copy_nonoverlapping(decoded.as_ptr(), scratch, decoded.len());
            SCInspectionBufferTruncate(buffer, decoded.len() as u32);
        }
        Base64TransformOutcome::Error => {
            SCInspectionBufferSetError(buffer);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformFromBase64DecodeRegister() {
    let kw = SCTransformTableElmt {
        name: b"from_base64\0".as_ptr() as *const libc::c_char,
        desc: b"convert the base64 decode of the buffer\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#from-base64\0".as_ptr() as *const libc::c_char,
        Setup: Some(base64_setup),
        flags: SIGMATCH_OPTIONAL_OPT | SIGMATCH_TRANSFORM_CAN_FAIL,
        Transform: Some(base64_transform),
        Free: Some(base64_free),
        TransformValidate: None,
        TransformId: Some(base64_id),
    };
    unsafe {
        G_TRANSFORM_BASE64_ID = SCDetectHelperTransformRegister(&kw);
        if G_TRANSFORM_BASE64_ID < 0 {
            SCLogWarning!("Failed registering transform base64");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_invalid() {
        assert!(parse_transform_base64("bytes 4, offset 3933, mode unknown").is_err());
        assert!(parse_transform_base64("bytes 4, offset 70000, mode strict").is_err());
        assert!(parse_transform_base64("bytes 4, offset 3933, mode strict, mode rfc2045").is_err());
    }

    #[test]
    fn test_parser_parse_partial_valid() {
        let (_, val) = parse_transform_base64("bytes 4").unwrap();
        assert_eq!(
            val,
            DetectTransformFromBase64Data {
                nbytes: 4,
                offset: 0,
                mode: TRANSFORM_FROM_BASE64_MODE_DEFAULT,
                flags: DETECT_TRANSFORM_BASE64_FLAG_NBYTES,
            }
        );

        let args = DetectTransformFromBase64Data {
            nbytes: 4,
            offset: 3933,
            mode: TRANSFORM_FROM_BASE64_MODE_DEFAULT,
            flags: DETECT_TRANSFORM_BASE64_FLAG_NBYTES | DETECT_TRANSFORM_BASE64_FLAG_OFFSET,
        };
        let (_, val) = parse_transform_base64("bytes 4, offset 3933").unwrap();
        assert_eq!(val, args);
        let (_, val) = parse_transform_base64("offset 3933, bytes 4").unwrap();
        assert_eq!(val, args);

        let (_, val) = parse_transform_base64("mode rfc2045").unwrap();
        assert_eq!(
            val,
            DetectTransformFromBase64Data {
                nbytes: 0,
                offset: 0,
                mode: SCBase64Mode::SCBase64ModeRFC2045,
                flags: DETECT_TRANSFORM_BASE64_FLAG_MODE,
            }
        );
    }

    #[test]
    fn test_parser_parse_valid() {
        let (_, val) = parse_transform_base64("").unwrap();
        assert_eq!(
            val,
            DetectTransformFromBase64Data {
                mode: TRANSFORM_FROM_BASE64_MODE_DEFAULT,
                ..Default::default()
            }
        );

        let (_, val) = parse_transform_base64("bytes 4, offset 3933, mode strict").unwrap();
        assert_eq!(
            val,
            DetectTransformFromBase64Data {
                nbytes: 4,
                offset: 3933,
                mode: SCBase64Mode::SCBase64ModeStrict,
                flags: DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                    | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                    | DETECT_TRANSFORM_BASE64_FLAG_MODE,
            }
        );

        let (_, val) = parse_transform_base64("bytes 4, offset 3933, mode rfc2045").unwrap();
        assert_eq!(
            val,
            DetectTransformFromBase64Data {
                nbytes: 4,
                offset: 3933,
                mode: SCBase64Mode::SCBase64ModeRFC2045,
                flags: DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                    | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                    | DETECT_TRANSFORM_BASE64_FLAG_MODE,
            }
        );

        let (_, val) = parse_transform_base64("bytes 4, offset 3933, mode rfc4648").unwrap();
        assert_eq!(
            val,
            DetectTransformFromBase64Data {
                nbytes: 4,
                offset: 3933,
                mode: SCBase64Mode::SCBase64ModeRFC4648,
                flags: DETECT_TRANSFORM_BASE64_FLAG_NBYTES
                    | DETECT_TRANSFORM_BASE64_FLAG_OFFSET
                    | DETECT_TRANSFORM_BASE64_FLAG_MODE,
            }
        );

        assert!(parse_transform_base64("bytes 4, offset var, mode rfc4648").is_err());
        assert!(parse_transform_base64("bytes var, offset 3933, mode rfc4648").is_err());
    }

    /// Parse `sig`, run the pure decode against `buf`, and assert the outcome.
    fn assert_outcome(sig: &str, buf: &[u8], expected: Base64TransformOutcome) {
        let (_, ctx) = parse_transform_base64(sig).unwrap();
        assert_eq!(base64_transform_pure(buf, &ctx), expected);
    }

    #[test]
    fn test_base64_transform() {
        use Base64TransformOutcome::*;

        /* Simple success case */
        assert_outcome(
            "",
            b"VGhpcyBpcyBTdXJpY2F0YQ==",
            Decoded(b"This is Suricata".to_vec()),
        );
        /* Simple success case with RFC2045 */
        assert_outcome("mode rfc2045", b"Zm 9v Ym Fy", Decoded(b"foobar".to_vec()));
        /* Decode failure case -- should signal error */
        assert_outcome("mode strict", b"This is Suricata\n", Error);
        /* bytes >= len so --> skip */
        assert_outcome("bytes 25", b"VGhpcyBpcyBTdXJpY2F0YQ==", Skip);
        /* offset >= len so --> skip */
        assert_outcome("offset 25", b"VGhpcyBpcyBTdXJpY2F0YQ==", Skip);
        /* partial transform */
        assert_outcome(
            "bytes 12",
            b"VGhpcyBpcyBTdXJpY2F0YQ==",
            Decoded(b"This is S".to_vec()),
        );
        /* transform from non-zero offset */
        assert_outcome(
            "offset 4",
            b"VGhpcyBpcyBTdXJpY2F0YQ==",
            Decoded(b"s is Suricata".to_vec()),
        );
        /* partial decode */
        assert_outcome(
            "mode rfc2045, bytes 15",
            b"SGVs bG8 gV29y bGQ=",
            Decoded(b"Hello Wor".to_vec()),
        );
        /* rfc2045 partial decode: valid prefix decoded, invalid suffix skipped */
        assert_outcome(
            "mode rfc2045",
            b"ABCD!!!!",
            Decoded(b"\x00\x10\x83".to_vec()),
        );
        /* input is not base64 encoded: decoder returns 0 -> Error */
        assert_outcome("mode rfc2045", b"!!!!", Error);
    }

    #[test]
    fn test_base64_transform_decode_error() {
        use Base64TransformOutcome::*;
        assert_outcome("mode strict", b"!!!!", Error);
        assert_outcome("mode rfc4648", b"!!!!", Error);
    }

    /// An empty (non-absent) buffer is neither a decode success nor a decode
    /// failure: the pure core returns Skip so the FFI shim leaves the
    /// inspection buffer untouched.
    #[test]
    fn test_base64_transform_empty_buffer_is_skip() {
        assert_outcome("", b"", Base64TransformOutcome::Skip);
    }

    /// offset past end and nbytes covering remaining input are both Skip;
    /// neither a decode success nor an error.
    #[test]
    fn test_base64_transform_offset_and_nbytes_short_circuit() {
        use Base64TransformOutcome::*;
        assert_outcome("offset 10", b"YWJj", Skip);
        assert_outcome("bytes 10", b"YWJj", Skip);
    }
}
