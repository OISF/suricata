/* Copyright (C) 2021-2024 Open Information Security Foundation
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

use crate::utils::base64::{decode_rfc2045, decode_rfc4648, Decoder};
use libc::c_ulong;
use std::os::raw::c_uchar;

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum Base64ReturnCode {
    SC_BASE64_OK = 0,
    SC_BASE64_INVALID_ARG,
    SC_BASE64_OVERFLOW,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Base64Mode {
    /* If the following strings were to be passed to the decoder with RFC2045 mode,
     * the results would be as follows. See the unittest B64TestVectorsRFC2045 in
     * src/util-base64.c
     *
     * BASE64("") = ""
     * BASE64("f") = "Zg=="
     * BASE64("fo") = "Zm8="
     * BASE64("foo") = "Zm9v"
     * BASE64("foob") = "Zm9vYg=="
     * BASE64("fooba") = "Zm9vYmE="
     * BASE64("foobar") = "Zm9vYmFy"
     * BASE64("foobar") = "Zm 9v Ym Fy"   <-- Notice how the spaces are ignored
     * BASE64("foobar") = "Zm$9vYm.Fy"    # According to RFC 2045, All line breaks or *other
     * characters* not found in base64 alphabet must be ignored by decoding software
     * */
    Base64ModeRFC2045 = 0, /* SPs are allowed during transfer but must be skipped by Decoder */
    Base64ModeStrict,
    /* If the following strings were to be passed to the decoder with RFC4648 mode,
     * the results would be as follows. See the unittest B64TestVectorsRFC4648 in
     * src/util-base64.c
     *
     * BASE64("") = ""
     * BASE64("f") = "Zg=="
     * BASE64("fo") = "Zm8="
     * BASE64("foo") = "Zm9v"
     * BASE64("foob") = "Zm9vYg=="
     * BASE64("fooba") = "Zm9vYmE="
     * BASE64("foobar") = "Zm9vYmFy"
     * BASE64("f") = "Zm 9v Ym Fy"   <-- Notice how the processing stops once space is encountered
     * BASE64("f") = "Zm$9vYm.Fy"    <-- Notice how the processing stops once an invalid char is
     * encountered
     * */
    Base64ModeRFC4648, /* reject the encoded data if it contains characters outside the base alphabet */
}

#[repr(C)]
pub struct Base64Decoded {
    decoded: *mut u8,
    decoded_len: u32,
}

impl Default for Base64Decoded {
    fn default() -> Self {
        Self::new()
    }
}

impl Base64Decoded {
    pub fn new() -> Base64Decoded {
        Base64Decoded {
            decoded: std::ptr::null_mut(),
            decoded_len: 0,
        }
    }
}

impl Drop for Base64Decoded {
    fn drop(&mut self) {
        unsafe {
            if !self.decoded.is_null() {
                let _ = Vec::from_raw_parts(
                    self.decoded,
                    self.decoded_len as usize,
                    self.decoded_len as usize,
                );
            }
        }
    }
}

/// Base64 decode a buffer.
///
/// This method exposes the Rust base64 decoder to C and should not be called from
/// Rust code.
///
/// It allows decoding in the modes described by ``Base64Mode`` enum.
#[no_mangle]
pub unsafe extern "C" fn Base64Decode(
    input: *const u8, len: u32, max_decoded: u32, mode: Base64Mode,
) -> *mut Base64Decoded {
    if input.is_null() || len == 0 {
        return std::ptr::null_mut();
    }

    let in_vec: &[u8] = std::slice::from_raw_parts(input as *mut u8, len as usize);
    let mut decoder = Decoder::new();
    let mut decoded_string = Vec::new();
    match mode {
        Base64Mode::Base64ModeRFC2045 => {
            if let Ok(fin_str) = decode_rfc2045(&mut decoder, in_vec) {
                decoded_string = fin_str;
            }
        }
        Base64Mode::Base64ModeRFC4648 => {
            if let Ok(fin_str) = decode_rfc4648(&mut decoder, in_vec, max_decoded) {
                decoded_string = fin_str;
            }
        }
        Base64Mode::Base64ModeStrict => {
            if let Ok(fin_str) = base64::decode(in_vec) {
                decoded_string = fin_str;
            }
        }
    }
    let mut b64_decoded = Base64Decoded::new();
    b64_decoded.decoded_len = decoded_string.len() as u32;

    // nothing was decoded
    if b64_decoded.decoded_len == 0 {
        return std::ptr::null_mut();
    }
    b64_decoded.decoded = decoded_string.as_mut_ptr();

    std::mem::forget(decoded_string);

    return Box::into_raw(Box::new(b64_decoded));
}

#[no_mangle]
pub unsafe extern "C" fn Base64DecodeFree(b64d: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(b64d as *mut Base64Decoded));
}

/// Base64 encode a buffer.
///
/// This method exposes the Rust base64 encoder to C and should not be called from
/// Rust code.
///
/// The output parameter must be an allocated buffer of at least the size returned
/// from Base64EncodeBufferSize for the input_len, and this length must be provided
/// in the output_len variable.
#[no_mangle]
pub unsafe extern "C" fn Base64Encode(
    input: *const u8, input_len: c_ulong, output: *mut c_uchar, output_len: *mut c_ulong,
) -> Base64ReturnCode {
    if input.is_null() || output.is_null() || output_len.is_null() {
        return Base64ReturnCode::SC_BASE64_INVALID_ARG;
    }
    let input = std::slice::from_raw_parts(input, input_len as usize);
    let encoded = base64::encode(input);
    if encoded.len() + 1 > *output_len as usize {
        return Base64ReturnCode::SC_BASE64_OVERFLOW;
    }
    let output = std::slice::from_raw_parts_mut(&mut *output, *output_len as usize);
    output[0..encoded.len()].copy_from_slice(encoded.as_bytes());
    output[encoded.len()] = 0;
    *output_len = encoded.len() as c_ulong;
    Base64ReturnCode::SC_BASE64_OK
}

/// Ratio of output bytes to input bytes for Base64 Encoding is 4:3, hence the
/// required output bytes are 4 * ceil(input_len / 3) and an additional byte for
/// storing the NULL pointer.
#[no_mangle]
pub extern "C" fn Base64EncodeBufferSize(len: c_ulong) -> c_ulong {
    (4 * ((len) + 2) / 3) + 1
}
