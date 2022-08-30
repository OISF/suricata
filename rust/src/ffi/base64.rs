/* Copyright (C) 2021-2022 Open Information Security Foundation
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

use std::os::raw::c_uchar;
use libc::c_ulong;

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum Base64ReturnCode {
    SC_BASE64_OK = 0,
    SC_BASE64_INVALID_ARG,
    SC_BASE64_OVERFLOW,
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
    let output = std::slice::from_raw_parts_mut(&mut *(output as *mut u8), *output_len as usize);
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
