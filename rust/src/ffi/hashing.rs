/* Copyright (C) 2020 Open Information Security Foundation
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

use digest::{Digest, Update};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::os::raw::c_char;

pub const SC_SHA1_LEN: usize = 20;
pub const SC_SHA256_LEN: usize = 32;

// Length of a MD5 hex string, not including a trailing NUL.
pub const SC_MD5_HEX_LEN: usize = 32;

// Wrap the Rust Sha256 in a new type named SCSha256 to give this type
// the "SC" prefix. The one drawback is we must access the actual context
// with .0.
pub struct SCSha256(Sha256);

#[no_mangle]
pub extern "C" fn SCSha256New() -> *mut SCSha256 {
    let hasher = Box::new(SCSha256(Sha256::new()));
    Box::into_raw(hasher)
}

#[no_mangle]
pub unsafe extern "C" fn SCSha256Update(hasher: &mut SCSha256, bytes: *const u8, len: u32) {
    update(&mut hasher.0, bytes, len);
}

#[no_mangle]
pub unsafe extern "C" fn SCSha256Finalize(hasher: &mut SCSha256, out: *mut u8, len: u32) {
    let hasher: Box<SCSha256> = Box::from_raw(hasher);
    finalize(hasher.0, out, len);
}

/// C function to finalize the Sha256 hasher to a hex string.
///
/// Notes:
/// - There is probably room for optimization here, by iterating the result and writing
///   the output directly to the output buffer.
///
/// But even given the notes, this appears to be faster than the equivalent that we
/// did in C using NSS.
#[no_mangle]
pub unsafe extern "C" fn SCSha256FinalizeToHex(hasher: &mut SCSha256, out: *mut c_char, len: u32) {
    let out = &mut *(out as *mut u8);
    let hasher: Box<SCSha256> = Box::from_raw(hasher);
    let result = hasher.0.finalize();
    let hex = format!("{:x}", &result);
    let output = std::slice::from_raw_parts_mut(out, len as usize);

    // This will panic if the sizes differ.
    output[0..len as usize - 1].copy_from_slice(hex.as_bytes());

    // Terminate the string.
    output[output.len() - 1] = 0;
}

/// Free an unfinalized Sha256 context.
#[no_mangle]
pub unsafe extern "C" fn SCSha256Free(hasher: &mut SCSha256) {
    // Drop.
    let _: Box<SCSha256> = Box::from_raw(hasher);
}

#[no_mangle]
pub unsafe extern "C" fn SCSha256HashBuffer(
    buf: *const u8, buf_len: u32, out: *mut u8, len: u32,
) -> bool {
    if len as usize != SC_SHA256_LEN {
        return false;
    }
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    let output = std::slice::from_raw_parts_mut(out, len as usize);
    let hash = Sha256::new().chain(data).finalize();
    output.copy_from_slice(&hash);
    return true;
}

// Start of SHA1 C bindings.

pub struct SCSha1(Sha1);

#[no_mangle]
pub extern "C" fn SCSha1New() -> *mut SCSha1 {
    let hasher = Box::new(SCSha1(Sha1::new()));
    Box::into_raw(hasher)
}

#[no_mangle]
pub unsafe extern "C" fn SCSha1Update(hasher: &mut SCSha1, bytes: *const u8, len: u32) {
    update(&mut hasher.0, bytes, len);
}

#[no_mangle]
pub unsafe extern "C" fn SCSha1Finalize(hasher: &mut SCSha1, out: *mut u8, len: u32) {
    let hasher: Box<SCSha1> = Box::from_raw(hasher);
    finalize(hasher.0, out, len);
}

/// Free an unfinalized Sha1 context.
#[no_mangle]
pub unsafe extern "C" fn SCSha1Free(hasher: &mut SCSha1) {
    // Drop.
    let _: Box<SCSha1> = Box::from_raw(hasher);
}

#[no_mangle]
pub unsafe extern "C" fn SCSha1HashBuffer(
    buf: *const u8, buf_len: u32, out: *mut u8, len: u32,
) -> bool {
    if len as usize != SC_SHA1_LEN {
        return false;
    }
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    let output = std::slice::from_raw_parts_mut(out, len as usize);
    let hash = Sha1::new().chain(data).finalize();
    output.copy_from_slice(&hash);
    return true;
}

// Start of MD5 C bindings.

pub struct SCMd5(Md5);

#[no_mangle]
pub extern "C" fn SCMd5New() -> *mut SCMd5 {
    let hasher = Box::new(SCMd5(Md5::new()));
    Box::into_raw(hasher)
}

#[no_mangle]
pub unsafe extern "C" fn SCMd5Update(hasher: &mut SCMd5, bytes: *const u8, len: u32) {
    update(&mut hasher.0, bytes, len);
}

/// Finalize the MD5 hash placing the digest in the provided out buffer.
///
/// This function consumes the SCMd5 hash context.
#[no_mangle]
pub unsafe extern "C" fn SCMd5Finalize(hasher: &mut SCMd5, out: *mut u8, len: u32) {
    let hasher: Box<SCMd5> = Box::from_raw(hasher);
    finalize(hasher.0, out, len);
}

/// Finalize MD5 context to a hex string.
///
/// Consumes the hash context and cannot be re-used.
#[no_mangle]
pub unsafe extern "C" fn SCMd5FinalizeToHex(hasher: &mut SCMd5, out: *mut c_char, len: u32) {
    let out = &mut *(out as *mut u8);
    let hasher: Box<SCMd5> = Box::from_raw(hasher);
    let result = hasher.0.finalize();
    let hex = format!("{:x}", &result);
    let output = std::slice::from_raw_parts_mut(out, len as usize);

    // This will panic if the sizes differ.
    output[0..len as usize - 1].copy_from_slice(hex.as_bytes());

    // Terminate the string.
    output[output.len() - 1] = 0;
}

/// Free an unfinalized Sha1 context.
#[no_mangle]
pub unsafe extern "C" fn SCMd5Free(hasher: &mut SCMd5) {
    // Drop.
    let _: Box<SCMd5> = Box::from_raw(hasher);
}

#[no_mangle]
pub unsafe extern "C" fn SCMd5HashBuffer(buf: *const u8, buf_len: u32, out: *mut u8, len: u32) {
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    let output = std::slice::from_raw_parts_mut(out, len as usize);
    let hash = Md5::new().chain(data).finalize();
    output.copy_from_slice(&hash);
}

/// C binding for a function to MD5 hash a single buffer to a hex string.
#[no_mangle]
pub unsafe extern "C" fn SCMd5HashBufferToHex(
    buf: *const u8, buf_len: u32, out: *mut c_char, len: u32,
) {
    let out = &mut *(out as *mut u8);
    let output = std::slice::from_raw_parts_mut(out, len as usize);
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    // let output = std::slice::from_raw_parts_mut(out, len as usize);
    let hash = Md5::new().chain(data).finalize();
    let hex = format!("{:x}", &hash);

    // This will panic if the sizes differ.
    output[0..len as usize - 1].copy_from_slice(hex.as_bytes());

    // Terminate the string.
    output[output.len() - 1] = 0;
}

// Functions that are generic over Digest. For the most part the C bindings are
// just wrappers around these.

unsafe fn update<D: Digest>(digest: &mut D, bytes: *const u8, len: u32) {
    let data = std::slice::from_raw_parts(bytes, len as usize);
    digest.update(data);
}

unsafe fn finalize<D: Digest>(digest: D, out: *mut u8, len: u32) {
    let result = digest.finalize();
    let output = std::slice::from_raw_parts_mut(out, len as usize);
    // This will panic if the sizes differ.
    output.copy_from_slice(&result);
}
