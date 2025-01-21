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

pub const SC_SHA256_LEN: usize = 32;
pub const SC_SHA1_LEN: usize = 20;
pub const SC_MD5_LEN: usize = 16;

// Length of hex digests without trailing NUL.
pub const SC_SHA256_HEX_LEN: usize = 64;
pub const SC_SHA1_HEX_LEN: usize = 40;
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
pub unsafe extern "C" fn SCSha256FinalizeToHex(
    hasher: &mut SCSha256, out: *mut c_char, len: u32,
) -> bool {
    let hasher: Box<SCSha256> = Box::from_raw(hasher);
    let result = hasher.0.finalize();
    let hex = format!("{:x}", &result);
    crate::ffi::strings::copy_to_c_char(hex, out, len as usize)
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

#[no_mangle]
pub unsafe extern "C" fn SCSha256HashBufferToHex(
    buf: *const u8, buf_len: u32, out: *mut c_char, len: u32,
) -> bool {
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    let hash = Sha256::new().chain(data).finalize();
    let hex = format!("{:x}", &hash);
    crate::ffi::strings::copy_to_c_char(hex, out, len as usize)
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

#[no_mangle]
pub unsafe extern "C" fn SCSha1FinalizeToHex(
    hasher: &mut SCSha1, out: *mut c_char, len: u32,
) -> bool {
    let hasher: Box<SCSha1> = Box::from_raw(hasher);
    let result = hasher.0.finalize();
    let hex = format!("{:x}", &result);
    crate::ffi::strings::copy_to_c_char(hex, out, len as usize)
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

#[no_mangle]
pub unsafe extern "C" fn SCSha1HashBufferToHex(
    buf: *const u8, buf_len: u32, out: *mut c_char, len: u32,
) -> bool {
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    let hash = Sha1::new().chain(data).finalize();
    let hex = format!("{:x}", &hash);
    crate::ffi::strings::copy_to_c_char(hex, out, len as usize)
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
pub unsafe extern "C" fn SCMd5FinalizeToHex(
    hasher: &mut SCMd5, out: *mut c_char, len: u32,
) -> bool {
    let hasher: Box<SCMd5> = Box::from_raw(hasher);
    let result = hasher.0.finalize();
    let hex = format!("{:x}", &result);
    crate::ffi::strings::copy_to_c_char(hex, out, len as usize)
}

/// Free an unfinalized Sha1 context.
#[no_mangle]
pub unsafe extern "C" fn SCMd5Free(hasher: &mut SCMd5) {
    // Drop.
    let _: Box<SCMd5> = Box::from_raw(hasher);
}

#[no_mangle]
pub unsafe extern "C" fn SCMd5HashBuffer(
    buf: *const u8, buf_len: u32, out: *mut u8, len: u32,
) -> bool {
    if len as usize != SC_MD5_LEN {
        return false;
    }
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    let output = std::slice::from_raw_parts_mut(out, len as usize);
    let hash = Md5::new().chain(data).finalize();
    output.copy_from_slice(&hash);
    true
}

/// C binding for a function to MD5 hash a single buffer to a hex string.
#[no_mangle]
pub unsafe extern "C" fn SCMd5HashBufferToHex(
    buf: *const u8, buf_len: u32, out: *mut c_char, len: u32,
) -> bool {
    let data = std::slice::from_raw_parts(buf, buf_len as usize);
    let hash = Md5::new().chain(data).finalize();
    let hex = format!("{:x}", &hash);
    crate::ffi::strings::copy_to_c_char(hex, out, len as usize)
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

pub static mut G_DISABLE_HASHING: bool = false;

#[no_mangle]
pub unsafe extern "C" fn SCDisableHashing() {
    G_DISABLE_HASHING = true;
}

#[cfg(test)]
mod test {
    use super::*;

    // A test around SCSha256 primarily to check that the output is
    // correctly copied into a C string.
    #[test]
    fn test_sha256() {
        unsafe {
            let hasher = SCSha256New();
            assert!(!hasher.is_null());
            let hasher = &mut *hasher as &mut SCSha256;
            let bytes = &[0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41];
            SCSha256Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            SCSha256Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            SCSha256Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            SCSha256Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            let hex = [0_u8; SC_SHA256_HEX_LEN + 1];
            SCSha256FinalizeToHex(
                hasher,
                hex.as_ptr() as *mut c_char,
                (SC_SHA256_HEX_LEN + 1) as u32,
            );
            let string = std::ffi::CStr::from_ptr(hex.as_ptr() as *mut c_char)
                .to_str()
                .unwrap();
            assert_eq!(
                string,
                "22a48051594c1949deed7040850c1f0f8764537f5191be56732d16a54c1d8153"
            );
        }
    }

    // A test around SCSha256 primarily to check that the output is
    // correctly copied into a C string.
    #[test]
    fn test_md5() {
        unsafe {
            let hasher = SCMd5New();
            assert!(!hasher.is_null());
            let hasher = &mut *hasher as &mut SCMd5;
            let bytes = &[0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41];
            SCMd5Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            SCMd5Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            SCMd5Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            SCMd5Update(hasher, bytes.as_ptr(), bytes.len() as u32);
            let hex = [0_u8; SC_MD5_HEX_LEN + 1];
            SCMd5FinalizeToHex(
                hasher,
                hex.as_ptr() as *mut c_char,
                (SC_MD5_HEX_LEN + 1) as u32,
            );
            let string = std::ffi::CStr::from_ptr(hex.as_ptr() as *mut c_char)
                .to_str()
                .unwrap();
            assert_eq!(string, "5216ddcc58e8dade5256075e77f642da");
        }
    }
}
