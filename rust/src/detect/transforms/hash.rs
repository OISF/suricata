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

use crate::detect::SIGMATCH_NOOPT;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, InspectionBuffer, SCDetectHelperTransformRegister,
    SCDetectSignatureAddTransform, SCTransformTableElmt, Signature, SCInspectionBufferCheckAndExpand,
    SCInspectionBufferTruncate,
};

use crate::ffi::hashing::{G_DISABLE_HASHING, SC_SHA1_LEN, SC_SHA256_LEN};
use digest::{Digest, Update};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_TRANSFORM_MD5_ID: c_int = 0;
static mut G_TRANSFORM_SHA1_ID: c_int = 0;
static mut G_TRANSFORM_SHA256_ID: c_int = 0;

const SC_MD5_LEN: usize = 16;

unsafe extern "C" fn md5_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if G_DISABLE_HASHING {
        SCLogError!("MD5 hashing has been disabled, needed for to_md5 keyword");
        return -1;
    }
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_MD5_ID, ptr::null_mut());
}

fn md5_transform_do(input: &[u8], output: &mut [u8]) {
    Md5::new().chain(input).finalize_into(output.into());
}

unsafe extern "C" fn md5_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = SCInspectionBufferCheckAndExpand(buffer, SC_MD5_LEN as u32);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, SC_MD5_LEN);

    md5_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, SC_MD5_LEN as u32);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformMd5Register() {
    let kw = SCTransformTableElmt {
        name: b"to_md5\0".as_ptr() as *const libc::c_char,
        desc: b"convert to md5 hash of the buffer\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#to-md5\0".as_ptr() as *const libc::c_char,
        Setup: Some(md5_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(md5_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    G_TRANSFORM_MD5_ID = SCDetectHelperTransformRegister(&kw);
    if G_TRANSFORM_MD5_ID < 0 {
        SCLogWarning!("Failed registering transform md5");
    }
}

unsafe extern "C" fn sha1_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if G_DISABLE_HASHING {
        SCLogError!("SHA1 hashing has been disabled, needed for to_sha1 keyword");
        return -1;
    }
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_SHA1_ID, ptr::null_mut());
}

fn sha1_transform_do(input: &[u8], output: &mut [u8]) {
    Sha1::new().chain(input).finalize_into(output.into());
}

unsafe extern "C" fn sha1_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = SCInspectionBufferCheckAndExpand(buffer, SC_SHA1_LEN as u32);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, SC_SHA1_LEN);

    sha1_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, SC_SHA1_LEN as u32);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformSha1Register() {
    let kw = SCTransformTableElmt {
        name: b"to_sha1\0".as_ptr() as *const libc::c_char,
        desc: b"convert to sha1 hash of the buffer\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#to-sha1\0".as_ptr() as *const libc::c_char,
        Setup: Some(sha1_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(sha1_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    G_TRANSFORM_SHA1_ID = SCDetectHelperTransformRegister(&kw);
    if G_TRANSFORM_SHA1_ID < 0 {
        SCLogWarning!("Failed registering transform sha1");
    }
}

unsafe extern "C" fn sha256_setup(
    _de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if G_DISABLE_HASHING {
        SCLogError!("SHA256 hashing has been disabled, needed for to_sha256 keyword");
        return -1;
    }
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_SHA256_ID, ptr::null_mut());
}

fn sha256_transform_do(input: &[u8], output: &mut [u8]) {
    Sha256::new().chain(input).finalize_into(output.into());
}

unsafe extern "C" fn sha256_transform(
    _det: *mut DetectEngineThreadCtx, buffer: *mut InspectionBuffer, _ctx: *mut c_void,
) {
    let input = (*buffer).inspect;
    let input_len = (*buffer).inspect_len;
    if input.is_null() || input_len == 0 {
        return;
    }
    let input = build_slice!(input, input_len as usize);

    let output = SCInspectionBufferCheckAndExpand(buffer, SC_SHA256_LEN as u32);
    if output.is_null() {
        // allocation failure
        return;
    }
    let output = std::slice::from_raw_parts_mut(output, SC_SHA256_LEN);

    sha256_transform_do(input, output);

    SCInspectionBufferTruncate(buffer, SC_SHA256_LEN as u32);
}

#[no_mangle]
pub unsafe extern "C" fn DetectTransformSha256Register() {
    let kw = SCTransformTableElmt {
        name: b"to_sha256\0".as_ptr() as *const libc::c_char,
        desc: b"convert to sha256 hash of the buffer\0".as_ptr() as *const libc::c_char,
        url: b"/rules/transforms.html#to-sha256\0".as_ptr() as *const libc::c_char,
        Setup: Some(sha256_setup),
        flags: SIGMATCH_NOOPT,
        Transform: Some(sha256_transform),
        Free: None,
        TransformValidate: None,
        TransformId: None,
    };
    G_TRANSFORM_SHA256_ID = SCDetectHelperTransformRegister(&kw);
    if G_TRANSFORM_SHA256_ID < 0 {
        SCLogWarning!("Failed registering transform sha256");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_transform() {
        let buf = b" A B C D ";
        let mut out = vec![0; SC_MD5_LEN];
        md5_transform_do(buf, &mut out);
        assert_eq!(
            out,
            b"\xe0\x59\xf8\x30\x43\x69\x58\xb6\x45\x82\x8c\xc2\x33\xc2\x47\x13"
        );
    }

    #[test]
    fn test_sha1_transform() {
        let buf = b" A B C D ";
        let mut out = vec![0; SC_SHA1_LEN];
        sha1_transform_do(buf, &mut out);
        assert_eq!(
            out,
            b"\xc8\xdc\x44\x97\xf7\xe0\x55\xf8\x6b\x88\x90\x52\x08\x2c\x0c\x7b\xdc\xc9\xc8\x89"
        );
    }

    #[test]
    fn test_sha256_transform() {
        let mut buf = Vec::with_capacity(SC_SHA256_LEN);
        buf.extend_from_slice(b" A B C D ");
        let mut out = vec![0; SC_SHA256_LEN];
        sha256_transform_do(&buf, &mut out);
        assert_eq!(out, b"\xd6\xbf\x7d\x8d\x69\x53\x02\x4d\x0d\x84\x5c\x99\x9b\xae\x93\xcc\xac\x68\xea\xab\x9a\xc9\x77\xd0\xfd\x30\x6a\xf5\x9a\x3d\xe4\x3a");
        // test in place
        let still_buf = unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) };
        buf.resize(SC_SHA256_LEN, 0);
        sha256_transform_do(still_buf, &mut buf);
        assert_eq!(&buf, b"\xd6\xbf\x7d\x8d\x69\x53\x02\x4d\x0d\x84\x5c\x99\x9b\xae\x93\xcc\xac\x68\xea\xab\x9a\xc9\x77\xd0\xfd\x30\x6a\xf5\x9a\x3d\xe4\x3a");
    }
}
