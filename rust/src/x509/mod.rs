/* Copyright (C) 2019-2020 Open Information Security Foundation
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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use crate::common::rust_string_to_c;
use std;
use std::os::raw::c_char;
use x509_parser::prelude::*;

#[repr(u32)]
pub enum X509DecodeError {
    Success = 0,
    /// Generic decoding error
    InvalidCert,
    /// Some length does not match, or certificate is incomplete
    InvalidLength,
    InvalidVersion,
    InvalidSerial,
    InvalidAlgorithmIdentifier,
    InvalidX509Name,
    InvalidDate,
    InvalidExtensions,
    /// DER structure is invalid
    InvalidDER,
}

pub struct X509(X509Certificate<'static>);

/// Attempt to parse a X.509 from input, and return a pointer to the parsed object if successful.
///
/// # Safety
///
/// input must be a valid buffer of at least input_len bytes
#[no_mangle]
pub unsafe extern "C" fn rs_x509_decode(
    input: *const u8,
    input_len: u32,
    err_code: *mut u32,
) -> *mut X509 {
    let slice = std::slice::from_raw_parts(input, input_len as usize);
    let res = X509Certificate::from_der(slice);
    match res {
        Ok((_rem, cert)) => Box::into_raw(Box::new(X509(cert))),
        Err(e) => {
            let error = x509_parse_error_to_errcode(&e);
            *err_code = error as u32;
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_x509_get_subject(ptr: *const X509) -> *mut c_char {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    let x509 = cast_pointer! {ptr, X509};
    let subject = x509.0.tbs_certificate.subject.to_string();
    rust_string_to_c(subject)
}

#[no_mangle]
pub unsafe extern "C" fn rs_x509_get_issuer(ptr: *const X509) -> *mut c_char {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    let x509 = cast_pointer! {ptr, X509};
    let issuer = x509.0.tbs_certificate.issuer.to_string();
    rust_string_to_c(issuer)
}

#[no_mangle]
pub unsafe extern "C" fn rs_x509_get_serial(ptr: *const X509) -> *mut c_char {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    let x509 = cast_pointer! {ptr, X509};
    let raw_serial = x509.0.tbs_certificate.raw_serial();
    let v: Vec<_> = raw_serial.iter().map(|x| format!("{:02X}", x)).collect();
    let serial = v.join(":");
    rust_string_to_c(serial)
}

/// Extract validity from input X.509 object
///
/// # Safety
///
/// ptr must be a valid object obtained using `rs_x509_decode`
#[no_mangle]
pub unsafe extern "C" fn rs_x509_get_validity(
    ptr: *const X509,
    not_before: *mut i64,
    not_after: *mut i64,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let x509 = &*ptr;
    let n_b = x509.0.validity().not_before.timestamp();
    let n_a = x509.0.validity().not_after.timestamp();
    *not_before = n_b;
    *not_after = n_a;
    0
}

/// Free a X.509 object allocated by Rust
///
/// # Safety
///
/// ptr must be a valid object obtained using `rs_x509_decode`
#[no_mangle]
pub unsafe extern "C" fn rs_x509_free(ptr: *mut X509) {
    if ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr));
}

fn x509_parse_error_to_errcode(e: &nom::Err<X509Error>) -> X509DecodeError {
    match e {
        nom::Err::Incomplete(_) => X509DecodeError::InvalidLength,
        nom::Err::Error(e) | nom::Err::Failure(e) => match e {
            X509Error::InvalidVersion => X509DecodeError::InvalidVersion,
            X509Error::InvalidSerial => X509DecodeError::InvalidSerial,
            X509Error::InvalidAlgorithmIdentifier => X509DecodeError::InvalidAlgorithmIdentifier,
            X509Error::InvalidX509Name => X509DecodeError::InvalidX509Name,
            X509Error::InvalidDate => X509DecodeError::InvalidDate,
            X509Error::InvalidExtensions => X509DecodeError::InvalidExtensions,
            X509Error::Der(_) => X509DecodeError::InvalidDER,
            _ => X509DecodeError::InvalidCert,
        },
    }
}
