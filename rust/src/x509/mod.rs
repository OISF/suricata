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

use std;
use std::ffi::CString;
use std::os::raw::c_char;
use x509_parser::{parse_x509_der, X509Certificate};

pub struct X509(X509Certificate<'static>);

#[no_mangle]
pub extern "C" fn rs_x509_decode(input: *const u8, input_len: u32) -> *mut X509 {
    let slice = build_slice!(input, input_len as usize);
    let res = parse_x509_der(slice);
    match res {
        Ok((_rem, cert)) => {
            Box::into_raw(Box::new(X509(cert)))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_x509_get_subject(ptr: *const X509) -> *mut c_char {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    let x509 = cast_pointer! {ptr, X509};
    let subject = format!("{}", x509.0.tbs_certificate.subject);
    let c_str = CString::new(subject).unwrap();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn rs_x509_get_issuer(ptr: *const X509) -> *mut c_char {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    let x509 = cast_pointer! {ptr, X509};
    let issuer = format!("{}", x509.0.tbs_certificate.issuer);
    let c_str = CString::new(issuer).unwrap();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn rs_x509_get_serial(ptr: *const X509) -> *mut c_char {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    let x509 = cast_pointer! {ptr, X509};
    let raw_serial = x509.0.tbs_certificate.raw_serial();
    let v : Vec<_> = raw_serial
        .iter()
        .map(|x| format!("{:02X}", x))
        .collect();
    let serial = v.join(":");
    let c_str = CString::new(serial).unwrap();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn rs_x509_get_validity(
    ptr: *const X509,
    not_before: *mut i64,
    not_after: *mut i64,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let x509 = cast_pointer! {ptr, X509};
    let n_b = x509.0.tbs_certificate.validity.not_before.to_timespec().sec;
    let n_a = x509.0.tbs_certificate.validity.not_after.to_timespec().sec;
    unsafe {
        *not_before = n_b;
        *not_after = n_a;
    }
    0
}

#[no_mangle]
pub extern "C" fn rs_x509_free(ptr: *mut X509) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}
