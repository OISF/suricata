/* Copyright (C) 2023 Open Information Security Foundation
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

use std::{ffi::{CString,CStr}, os::raw::c_char};
use tls_parser::{TlsCipherSuiteID, TlsExtensionType, TlsVersion};

pub enum CJa4 {}

extern {
    pub fn Ja4Init() -> *mut CJa4;
    pub fn Ja4SetQUIC(j: *mut CJa4);
    pub fn Ja4SetTLSVersion(j: *mut CJa4, version: u16);
    pub fn Ja4SetALPN(j: *mut CJa4, proto: *const c_char, len: u8);
    pub fn Ja4AddCipher(j: *mut CJa4, cipher: u16);
    pub fn Ja4AddExtension(j: *mut CJa4, ext: u16);
    pub fn Ja4AddSigAlgo(j: *mut CJa4, sigalgo: u16);
    pub fn Ja4GetHash(j: *mut CJa4) -> *const c_char;
    pub fn Ja4Free(j: *mut *mut CJa4);
}

#[derive(Debug, PartialEq)]
pub struct JA4 {
    pub ptr: *mut CJa4,
}

impl JA4 {
    pub fn new() -> Self {
        let new_ptr = unsafe { Ja4Init() };
        unsafe { Ja4SetQUIC(new_ptr) };
        Self { ptr: new_ptr }
    }
    
    pub fn set_tls_version(&self, version: TlsVersion) {
        unsafe {
            Ja4SetTLSVersion(self.ptr, u16::from(version));
        }
    }
    
    pub fn set_alpn(&self, alpn: &[u8], len: usize) {
        unsafe {
            // allowing this since the pointer will not
            // be used further after the call to the C code
            #[allow(temporary_cstring_as_ptr)]
            Ja4SetALPN(self.ptr, CString::new(alpn).unwrap().as_ptr(), len as u8)
        }
    }
    
    pub fn add_cipher_suite(&self, cipher: TlsCipherSuiteID) {
        unsafe {
            Ja4AddCipher(self.ptr, u16::from(cipher));
        }
    }
    
    pub fn add_extension(&self, ext: TlsExtensionType) {
        unsafe {
            Ja4AddExtension(self.ptr, u16::from(ext));
        }
    }
    
    pub fn add_signature_algorithm(&self, sigalgo: u16) {
        unsafe {
            Ja4AddSigAlgo(self.ptr, sigalgo);
        }
    }

    pub fn get_hash(&self) -> Result<String, std::str::Utf8Error> {
        let c_str = unsafe { CStr::from_ptr(Ja4GetHash(self.ptr)) };
        Ok(String::from_utf8_lossy(c_str.to_bytes()).to_string())
    }
}

impl Drop for JA4 {
    fn drop(&mut self) {
        unsafe {
            Ja4Free(&mut self.ptr as *mut *mut CJa4);
        }
    }
}
