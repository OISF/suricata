/* Copyright (C) 2025 Open Information Security Foundation
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

// Author: Sascha Steinbiss <sascha@steinbiss.name>

*/

use libc::c_uchar;
use std::os::raw::c_char;
use tls_parser::{TlsCipherSuiteID, TlsExtensionType, TlsVersion};

#[derive(Debug, PartialEq)]
pub struct HandshakeParams {
    pub(crate) tls_version: Option<TlsVersion>,
    pub(crate) ciphersuites: Vec<TlsCipherSuiteID>,
    pub(crate) extensions: Vec<TlsExtensionType>,
    pub(crate) signature_algorithms: Vec<u16>,
    pub(crate) domain: bool,
    pub(crate) alpns: Vec<Vec<u8>>,
    pub(crate) quic: bool,
}

impl Default for HandshakeParams {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeParams {
    #[inline]
    pub(crate) fn is_grease(val: u16) -> bool {
        match val {
            0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a | 0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a
            | 0x9a9a | 0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa => true,
            _ => false,
        }
    }

    fn new() -> Self {
        Self {
            tls_version: None,
            ciphersuites: Vec::with_capacity(20),
            extensions: Vec::with_capacity(20),
            signature_algorithms: Vec::with_capacity(20),
            domain: false,
            alpns: Vec::with_capacity(4),
            quic: false,
        }
    }

    pub(crate) fn set_tls_version(&mut self, version: TlsVersion) {
        if Self::is_grease(u16::from(version)) {
            return;
        }
        // Track maximum of seen TLS versions
        match self.tls_version {
            None => {
                self.tls_version = Some(version);
            }
            Some(cur_version) => {
                if u16::from(version) > u16::from(cur_version) {
                    self.tls_version = Some(version);
                }
            }
        }
    }

    pub fn add_alpn(&mut self, alpn: &[u8]) {
        if alpn.is_empty() {
            return;
        }
        self.alpns.push(alpn.to_vec());
    }

    pub(crate) fn add_cipher_suite(&mut self, cipher: TlsCipherSuiteID) {
        if Self::is_grease(u16::from(cipher)) {
            return;
        }
        self.ciphersuites.push(cipher);
    }

    pub(crate) fn add_extension(&mut self, ext: TlsExtensionType) {
        if Self::is_grease(u16::from(ext)) {
            return;
        }
        if ext == TlsExtensionType::ServerName {
            self.domain = true;
        }
        self.extensions.push(ext);
    }

    pub(crate) fn add_signature_algorithm(&mut self, sigalgo: u16) {
        if Self::is_grease(sigalgo) {
            return;
        }
        self.signature_algorithms.push(sigalgo);
    }
}

// Objects used to allow C to call into this struct via the below C ABI
// that enables the return of a u8 pointer and length
#[repr(C)]
pub struct CStringData {
    data: *const u8,
    len: usize,
}

#[no_mangle]
pub extern "C" fn SCHandshakeNew() -> *mut HandshakeParams {
    let hs = Box::new(HandshakeParams::new());
    Box::into_raw(hs)
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeSetTLSVersion(hs: &mut HandshakeParams, version: u16) {
    hs.set_tls_version(TlsVersion(version));
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeAddCipher(hs: &mut HandshakeParams, cipher: u16) {
    hs.add_cipher_suite(TlsCipherSuiteID(cipher));
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeAddExtension(hs: &mut HandshakeParams, ext: u16) {
    hs.add_extension(TlsExtensionType(ext));
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeAddSigAlgo(hs: &mut HandshakeParams, sigalgo: u16) {
    hs.add_signature_algorithm(sigalgo);
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeAddALPN(
    hs: &mut HandshakeParams, alpn: *const c_char, len: u16,
) {
    let b: &[u8] = std::slice::from_raw_parts(alpn as *const c_uchar, len as usize);
    hs.add_alpn(b);
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeFree(hs: &mut HandshakeParams) {
    let hs: Box<HandshakeParams> = Box::from_raw(hs);
    std::mem::drop(hs);
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeGetVersion(hs: &HandshakeParams) -> u16 {
    u16::from(hs.tls_version.unwrap_or(TlsVersion(0)))
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeGetCiphers(
    hs: &mut HandshakeParams, out: *mut usize,
) -> *const u16 {
    *out = hs.ciphersuites.len();
    hs.ciphersuites.as_ptr() as *const u16
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeGetFirstCipher(j: &mut HandshakeParams) -> u16 {
    j.ciphersuites.first().map(|&v| *v).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeGetExtensions(
    hs: &mut HandshakeParams, out: *mut usize,
) -> *const u16 {
    *out = hs.extensions.len();
    hs.extensions.as_ptr() as *const u16
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeGetSigAlgs(
    hs: &mut HandshakeParams, out: *mut usize,
) -> *const u16 {
    *out = hs.signature_algorithms.len();
    hs.signature_algorithms.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeGetALPN(
    hs: &HandshakeParams, idx: u32, out: *mut CStringData,
) -> bool {
    if out.is_null() {
        return false;
    }
    if let Some(alpn) = hs.alpns.get(idx as usize) {
        *out = CStringData {
            data: alpn.as_ptr(),
            len: alpn.len(),
        };
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        let mut alpn = "foobar".as_bytes();
        let mut len = alpn.len();
        let v: u16 = ((alpn[0] as u16) << 8) | alpn[len - 1] as u16;
        assert!(!HandshakeParams::is_grease(v));

        alpn = &[0x0a, 0x0a];
        len = alpn.len();
        let v: u16 = ((alpn[0] as u16) << 8) | alpn[len - 1] as u16;
        assert!(HandshakeParams::is_grease(v));
    }

    #[test]
    fn test_tlsversion_max() {
        let mut hs = HandshakeParams::new();
        assert_eq!(hs.tls_version, None);
        hs.set_tls_version(TlsVersion::Ssl30);
        assert_eq!(hs.tls_version, Some(TlsVersion::Ssl30));
        hs.set_tls_version(TlsVersion::Tls12);
        assert_eq!(hs.tls_version, Some(TlsVersion::Tls12));
        hs.set_tls_version(TlsVersion::Tls10);
        assert_eq!(hs.tls_version, Some(TlsVersion::Tls12));
    }

    #[test]
    fn test_add_cipher_suite_filters_grease() {
        let mut hs = HandshakeParams::new();
        hs.add_cipher_suite(TlsCipherSuiteID(0x1a1a)); // GREASE
        assert_eq!(hs.ciphersuites.len(), 0);
    }

    #[test]
    fn test_add_cipher_suite_accepts_normal() {
        let mut hs = HandshakeParams::new();
        hs.add_cipher_suite(TlsCipherSuiteID(0x1301));
        assert_eq!(hs.ciphersuites, &[TlsCipherSuiteID(0x1301)]);
    }

    #[test]
    fn test_add_cipher_suite_len_tracking() {
        let mut hs = HandshakeParams::new();
        hs.add_cipher_suite(TlsCipherSuiteID(0x1301));
        hs.add_cipher_suite(TlsCipherSuiteID(0x1302));
        hs.add_cipher_suite(TlsCipherSuiteID(0x1a1a)); // GREASE
        assert_eq!(hs.ciphersuites.len(), 2);
    }

    #[test]
    fn test_add_extension_sets_domain_for_server_name() {
        let mut hs = HandshakeParams::new();
        hs.add_extension(TlsExtensionType::ServerName);
        assert!(hs.domain);
    }

    #[test]
    fn test_add_extension_filters_grease() {
        let mut hs = HandshakeParams::new();
        hs.add_extension(TlsExtensionType(0xaaaa)); // GREASE
        assert_eq!(hs.extensions.len(), 0);
    }

    #[test]
    fn test_add_extension_len_tracking() {
        let mut hs = HandshakeParams::new();
        hs.add_extension(TlsExtensionType::ClientCertificate);
        hs.add_extension(TlsExtensionType::ServerName);
        hs.add_extension(TlsExtensionType(0xaaaa)); // GREASE
        assert_eq!(hs.extensions.len(), 2);
    }

    #[test]
    fn test_add_signature_algorithm_filters_grease() {
        let mut hs = HandshakeParams::new();
        hs.add_signature_algorithm(0xbaba); // GREASE
        assert_eq!(hs.signature_algorithms.len(), 0);
    }

    #[test]
    fn test_add_signature_algorithm_len_tracking() {
        let mut hs = HandshakeParams::new();
        hs.add_signature_algorithm(0x1234);
        hs.add_signature_algorithm(0x1235);
        hs.add_signature_algorithm(0xbaba); // GREASE
        assert_eq!(hs.signature_algorithms.len(), 2);
    }
}
