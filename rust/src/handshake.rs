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

use crate::jsonbuilder::HEX;
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
    pub(crate) alpn: [char; 2],
    pub(crate) quic: bool,
}

impl Default for HandshakeParams {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeParams {
    #[inline]
    fn is_grease(val: u16) -> bool {
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
            alpn: ['0', '0'],
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

    pub(crate) fn set_alpn(&mut self, alpn: &[u8]) {
        if !alpn.is_empty() {
            // If the first ALPN value is only a single character, then that character is treated as both the first and last character.
            if alpn.len() == 2 {
                // GREASE values are 2 bytes, so this could be one -- check
                let v: u16 = ((alpn[0] as u16) << 8) | alpn[alpn.len() - 1] as u16;
                if Self::is_grease(v) {
                    return;
                }
            }
            if !alpn[0].is_ascii_alphanumeric() || !alpn[alpn.len() - 1].is_ascii_alphanumeric() {
                // If the first or last byte of the first ALPN is non-alphanumeric (meaning not 0x30-0x39, 0x41-0x5A, or 0x61-0x7A), then we print the first and last characters of the hex representation of the first ALPN instead.
                self.alpn[0] = char::from(HEX[(alpn[0] >> 4) as usize]);
                self.alpn[1] = char::from(HEX[(alpn[alpn.len() - 1] & 0xF) as usize]);
                return;
            }
            self.alpn[0] = char::from(alpn[0]);
            self.alpn[1] = char::from(alpn[alpn.len() - 1]);
        }
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
pub unsafe extern "C" fn SCHandshakeSetALPN(
    hs: &mut HandshakeParams, proto: *const c_char, len: u16,
) {
    let b: &[u8] = std::slice::from_raw_parts(proto as *const c_uchar, len as usize);
    hs.set_alpn(b);
}

#[no_mangle]
pub unsafe extern "C" fn SCHandshakeFree(hs: &mut HandshakeParams) {
    let hs: Box<HandshakeParams> = Box::from_raw(hs);
    std::mem::drop(hs);
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

    #[test]
    fn test_set_alpn_ascii() {
        let mut hs = HandshakeParams::new();
        hs.set_alpn(b"http/1.1");
        assert_eq!(hs.alpn, ['h', '1']);
    }

    #[test]
    fn test_set_alpn_non_ascii_first_or_last() {
        let mut hs = HandshakeParams::new();
        hs.set_alpn(&[0x01, b'T', b'E', 0x7f]); // non-alphanumeric start and end
        assert_eq!(hs.alpn, [HEX[0x0], HEX[0xF]].map(|b| b as char)); // 0x01 -> 0, 0x7f -> f
    }

    #[test]
    fn test_set_alpn_grease_pair_filtered() {
        let mut hs = HandshakeParams::new();
        hs.set_alpn(&[0x2a, 0x2a]); // 0x2a2a GREASE
        assert_eq!(hs.alpn, ['0', '0']);
    }
}
