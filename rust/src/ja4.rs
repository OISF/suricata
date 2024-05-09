/* Copyright (C) 2023-2024 Open Information Security Foundation
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

#[cfg(feature = "ja4")]
use digest::Digest;
use libc::c_uchar;
#[cfg(feature = "ja4")]
use sha2::Sha256;
#[cfg(feature = "ja4")]
use std::cmp::min;
use std::os::raw::c_char;
use tls_parser::{TlsCipherSuiteID, TlsExtensionType, TlsVersion};

#[derive(Debug, PartialEq)]
pub struct JA4 {
    tls_version: Option<TlsVersion>,
    ciphersuites: Vec<TlsCipherSuiteID>,
    extensions: Vec<TlsExtensionType>,
    signature_algorithms: Vec<u16>,
    domain: bool,
    alpn: [char; 2],
    quic: bool,
    // Some extensions contribute to the total count component of the
    // fingerprint, yet are not to be included in the SHA256 hash component.
    // Let's track the count separately.
    nof_exts: u16,
}

impl Default for JA4 {
    fn default() -> Self {
        Self::new()
    }
}

// Stubs for when JA4 is disabled
#[cfg(not(feature = "ja4"))]
impl JA4 {
    pub fn new() -> Self {
        Self {
            tls_version: None,
            // Vec::new() does not allocate memory until filled, which we
            // will not do here.
            ciphersuites: Vec::new(),
            extensions: Vec::new(),
            signature_algorithms: Vec::new(),
            domain: false,
            alpn: ['0', '0'],
            quic: false,
            nof_exts: 0,
        }
    }
    pub fn set_quic(&mut self) {}
    pub fn set_tls_version(&mut self, _version: TlsVersion) {}
    pub fn set_alpn(&mut self, _alpn: &[u8]) {}
    pub fn add_cipher_suite(&mut self, _cipher: TlsCipherSuiteID) {}
    pub fn add_extension(&mut self, _ext: TlsExtensionType) {}
    pub fn add_signature_algorithm(&mut self, _sigalgo: u16) {}
    pub fn get_hash(&self) -> String {
        String::new()
    }
}

#[cfg(feature = "ja4")]
impl JA4 {
    #[inline]
    fn is_grease(val: u16) -> bool {
        match val {
            0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a | 0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a
            | 0x9a9a | 0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa => true,
            _ => false,
        }
    }

    #[inline]
    fn version_to_ja4code(val: Option<TlsVersion>) -> &'static str {
        match val {
            Some(TlsVersion::Tls13) => "13",
            Some(TlsVersion::Tls12) => "12",
            Some(TlsVersion::Tls11) => "11",
            Some(TlsVersion::Tls10) => "10",
            Some(TlsVersion::Ssl30) => "s3",
            // the TLS parser does not support SSL 1.0 and 2.0 hence no
            // support for "s1"/"s2"
            _ => "00",
        }
    }

    pub fn new() -> Self {
        Self {
            tls_version: None,
            ciphersuites: Vec::with_capacity(20),
            extensions: Vec::with_capacity(20),
            signature_algorithms: Vec::with_capacity(20),
            domain: false,
            alpn: ['0', '0'],
            quic: false,
            nof_exts: 0,
        }
    }

    pub fn set_quic(&mut self) {
        self.quic = true;
    }

    pub fn set_tls_version(&mut self, version: TlsVersion) {
        if JA4::is_grease(u16::from(version)) {
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

    pub fn set_alpn(&mut self, alpn: &[u8]) {
        if alpn.len() > 1 {
            if alpn.len() == 2 {
                // GREASE values are 2 bytes, so this could be one -- check
                let v: u16 = (alpn[0] as u16) << 8 | alpn[alpn.len() - 1] as u16;
                if JA4::is_grease(v) {
                    return;
                }
            }
            self.alpn[0] = char::from(alpn[0]);
            self.alpn[1] = char::from(alpn[alpn.len() - 1]);
        }
    }

    pub fn add_cipher_suite(&mut self, cipher: TlsCipherSuiteID) {
        if JA4::is_grease(u16::from(cipher)) {
            return;
        }
        self.ciphersuites.push(cipher);
    }

    pub fn add_extension(&mut self, ext: TlsExtensionType) {
        if JA4::is_grease(u16::from(ext)) {
            return;
        }
        if ext != TlsExtensionType::ApplicationLayerProtocolNegotiation
            && ext != TlsExtensionType::ServerName
        {
            self.extensions.push(ext);
        } else if ext == TlsExtensionType::ServerName {
            self.domain = true;
        }
        self.nof_exts += 1;
    }

    pub fn add_signature_algorithm(&mut self, sigalgo: u16) {
        if JA4::is_grease(sigalgo) {
            return;
        }
        self.signature_algorithms.push(sigalgo);
    }

    pub fn get_hash(&self) -> String {
        // Calculate JA4_a
        let ja4_a = format!(
            "{proto}{version}{sni}{nof_c:02}{nof_e:02}{al1}{al2}",
            proto = if self.quic { "q" } else { "t" },
            version = JA4::version_to_ja4code(self.tls_version),
            sni = if self.domain { "d" } else { "i" },
            nof_c = min(99, self.ciphersuites.len()),
            nof_e = min(99, self.nof_exts),
            al1 = self.alpn[0],
            al2 = self.alpn[1]
        );

        // Calculate JA4_b
        let mut sorted_ciphers = self.ciphersuites.to_vec();
        sorted_ciphers.sort_by(|a, b| u16::from(*a).cmp(&u16::from(*b)));
        let sorted_cipherstrings: Vec<String> = sorted_ciphers
            .iter()
            .map(|v| format!("{:04x}", u16::from(*v)))
            .collect();
        let mut sha = Sha256::new();
        let ja4_b_raw = sorted_cipherstrings.join(",");
        sha.update(&ja4_b_raw);
        let mut ja4_b = format!("{:x}", sha.finalize_reset());
        ja4_b.truncate(12);

        // Calculate JA4_c
        let mut sorted_exts = self.extensions.to_vec();
        sorted_exts.sort_by(|a, b| u16::from(*a).cmp(&u16::from(*b)));
        let sorted_extstrings: Vec<String> = sorted_exts
            .iter()
            .map(|v| format!("{:04x}", u16::from(*v)))
            .collect();
        let ja4_c1_raw = sorted_extstrings.join(",");
        let unsorted_sigalgostrings: Vec<String> = self
            .signature_algorithms
            .iter()
            .map(|v| format!("{:04x}", (*v)))
            .collect();
        let ja4_c2_raw = unsorted_sigalgostrings.join(",");
        let ja4_c_raw = format!("{}_{}", ja4_c1_raw, ja4_c2_raw);
        sha.update(&ja4_c_raw);
        let mut ja4_c = format!("{:x}", sha.finalize());
        ja4_c.truncate(12);

        return format!("{}_{}_{}", ja4_a, ja4_b, ja4_c);
    }
}

#[no_mangle]
pub extern "C" fn SCJA4New() -> *mut JA4 {
    let j = Box::new(JA4::new());
    Box::into_raw(j)
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SetTLSVersion(j: &mut JA4, version: u16) {
    j.set_tls_version(TlsVersion(version));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4AddCipher(j: &mut JA4, cipher: u16) {
    j.add_cipher_suite(TlsCipherSuiteID(cipher));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4AddExtension(j: &mut JA4, ext: u16) {
    j.add_extension(TlsExtensionType(ext));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4AddSigAlgo(j: &mut JA4, sigalgo: u16) {
    j.add_signature_algorithm(sigalgo);
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SetALPN(j: &mut JA4, proto: *const c_char, len: u16) {
    let b: &[u8] = std::slice::from_raw_parts(proto as *const c_uchar, len as usize);
    j.set_alpn(b);
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4GetHash(j: &mut JA4, out: &mut [u8; 36]) {
    let hash = j.get_hash();
    out[0..36].copy_from_slice(hash.as_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4Free(j: &mut JA4) {
    let ja4: Box<JA4> = Box::from_raw(j);
    std::mem::drop(ja4);
}

#[cfg(all(test, feature = "ja4"))]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        let mut alpn = "foobar".as_bytes();
        let mut len = alpn.len();
        let v: u16 = (alpn[0] as u16) << 8 | alpn[len - 1] as u16;
        assert!(!JA4::is_grease(v));

        alpn = &[0x0a, 0x0a];
        len = alpn.len();
        let v: u16 = (alpn[0] as u16) << 8 | alpn[len - 1] as u16;
        assert!(JA4::is_grease(v));
    }

    #[test]
    fn test_tlsversion_max() {
        let mut j = JA4::new();
        assert_eq!(j.tls_version, None);
        j.set_tls_version(TlsVersion::Ssl30);
        assert_eq!(j.tls_version, Some(TlsVersion::Ssl30));
        j.set_tls_version(TlsVersion::Tls12);
        assert_eq!(j.tls_version, Some(TlsVersion::Tls12));
        j.set_tls_version(TlsVersion::Tls10);
        assert_eq!(j.tls_version, Some(TlsVersion::Tls12));
    }

    #[test]
    fn test_get_hash_limit_numbers() {
        // Test whether the limitation of the extension and ciphersuite
        // count to 99 is reflected correctly.
        let mut j = JA4::new();

        for i in 1..200 {
            j.add_cipher_suite(TlsCipherSuiteID(i));
        }
        for i in 1..200 {
            j.add_extension(TlsExtensionType(i));
        }

        let mut s = j.get_hash();
        s.truncate(10);
        assert_eq!(s, "t00i999900");
    }

    #[test]
    fn test_short_alpn() {
        let mut j = JA4::new();

        j.set_alpn("a".as_bytes());
        let mut s = j.get_hash();
        s.truncate(10);
        assert_eq!(s, "t00i000000");

        j.set_alpn("aa".as_bytes());
        let mut s = j.get_hash();
        s.truncate(10);
        assert_eq!(s, "t00i0000aa");
    }

    #[test]
    fn test_get_hash() {
        let mut j = JA4::new();

        // the empty JA4 hash
        let s = j.get_hash();
        assert_eq!(s, "t00i000000_e3b0c44298fc_d2e2adf7177b");

        // set TLS version
        j.set_tls_version(TlsVersion::Tls12);
        let s = j.get_hash();
        assert_eq!(s, "t12i000000_e3b0c44298fc_d2e2adf7177b");

        // set QUIC
        j.set_quic();
        let s = j.get_hash();
        assert_eq!(s, "q12i000000_e3b0c44298fc_d2e2adf7177b");

        // set GREASE extension, should be ignored
        j.add_extension(TlsExtensionType(0x0a0a));
        let s = j.get_hash();
        assert_eq!(s, "q12i000000_e3b0c44298fc_d2e2adf7177b");

        // set SNI extension, should only increase count and change i->d
        j.add_extension(TlsExtensionType(0x0000));
        let s = j.get_hash();
        assert_eq!(s, "q12d000100_e3b0c44298fc_d2e2adf7177b");

        // set ALPN extension, should only increase count and set end of JA4_a
        j.set_alpn(b"h3-16");
        j.add_extension(TlsExtensionType::ApplicationLayerProtocolNegotiation);
        let s = j.get_hash();
        assert_eq!(s, "q12d0002h6_e3b0c44298fc_d2e2adf7177b");

        // set some ciphers
        j.add_cipher_suite(TlsCipherSuiteID(0x1111));
        j.add_cipher_suite(TlsCipherSuiteID(0x0a20));
        j.add_cipher_suite(TlsCipherSuiteID(0xbada));
        let s = j.get_hash();
        assert_eq!(s, "q12d0302h6_f500716053f9_d2e2adf7177b");

        // set some extensions and signature algorithms
        j.add_extension(TlsExtensionType(0xface));
        j.add_extension(TlsExtensionType(0x0121));
        j.add_extension(TlsExtensionType(0x1234));
        j.add_signature_algorithm(0x6666);
        let s = j.get_hash();
        assert_eq!(s, "q12d0305h6_f500716053f9_2debc8880bae");
    }
}
