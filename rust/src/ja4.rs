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

// Author: Sascha Steinbiss <sascha@steinbiss.name>

use digest::Digest;
use libc::c_uchar;
use sha2::Sha256;
use std::{cmp, os::raw::c_char};
use tls_parser::{TlsCipherSuiteID, TlsExtensionType, TlsVersion};

#[derive(Debug, PartialEq)]
pub struct JA4Cache {
    ja4: String,
    ja4_r: String,
    ja4_ro: String,
}

#[derive(Debug, PartialEq)]
pub struct JA4 {
    tls_version: Option<TlsVersion>,
    ciphersuites: Vec<TlsCipherSuiteID>,
    extensions: Vec<TlsExtensionType>,
    signature_algorithms: Vec<u16>,
    domain: bool,
    alpn: [char; 2],
    quic: bool,
    nof_exts: u16,
    nof_ciphers: u16,
    cache: Option<JA4Cache>,
}

impl Default for JA4 {
    fn default() -> Self {
        Self::new()
    }
}

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
            nof_ciphers: 0,
            cache: None,
        }
    }

    pub fn set_quic(&mut self) {
        self.quic = true;
        self.cache = None;
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
        self.cache = None;
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
            self.cache = None;
        }
    }

    pub fn add_cipher_suite(&mut self, cipher: TlsCipherSuiteID) {
        if JA4::is_grease(u16::from(cipher)) {
            return;
        }
        self.ciphersuites.push(cipher);
        self.nof_ciphers += 1;
        self.cache = None;
    }

    pub fn add_extension(&mut self, ext: TlsExtensionType) {
        if JA4::is_grease(u16::from(ext)) {
            return;
        }
        self.extensions.push(ext);
        if ext == TlsExtensionType::ServerName {
            self.domain = true;
        }
        self.nof_exts += 1;
        self.cache = None;
    }

    pub fn add_signature_algorithm(&mut self, sigalgo: u16) {
        if JA4::is_grease(sigalgo) {
            return;
        }
        self.signature_algorithms.push(sigalgo);
        self.cache = None;
    }

    pub fn get_hash(&mut self) -> (String, String, String) {
        if self.cache.is_none() {
            // Calculate JA4_a
            let ja4_a = format!(
                "{proto}{version}{sni}{nof_c:02}{nof_e:02}{al1}{al2}",
                proto = if self.quic { "q" } else { "t" },
                version = JA4::version_to_ja4code(self.tls_version),
                sni = if self.domain { "d" } else { "i" },
                nof_c = if self.nof_ciphers > 99 {
                    99
                } else {
                    self.nof_ciphers
                },
                nof_e = if self.nof_exts > 99 {
                    99
                } else {
                    self.nof_exts
                },
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
            let unsorted_cipherstrings: Vec<String> = self
                .ciphersuites
                .to_vec()
                .iter()
                .map(|v| format!("{:04x}", u16::from(*v)))
                .collect();
            let mut sha = Sha256::new();
            let ja4_b_raw = sorted_cipherstrings.join(",");
            let ja4_b_raw_unsorted = unsorted_cipherstrings.join(",");
            sha.update(&ja4_b_raw);
            let mut ja4_b = format!("{:x}", sha.finalize_reset());
            ja4_b.truncate(12);

            // Calculate JA4_c
            let mut extensions = self.extensions.to_vec();
            let unsorted_extstrings: Vec<String> = extensions
                .iter()
                .map(|v| format!("{:04x}", u16::from(*v)))
                .collect();
            extensions.sort_by(|a, b| u16::from(*a).cmp(&u16::from(*b)));
            extensions.retain(|&ext| {
                ext != TlsExtensionType::ApplicationLayerProtocolNegotiation
                    && ext != TlsExtensionType::ServerName
            });
            let sorted_extstrings: Vec<String> = extensions
                .iter()
                .map(|v| format!("{:04x}", u16::from(*v)))
                .collect();
            let ja4_c1_raw = sorted_extstrings.join(",");
            let ja4_c1_unsorted_raw = unsorted_extstrings.join(",");
            let ja4_c_raw: String;
            let ja4_c_raw_unsorted: String;
            if self.signature_algorithms.is_empty() {
                ja4_c_raw = ja4_c1_raw;
                ja4_c_raw_unsorted = ja4_c1_unsorted_raw;
            } else {
                let unsorted_sigalgostrings: Vec<String> = self
                    .signature_algorithms
                    .iter()
                    .map(|v| format!("{:04x}", (*v)))
                    .collect();
                let ja4_c2_raw = unsorted_sigalgostrings.join(",");
                ja4_c_raw = format!("{}_{}", ja4_c1_raw, ja4_c2_raw);
                ja4_c_raw_unsorted = format!("{}_{}", ja4_c1_unsorted_raw, ja4_c2_raw);
            }
            sha.update(&ja4_c_raw);
            let mut ja4_c = format!("{:x}", sha.finalize());
            ja4_c.truncate(12);

            self.cache = Some(JA4Cache {
                ja4: format!("{}_{}_{}", ja4_a, ja4_b, ja4_c),
                ja4_r: format!("{}_{}_{}", ja4_a, ja4_b_raw, ja4_c_raw),
                ja4_ro: format!("{}_{}_{}", ja4_a, ja4_b_raw_unsorted, ja4_c_raw_unsorted),
            });
        }
        if let Some(ref cache) = self.cache {
            return (cache.ja4.clone(), cache.ja4_r.clone(), cache.ja4_ro.clone());
        } else {
            panic!("JA4 strings always expected before returning")
        }
    }
}

pub struct SCJA4(JA4);

#[no_mangle]
pub extern "C" fn SCJA4New() -> *mut SCJA4 {
    let j = Box::new(SCJA4(JA4::new()));
    Box::into_raw(j)
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SetTLSVersion(j: &mut SCJA4, version: u16) {
    j.0.set_tls_version(TlsVersion(version));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4AddCipher(j: &mut SCJA4, cipher: u16) {
    j.0.add_cipher_suite(TlsCipherSuiteID(cipher));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4AddExtension(j: &mut SCJA4, ext: u16) {
    j.0.add_extension(TlsExtensionType(ext));
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4AddSigAlgo(j: &mut SCJA4, sigalgo: u16) {
    j.0.add_signature_algorithm(sigalgo);
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4SetALPN(j: &mut SCJA4, proto: *const c_char, len: u16) {
    let b: &[u8] = std::slice::from_raw_parts(proto as *const c_uchar, len as usize);
    j.0.set_alpn(b);
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4GetHash(
    j: &mut SCJA4, out: &mut [u8; 36], out_r: *mut c_uchar, out_r_len: usize, out_ro: *mut c_uchar,
    out_ro_len: usize,
) {
    let (ja4h, ja4r, ja4ro) = j.0.get_hash();
    if out.len() == 36 {
        out[0..36].copy_from_slice(ja4h.as_bytes());
    }
    if !out_r.is_null() && out_r_len > 0 {
        let c_r: &mut [u8] = std::slice::from_raw_parts_mut(out_r, out_r_len);
        let r_effective_len = cmp::min(out_r_len, ja4r.len());
        c_r[..r_effective_len].copy_from_slice(ja4r[..r_effective_len].as_bytes());
        c_r[r_effective_len] = b'\0';
    }
    if !out_ro.is_null() && out_ro_len > 0 {
        let c_ro: &mut [u8] = std::slice::from_raw_parts_mut(out_ro, out_ro_len);
        let ro_effective_len = cmp::min(out_ro_len, ja4ro.len());
        c_ro[..ro_effective_len].copy_from_slice(ja4ro[..ro_effective_len].as_bytes());
        c_ro[ro_effective_len] = b'\0';
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCJA4Free(j: &mut SCJA4) {
    let ja4: Box<SCJA4> = Box::from_raw(j);
    std::mem::drop(ja4);
}

#[cfg(test)]
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
        let mut j = JA4::new();

        for i in 1..200 {
            j.add_cipher_suite(TlsCipherSuiteID(i));
        }
        for i in 1..200 {
            j.add_extension(TlsExtensionType(i));
        }

        let (mut s, _, _) = j.get_hash();
        s.truncate(10);
        assert_eq!(s, "t00i999900");
    }

    #[test]
    fn test_short_alpn() {
        let mut j = JA4::new();

        j.set_alpn("a".as_bytes());
        let (mut s, mut ja4r, mut ja4ro) = j.get_hash();
        s.truncate(10);
        assert_eq!(s, "t00i000000");
        ja4r.truncate(10);
        assert_eq!(ja4r, "t00i000000");
        ja4ro.truncate(10);
        assert_eq!(ja4ro, "t00i000000");

        j.set_alpn("aa".as_bytes());
        let (mut s, _, _) = j.get_hash();
        s.truncate(10);
        assert_eq!(s, "t00i0000aa");
    }

    #[test]
    fn test_get_hash() {
        let mut j = JA4::new();

        // the empty JA4 hash
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "t00i000000_e3b0c44298fc_e3b0c44298fc");
        assert_eq!(ja4r, "t00i000000__");
        assert_eq!(ja4ro, "t00i000000__");

        // set TLS version
        j.set_tls_version(TlsVersion::Tls12);
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "t12i000000_e3b0c44298fc_e3b0c44298fc");
        assert_eq!(ja4r, "t12i000000__");
        assert_eq!(ja4ro, "t12i000000__");

        // set QUIC
        j.set_quic();
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "q12i000000_e3b0c44298fc_e3b0c44298fc");
        assert_eq!(ja4r, "q12i000000__");
        assert_eq!(ja4ro, "q12i000000__");

        // set GREASE extension, should be ignored
        j.add_extension(TlsExtensionType(0x0a0a));
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "q12i000000_e3b0c44298fc_e3b0c44298fc");
        assert_eq!(ja4r, "q12i000000__");
        assert_eq!(ja4ro, "q12i000000__");

        // set SNI extension, should only increase count and change i->d
        j.add_extension(TlsExtensionType(0x0000));
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "q12d000100_e3b0c44298fc_e3b0c44298fc");
        assert_eq!(ja4r, "q12d000100__");
        assert_eq!(ja4ro, "q12d000100__0000");

        // set ALPN extension, should only increase count and set end of JA4_a
        j.set_alpn(b"h3-16");
        j.add_extension(TlsExtensionType::ApplicationLayerProtocolNegotiation);
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "q12d0002h6_e3b0c44298fc_e3b0c44298fc");
        assert_eq!(ja4r, "q12d0002h6__");
        assert_eq!(ja4ro, "q12d0002h6__0000,0010");

        // set some ciphers
        j.add_cipher_suite(TlsCipherSuiteID(0x1111));
        j.add_cipher_suite(TlsCipherSuiteID(0x0a20));
        j.add_cipher_suite(TlsCipherSuiteID(0xbada));
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "q12d0302h6_f500716053f9_e3b0c44298fc");
        assert_eq!(ja4r, "q12d0302h6_0a20,1111,bada_");
        assert_eq!(ja4ro, "q12d0302h6_1111,0a20,bada_0000,0010");

        // set some extensions and signature algorithms
        j.add_extension(TlsExtensionType(0xface));
        j.add_extension(TlsExtensionType(0x0121));
        j.add_extension(TlsExtensionType(0x1234));
        j.add_signature_algorithm(0x6666);
        let (s, ja4r, ja4ro) = j.get_hash();
        assert_eq!(s, "q12d0305h6_f500716053f9_2debc8880bae");
        assert_eq!(ja4r, "q12d0305h6_0a20,1111,bada_0121,1234,face_6666");
        assert_eq!(
            ja4ro,
            "q12d0305h6_1111,0a20,bada_0000,0010,face,0121,1234_6666"
        );
    }
}
