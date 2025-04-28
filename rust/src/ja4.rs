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
use crate::jsonbuilder::HEX;
#[cfg(feature = "ja4")]
use digest::Digest;
#[cfg(feature = "ja4")]
use sha2::Sha256;
#[cfg(feature = "ja4")]
use std::cmp::min;
#[cfg(feature = "ja4")]
use tls_parser::{TlsExtensionType, TlsVersion};

use crate::handshake::HandshakeParams;

pub const JA4_HEX_LEN: usize = 36;

pub(crate) trait JA4Impl {
    fn try_new(hs: &HandshakeParams) -> Option<JA4>;
}

#[derive(Debug, PartialEq)]
pub struct JA4 {
    hash: String,
}

impl AsRef<str> for JA4 {
    fn as_ref(&self) -> &str {
        &self.hash
    }
}

#[cfg(feature = "ja4")]
impl JA4 {
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

    fn format_alpn(alpn: Option<&Vec<u8>>) -> [char; 2] {
        let mut ret = ['0', '0'];

        if let Some(alpn) = alpn {
            if !alpn.is_empty() {
                // If the first ALPN value is only a single character, then that character is treated as both the first and last character.
                if alpn.len() == 2 {
                    // GREASE values are 2 bytes, so this could be one -- check
                    let v: u16 = ((alpn[0] as u16) << 8) | alpn[alpn.len() - 1] as u16;
                    if HandshakeParams::is_grease(v) {
                        return ret;
                    }
                }
                if !alpn[0].is_ascii_alphanumeric() || !alpn[alpn.len() - 1].is_ascii_alphanumeric()
                {
                    // If the first or last byte of the first ALPN is non-alphanumeric (meaning not 0x30-0x39, 0x41-0x5A, or 0x61-0x7A), then we print the first and last characters of the hex representation of the first ALPN instead.
                    ret[0] = char::from(HEX[(alpn[0] >> 4) as usize]);
                    ret[1] = char::from(HEX[(alpn[alpn.len() - 1] & 0xF) as usize]);
                } else {
                    ret[0] = char::from(alpn[0]);
                    ret[1] = char::from(alpn[alpn.len() - 1]);
                }
            }
        }
        ret
    }
}

#[cfg(feature = "ja4")]
impl JA4Impl for JA4 {
    fn try_new(hs: &HandshakeParams) -> Option<Self> {
        // All non-GREASE extensions are stored to produce a more verbose, complete output
        // of extensions but we need to omit ALPN & SNI extensions from the JA4_a hash.
        let mut exts = hs
            .extensions
            .iter()
            .filter(|&ext| {
                *ext != TlsExtensionType::ApplicationLayerProtocolNegotiation
                    && *ext != TlsExtensionType::ServerName
            })
            .collect::<Vec<&TlsExtensionType>>();

        let alpn = Self::format_alpn(hs.alpns.first());

        // Calculate JA4_a
        let ja4_a = format!(
            "{proto}{version}{sni}{nof_c:02}{nof_e:02}{al1}{al2}",
            proto = if hs.quic { "q" } else { "t" },
            version = Self::version_to_ja4code(hs.tls_version),
            sni = if hs.domain { "d" } else { "i" },
            nof_c = min(99, hs.ciphersuites.len()),
            nof_e = min(99, hs.extensions.len()),
            al1 = alpn[0],
            al2 = alpn[1]
        );

        // Calculate JA4_b
        let mut sorted_ciphers = hs.ciphersuites.to_vec();
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
        exts.sort_by(|&a, &b| u16::from(*a).cmp(&u16::from(*b)));
        let sorted_extstrings: Vec<String> = exts
            .into_iter()
            .map(|&v| format!("{:04x}", u16::from(v)))
            .collect();
        let ja4_c1_raw = sorted_extstrings.join(",");
        let unsorted_sigalgostrings: Vec<String> = hs
            .signature_algorithms
            .iter()
            .map(|v| format!("{:04x}", (*v)))
            .collect();
        let ja4_c2_raw = unsorted_sigalgostrings.join(",");
        let ja4_c_raw = format!("{}_{}", ja4_c1_raw, ja4_c2_raw);
        sha.update(&ja4_c_raw);
        let mut ja4_c = format!("{:x}", sha.finalize());
        ja4_c.truncate(12);

        Some(Self {
            hash: format!("{}_{}_{}", ja4_a, ja4_b, ja4_c),
        })
    }
}

#[cfg(not(feature = "ja4"))]
impl JA4Impl for JA4 {
    fn try_new(_hs: &HandshakeParams) -> Option<Self> {
        None
    }
}

// C ABI
#[cfg(feature = "ja4")]
#[no_mangle]
pub unsafe extern "C" fn SCJA4GetHash(hs: &HandshakeParams, out: &mut [u8; JA4_HEX_LEN]) {
    if let Some(ja4) = JA4::try_new(hs) {
        out[0..JA4_HEX_LEN].copy_from_slice(ja4.as_ref().as_bytes());
    }
}

#[cfg(test)]
#[cfg(feature = "ja4")]
mod tests {
    use super::*;
    use tls_parser::{TlsCipherSuiteID, TlsExtensionType, TlsVersion};

    #[test]
    fn test_format_alpn_ascii() {
        let res = JA4::format_alpn(Some(&"http/1.1".as_bytes().to_vec()));
        assert_eq!(res, ['h', '1']);
    }

    #[test]
    fn test_add_alpn_non_ascii_first_or_last() {
        let res = JA4::format_alpn(Some(&vec![0x01, b'T', b'E', 0x7f])); // non-alphanumeric start and end
        assert_eq!(res, [HEX[0x0], HEX[0xF]].map(|b| b as char)); // 0x01 -> 0, 0x7f -> f
    }

    #[test]
    fn test_add_alpn_grease_pair_filtered() {
        let res = JA4::format_alpn(Some(&vec![0x2a, 0x2a])); // 0x2a2a GREASE
        assert_eq!(res, ['0', '0']);
    }

    #[test]
    fn test_hash_limit_numbers() {
        // Test whether the limitation of the extension and ciphersuite
        // count to 99 is reflected correctly.
        let mut hs = HandshakeParams::default();

        for i in 1..200 {
            hs.add_cipher_suite(TlsCipherSuiteID(i));
        }
        for i in 1..200 {
            hs.add_extension(TlsExtensionType(i));
        }

        let ja4 = JA4::try_new(&hs).expect("JA4 create failure");

        // Only testing the ja4_a portion of the hash, we we truncate to
        // ensure we're only testing this
        let mut ja4_hash = ja4.as_ref().to_string();
        ja4_hash.truncate(10);

        assert_eq!(ja4_hash, "t00i999900");
    }

    #[test]
    fn test_short_alpn() {
        let mut hs = HandshakeParams::default();
        hs.add_alpn("b".as_bytes());
        let mut s = JA4::try_new(&hs)
            .expect("JA4 create failure")
            .as_ref()
            .to_string();
        s.truncate(10);
        assert_eq!(s, "t00i0000bb");

        let mut hs = HandshakeParams::default();
        hs.add_alpn("h2".as_bytes());
        let mut s = JA4::try_new(&hs)
            .expect("JA4 create failure")
            .as_ref()
            .to_string();
        s.truncate(10);
        assert_eq!(s, "t00i0000h2");

        // from https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md#alpn-extension-value
        let mut hs = HandshakeParams::default();
        hs.add_alpn(&[0xab]);
        let mut s = JA4::try_new(&hs)
            .expect("JA4 create failure")
            .as_ref()
            .to_string();
        s.truncate(10);
        assert_eq!(s, "t00i0000ab");

        let mut hs = HandshakeParams::default();
        hs.add_alpn(&[0xab, 0xcd]);
        let mut s = JA4::try_new(&hs)
            .expect("JA4 create failure")
            .as_ref()
            .to_string();
        s.truncate(10);
        assert_eq!(s, "t00i0000ad");

        let mut hs = HandshakeParams::default();
        hs.add_alpn(&[0x30, 0xab]);
        let mut s = JA4::try_new(&hs)
            .expect("JA4 create failure")
            .as_ref()
            .to_string();
        s.truncate(10);
        assert_eq!(s, "t00i00003b");

        let mut hs = HandshakeParams::default();
        hs.add_alpn(&[0x30, 0x31, 0xab, 0xcd]);
        let mut s = JA4::try_new(&hs)
            .expect("JA4 create failure")
            .as_ref()
            .to_string();
        s.truncate(10);
        assert_eq!(s, "t00i00003d");

        let mut hs = HandshakeParams::default();
        hs.add_alpn(&[0x30, 0xab, 0xcd, 0x31]);
        let mut s = JA4::try_new(&hs)
            .expect("JA4 create failure")
            .as_ref()
            .to_string();
        s.truncate(10);
        assert_eq!(s, "t00i000001");
    }

    #[test]
    fn test_get_hash() {
        let mut hs = HandshakeParams::default();

        // the empty JA4 hash
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "t00i000000_e3b0c44298fc_d2e2adf7177b");

        // set TLS version
        hs.set_tls_version(TlsVersion::Tls12);
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "t12i000000_e3b0c44298fc_d2e2adf7177b");

        // set QUIC
        hs.quic = true;
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "q12i000000_e3b0c44298fc_d2e2adf7177b");

        // set GREASE extension, should be ignored
        hs.add_extension(TlsExtensionType(0x0a0a));
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "q12i000000_e3b0c44298fc_d2e2adf7177b");

        // set SNI extension, should only increase count and change i->d
        hs.add_extension(TlsExtensionType(0x0000));
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "q12d000100_e3b0c44298fc_d2e2adf7177b");

        // set ALPN extension, should only increase count and set end of JA4_a
        hs.add_alpn(b"h3-16");
        hs.add_extension(TlsExtensionType::ApplicationLayerProtocolNegotiation);
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "q12d0002h6_e3b0c44298fc_d2e2adf7177b");

        // set some ciphers
        hs.add_cipher_suite(TlsCipherSuiteID(0x1111));
        hs.add_cipher_suite(TlsCipherSuiteID(0x0a20));
        hs.add_cipher_suite(TlsCipherSuiteID(0xbada));
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "q12d0302h6_f500716053f9_d2e2adf7177b");

        // set some extensions and signature algorithms
        hs.add_extension(TlsExtensionType(0xface));
        hs.add_extension(TlsExtensionType(0x0121));
        hs.add_extension(TlsExtensionType(0x1234));
        hs.add_signature_algorithm(0x6666);
        let s = JA4::try_new(&hs).expect("JA4 create failure");
        assert_eq!(s.as_ref(), "q12d0305h6_f500716053f9_2debc8880bae");
    }
}
