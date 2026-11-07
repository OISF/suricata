/* Copyright (C) 2021 Open Information Security Foundation
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

use super::parser::{quic_pkt_num, QuicHeader};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use std::convert::TryInto;

pub const AES128_KEY_LEN: usize = 16;
pub const AES128_TAG_LEN: usize = 16;
pub const AES128_IV_LEN: usize = 12;
const PKT_NUM_BUF_MAX_LEN: usize = 4;
// RFC 9001 section 5.8.
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

pub struct HeaderProtectionKey(Aes128);

impl HeaderProtectionKey {
    fn new(secret: &[u8], version: u32) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(secret).unwrap();
        let mut secret = [0u8; AES128_KEY_LEN];
        let quichp = if version == 0x6b3343cf {
            b"quicv2 hp" as &[u8]
        } else {
            b"quic hp" as &[u8]
        };
        hkdf_expand_label(&hk, quichp, &mut secret, AES128_KEY_LEN as u16);
        return Self(Aes128::new((&secret).into()));
    }

    pub fn decrypt_in_place(
        &self, sample: &[u8], first: &mut u8, packet_number: &mut [u8],
    ) -> Result<(), ()> {
        debug_validate_bug_on!(sample.len() != AES128_KEY_LEN);
        let mut mask: [u8; AES128_KEY_LEN] = sample[..AES128_KEY_LEN].try_into().map_err(|_| ())?;
        self.0.encrypt_block((&mut mask).into());

        let (first_mask, pn_mask) = mask.split_first().unwrap();

        let bits = if (*first & 0x80) != 0 {
            0x0f // Long header: 4 bits masked
        } else {
            0x1f // Short header: 5 bits masked
        };

        *first ^= first_mask & bits;
        let pn_len = (*first & 0x03) as usize + 1;

        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

pub struct PacketKey {
    key: Aes128Gcm,
    iv: [u8; AES128_IV_LEN],
}

impl PacketKey {
    fn new(secret: &[u8], version: u32) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(secret).unwrap();
        let mut secret = [0u8; AES128_KEY_LEN];
        let quickey = if version == 0x6b3343cf {
            b"quicv2 key" as &[u8]
        } else {
            b"quic key" as &[u8]
        };
        hkdf_expand_label(&hk, quickey, &mut secret, AES128_KEY_LEN as u16);
        let key = Aes128Gcm::new((&secret).into());

        let mut r = PacketKey {
            key,
            iv: [0u8; AES128_IV_LEN],
        };
        let quiciv = if version == 0x6b3343cf {
            b"quicv2 iv" as &[u8]
        } else {
            b"quic iv" as &[u8]
        };
        hkdf_expand_label(&hk, quiciv, &mut r.iv, AES128_IV_LEN as u16);
        return r;
    }

    pub fn decrypt_in_place<'a>(
        &self, packet_number: u64, header: &[u8], payload: &'a mut [u8],
    ) -> Result<&'a [u8], ()> {
        if payload.len() < AES128_TAG_LEN {
            return Err(());
        }
        let mut nonce = [0; AES128_IV_LEN];
        nonce[4..].copy_from_slice(&packet_number.to_be_bytes());
        for (nonce, inp) in nonce.iter_mut().zip(self.iv.iter()) {
            *nonce ^= inp;
        }
        let tag_pos = payload.len() - AES128_TAG_LEN;
        let (buffer, tag) = payload.split_at_mut(tag_pos);
        self.key
            .decrypt_in_place_detached((&nonce).into(), header, buffer, (&*tag).into())
            .map_err(|_| ())?;
        Ok(&payload[..tag_pos])
    }
}

pub struct DirectionalKeys {
    pub header: HeaderProtectionKey,
    pub packet: PacketKey,
}

impl DirectionalKeys {
    fn new(secret: &[u8], version: u32) -> Self {
        Self {
            header: HeaderProtectionKey::new(secret, version),
            packet: PacketKey::new(secret, version),
        }
    }
}

pub struct QuicKeys {
    pub local: DirectionalKeys,
    pub remote: DirectionalKeys,
}

fn hkdf_expand_label(hk: &Hkdf<Sha256>, label: &[u8], okm: &mut [u8], olen: u16) {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let output_len = u16::to_be_bytes(olen);
    let label_len = u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8);
    let context_len = u8::to_be_bytes(0);

    let info = &[
        &output_len[..],
        &label_len[..],
        LABEL_PREFIX,
        label,
        &context_len[..],
    ];

    hk.expand_multi_info(info, okm).unwrap();
}

pub fn quic_keys_initial(version: u32, client_dst_connection_id: &[u8]) -> Option<QuicKeys> {
    let salt = match version {
        0x51303530 => &[
            0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94, 0x5C, 0xFC, 0xDB, 0xD3,
            0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45,
        ],
        0xff00_001d..=0xff00_0020 => &[
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#section-5.2
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
            0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
        ],
        0xfaceb002 | 0xff00_0017..=0xff00_001c => &[
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-23#section-5.2
            0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4,
            0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
        ],
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => &[
            // https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ],
        0x6b3343cf => &[
            // https://www.rfc-editor.org/rfc/rfc9369.html#section-3.3.1
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
            0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ],
        _ => {
            return None;
        }
    };
    let hk = Hkdf::<Sha256>::new(Some(salt), client_dst_connection_id);
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(&hk, b"client in", &mut client_secret, 32);
    let mut server_secret = [0u8; 32];
    hkdf_expand_label(&hk, b"server in", &mut server_secret, 32);

    return Some(QuicKeys {
        local: DirectionalKeys::new(&server_secret, version),
        remote: DirectionalKeys::new(&client_secret, version),
    });
}

pub(super) fn decrypt_initial<'a>(
    keys: &QuicKeys, to_server: bool, header: &QuicHeader, framebuf: &'a [u8], buf: &'a [u8],
    hlen: usize, output: &'a mut Vec<u8>,
) -> Result<usize, ()> {
    let hkey = if to_server {
        &keys.remote.header
    } else {
        &keys.local.header
    };
    if framebuf.len() < PKT_NUM_BUF_MAX_LEN + AES128_KEY_LEN {
        return Err(());
    }
    let h2len = hlen + usize::from(header.length);
    let mut h2 = Vec::with_capacity(h2len);
    h2.extend_from_slice(&buf[..h2len]);
    let mut h20 = h2[0];
    let mut pktnum_buf = Vec::with_capacity(PKT_NUM_BUF_MAX_LEN);
    pktnum_buf.extend_from_slice(&h2[hlen..hlen + PKT_NUM_BUF_MAX_LEN]);
    let r1 = hkey.decrypt_in_place(
        &h2[hlen + PKT_NUM_BUF_MAX_LEN..hlen + PKT_NUM_BUF_MAX_LEN + AES128_KEY_LEN],
        &mut h20,
        &mut pktnum_buf,
    );
    if r1.is_err() {
        return Err(());
    }
    // mutate one at a time
    h2[0] = h20;
    let _ = &h2[hlen..hlen + 1 + ((h20 & 3) as usize)]
        .copy_from_slice(&pktnum_buf[..1 + ((h20 & 3) as usize)]);
    let pkt_num = quic_pkt_num(&h2[hlen..hlen + 1 + ((h20 & 3) as usize)]);
    if framebuf.len() < 1 + ((h20 & 3) as usize) {
        return Err(());
    }
    output.extend_from_slice(&framebuf[1 + ((h20 & 3) as usize)..]);
    let pkey = if to_server {
        &keys.remote.packet
    } else {
        &keys.local.packet
    };
    let r = pkey.decrypt_in_place(pkt_num, &h2[..hlen + 1 + ((h20 & 3) as usize)], output);
    if let Ok(r2) = r {
        return Ok(r2.len());
    }
    Err(())
}

/// Verify the Retry pseudo-packet, including the original client DCID.
pub(super) fn verify_retry(version: u32, odcid: &[u8], packet: &[u8]) -> bool {
    let (key, nonce) = match version {
        1 | 0xff00_0021..=0xff00_0022 => (
            RETRY_KEY_V1,
            [
                0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
            ],
        ),
        0x6b3343cf => (
            [
                0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c,
                0xcc, 0x92,
            ],
            [
                0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
            ],
        ),
        // draft-ietf-quic-tls-27 and -28, section 5.8.
        0xff00_001b..=0xff00_001c => (
            [
                0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8, 0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d,
                0x44, 0x30,
            ],
            [
                0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75,
            ],
        ),
        0xff00_001d..=0xff00_0020 => (
            [
                0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9,
                0x6b, 0xe1,
            ],
            [
                0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
            ],
        ),
        _ => return false,
    };
    if packet.len() < AES128_TAG_LEN || odcid.len() > 20 {
        return false;
    }
    let tag_pos = packet.len() - AES128_TAG_LEN;
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + tag_pos);
    pseudo.push(odcid.len() as u8);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(&packet[..tag_pos]);
    Aes128Gcm::new((&key).into())
        .decrypt_in_place_detached((&nonce).into(), &pseudo, &mut [], packet[tag_pos..].into())
        .is_ok()
}

#[cfg(test)]
pub(super) mod test_packets {
    use super::*;

    pub fn varint(value: usize) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else {
            ((value as u16) | 0x4000).to_be_bytes().to_vec()
        }
    }

    pub fn initial(
        version: u32, key_dcid: &[u8], dcid: &[u8], scid: &[u8], number: u32, client: bool,
        offset: usize, data: &[u8],
    ) -> Vec<u8> {
        initial_with_token(
            version,
            key_dcid,
            dcid,
            scid,
            number,
            client,
            offset,
            data,
            &[],
        )
    }

    pub fn initial_with_token(
        version: u32, key_dcid: &[u8], dcid: &[u8], scid: &[u8], number: u32, client: bool,
        offset: usize, data: &[u8], token: &[u8],
    ) -> Vec<u8> {
        let keys = quic_keys_initial(version, key_dcid).unwrap();
        let keys = if client { keys.remote } else { keys.local };
        let mut plain = vec![6];
        plain.extend(varint(offset));
        plain.extend(varint(data.len()));
        plain.extend_from_slice(data);
        plain.resize(1160.max(plain.len()), 0);
        let mut packet = vec![if version == 0x6b3343cf { 0xd3 } else { 0xc3 }];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);
        packet.extend(varint(token.len()));
        packet.extend_from_slice(token);
        packet.extend(varint(4 + plain.len() + 16));
        let pn_offset = packet.len();
        packet.extend_from_slice(&number.to_be_bytes());
        let mut nonce = keys.packet.iv;
        for (dst, src) in nonce[8..].iter_mut().zip(number.to_be_bytes()) {
            *dst ^= src;
        }
        let tag = keys
            .packet
            .key
            .encrypt_in_place_detached((&nonce).into(), &packet, &mut plain)
            .unwrap();
        packet.extend(plain);
        packet.extend_from_slice(&tag);
        let mut mask: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        keys.header.0.encrypt_block((&mut mask).into());
        packet[0] ^= mask[0] & 15;
        for i in 0..4 {
            packet[pn_offset + i] ^= mask[i + 1];
        }
        packet
    }

    pub fn retry(dcid: &[u8], scid: &[u8], odcid: &[u8]) -> Vec<u8> {
        retry_with_version(1, dcid, scid, odcid)
    }

    pub fn retry_with_version(version: u32, dcid: &[u8], scid: &[u8], odcid: &[u8]) -> Vec<u8> {
        let mut p = vec![0xf0];
        p.extend_from_slice(&version.to_be_bytes());
        p.push(dcid.len() as u8);
        p.extend_from_slice(dcid);
        p.push(scid.len() as u8);
        p.extend_from_slice(scid);
        p.extend_from_slice(b"retry-token");
        let mut pseudo = vec![odcid.len() as u8];
        pseudo.extend_from_slice(odcid);
        pseudo.extend_from_slice(&p);
        let (key, nonce) = match version {
            1 => (
                "be0c690b9f66575a1d766b54e368c84e",
                "461599d35d632bf2239825bb",
            ),
            0xff00_001b | 0xff00_001c => (
                "4d32ecdb2a2133c841e4043df27d4430",
                "4d1611d05513a552c587d575",
            ),
            _ => panic!("unsupported Retry test version"),
        };
        let key = hex::decode(key).unwrap();
        let nonce = hex::decode(nonce).unwrap();
        let tag = Aes128Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt_in_place_detached(nonce.as_slice().into(), &pseudo, &mut [])
            .unwrap();
        p.extend_from_slice(&tag);
        p
    }
}

#[cfg(test)]
mod retry_vectors {
    use super::verify_retry;

    #[test]
    fn rfc9001_and_rfc9369_retry_vectors() {
        let odcid = hex::decode("8394c8f03e515708").unwrap();
        for (version, text) in [
            (
                1,
                "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
            ),
            (
                0x6b3343cf,
                "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6",
            ),
        ] {
            let packet = hex::decode(text).unwrap();
            assert!(verify_retry(version, &odcid, &packet));
            assert!(!verify_retry(version, &[0; 8], &packet));
        }
    }
}
