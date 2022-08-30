/* Copyright (C) 2021-2022 Open Information Security Foundation
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

use aes::cipher::generic_array::GenericArray;
use aes::Aes128;
use aes::BlockCipher;
use aes::NewBlockCipher;
use aes_gcm::AeadInPlace;
use aes_gcm::Aes128Gcm;
use aes_gcm::NewAead;
use hkdf::Hkdf;
use sha2::Sha256;

pub const AES128_KEY_LEN: usize = 16;
pub const AES128_TAG_LEN: usize = 16;
pub const AES128_IV_LEN: usize = 12;

pub struct HeaderProtectionKey(Aes128);

impl HeaderProtectionKey {
    fn new(secret: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(secret).unwrap();
        let mut secret = [0u8; AES128_KEY_LEN];
        hkdf_expand_label(&hk, b"quic hp", &mut secret, AES128_KEY_LEN as u16);
        return Self(Aes128::new(GenericArray::from_slice(&secret)));
    }

    pub fn decrypt_in_place(
        &self, sample: &[u8], first: &mut u8, packet_number: &mut [u8],
    ) -> Result<(), ()> {
        let mut mask = GenericArray::clone_from_slice(sample);
        self.0.encrypt_block(&mut mask);

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
    fn new(secret: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(secret).unwrap();
        let mut secret = [0u8; AES128_KEY_LEN];
        hkdf_expand_label(&hk, b"quic key", &mut secret, AES128_KEY_LEN as u16);
        let key = Aes128Gcm::new(GenericArray::from_slice(&secret));

        let mut r = PacketKey {
            key: key,
            iv: [0u8; AES128_IV_LEN],
        };
        hkdf_expand_label(&hk, b"quic iv", &mut r.iv, AES128_IV_LEN as u16);
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
        let taga = GenericArray::from_slice(tag);
        self.key
            .decrypt_in_place_detached(GenericArray::from_slice(&nonce), header, buffer, &taga)
            .map_err(|_| ())?;
        Ok(&payload[..tag_pos])
    }
}

pub struct DirectionalKeys {
    pub header: HeaderProtectionKey,
    pub packet: PacketKey,
}

impl DirectionalKeys {
    fn new(secret: &[u8]) -> Self {
        Self {
            header: HeaderProtectionKey::new(secret),
            packet: PacketKey::new(secret),
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
        local: DirectionalKeys::new(&server_secret),
        remote: DirectionalKeys::new(&client_secret),
    });
}
