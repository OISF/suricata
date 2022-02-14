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

use ring::{aead, hkdf};

struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Self(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

struct Iv([u8; ring::aead::NONCE_LEN]);

fn hkdf_expand<T, L>(secret: &hkdf::Prk, key_type: L, label: &[u8], context: &[u8]) -> T
where
    T: for<'a> From<hkdf::Okm<'a, L>>,
    L: hkdf::KeyType,
{
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let output_len = u16::to_be_bytes(key_type.len() as u16);
    let label_len = u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8);
    let context_len = u8::to_be_bytes(context.len() as u8);

    let info = &[
        &output_len[..],
        &label_len[..],
        LABEL_PREFIX,
        label,
        &context_len[..],
        context,
    ];
    let okm = secret.expand(info, key_type).unwrap();

    okm.into()
}

/// Compute the nonce to use for encrypting or decrypting `packet_number`
fn nonce_for(packet_number: u64, iv: &Iv) -> ring::aead::Nonce {
    let mut out = [0; aead::NONCE_LEN];
    out[4..].copy_from_slice(&packet_number.to_be_bytes());
    for (out, inp) in out.iter_mut().zip(iv.0.iter()) {
        *out ^= inp;
    }
    aead::Nonce::assume_unique_for_key(out)
}

pub struct HeaderProtectionKey(aead::quic::HeaderProtectionKey);

impl HeaderProtectionKey {
    fn new(secret: &hkdf::Prk) -> Self {
        Self(hkdf_expand(secret, &aead::quic::AES_128, b"quic hp", &[]))
    }

    pub fn decrypt_in_place(
        &self, sample: &[u8], first: &mut u8, packet_number: &mut [u8],
    ) -> Result<(), ()> {
        let mask = self.0.new_mask(sample).map_err(|_| ())?;

        let (first_mask, pn_mask) = mask.split_first().unwrap();
        if packet_number.len() > pn_mask.len() {
            return Err(());
        }

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

    pub fn sample_len(&self) -> usize {
        self.0.algorithm().sample_len()
    }
}

pub struct PacketKey {
    key: aead::LessSafeKey,
    iv: Iv,
}

impl PacketKey {
    fn new(secret: &hkdf::Prk) -> Self {
        Self {
            key: aead::LessSafeKey::new(hkdf_expand(
                secret,
                &ring::aead::AES_128_GCM,
                b"quic key",
                &[],
            )),
            iv: hkdf_expand(secret, IvLen, b"quic iv", &[]),
        }
    }

    pub fn decrypt_in_place<'a>(
        &self, packet_number: u64, header: &[u8], payload: &'a mut [u8],
    ) -> Result<&'a [u8], ()> {
        let payload_len = payload.len();
        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet_number, &self.iv);
        self.key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| ())?;

        let plain_len = payload_len - self.key.algorithm().tag_len();
        Ok(&payload[..plain_len])
    }
}

pub struct DirectionalKeys {
    pub header: HeaderProtectionKey,
    pub packet: PacketKey,
}

impl DirectionalKeys {
    fn new(secret: &hkdf::Prk) -> Self {
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

pub fn quic_keys_initial(version: u32, client_dst_connection_id: &[u8]) -> Option<QuicKeys> {
    const CLIENT_LABEL: &[u8] = b"client in";
    const SERVER_LABEL: &[u8] = b"server in";
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
    let hs_secret = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(client_dst_connection_id);
    let client_secret: hkdf::Prk = hkdf_expand(&hs_secret, hkdf::HKDF_SHA256, CLIENT_LABEL, &[]);
    let server_secret: hkdf::Prk = hkdf_expand(&hs_secret, hkdf::HKDF_SHA256, SERVER_LABEL, &[]);
    return Some(QuicKeys {
        local: DirectionalKeys::new(&server_secret),
        remote: DirectionalKeys::new(&client_secret),
    });
}
