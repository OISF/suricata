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

use super::{
    frames::{parse_quic_handshake, Frame},
    quic::{QuicEvent, QUIC_MAX_CRYPTO_FRAG_LEN},
};
use tls_parser::parse_tls_message_handshake;

/// Initial CRYPTO bytes for one direction of one connection.
#[derive(Default)]
pub(super) struct CryptoReassembly {
    data: Vec<u8>,
    present: Vec<bool>,
    contiguous: usize,
}

impl CryptoReassembly {
    pub fn insert(&mut self, offset: u64, data: &[u8]) -> Result<(), QuicEvent> {
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|end| *end < QUIC_MAX_CRYPTO_FRAG_LEN)
            .ok_or(QuicEvent::CryptoFragTooLong)? as usize;
        let offset = offset as usize;
        // Reject conflicting retransmissions before modifying any buffered byte.
        for (i, byte) in data.iter().enumerate() {
            let i = offset + i;
            if i < self.present.len() && self.present[i] && self.data[i] != *byte {
                return Err(QuicEvent::ErrorOnData);
            }
        }
        if end > self.data.len() {
            self.data.resize(end, 0);
            self.present.resize(end, false);
        }
        self.data[offset..end].copy_from_slice(data);
        self.present[offset..end].fill(true);
        while self.contiguous < self.present.len() && self.present[self.contiguous] {
            self.contiguous += 1;
        }
        Ok(())
    }

    pub fn hello(&self) -> Result<Option<Frame>, QuicEvent> {
        if self.contiguous < 4 {
            return Ok(None);
        }
        let length = 4
            + ((self.data[1] as usize) << 16)
            + ((self.data[2] as usize) << 8)
            + self.data[3] as usize;
        if length as u64 >= QUIC_MAX_CRYPTO_FRAG_LEN {
            return Err(QuicEvent::CryptoFragTooLong);
        }
        if self.contiguous < length {
            return Ok(None);
        }
        let (_, msg) = parse_tls_message_handshake(&self.data[..length])
            .map_err(|_| QuicEvent::ErrorOnData)?;
        parse_quic_handshake(msg)
            .map(Some)
            .ok_or(QuicEvent::ErrorOnData)
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_fragments_do_not_fill_a_gap() {
        let mut r = CryptoReassembly::default();
        r.insert(0, &[1, 0, 0, 8]).unwrap();
        r.insert(8, &[1, 2, 3, 4]).unwrap();
        r.insert(8, &[1, 2, 3, 4]).unwrap();
        assert_eq!(r.contiguous, 4);
        assert!(r.hello().unwrap().is_none());
        r.insert(4, &[5, 6, 7, 8]).unwrap();
        assert_eq!(r.contiguous, 12);
    }

    #[test]
    fn conflicting_overlap_is_rejected() {
        let mut r = CryptoReassembly::default();
        r.insert(2, &[1, 2, 3]).unwrap();
        assert!(matches!(r.insert(3, &[9]), Err(QuicEvent::ErrorOnData)));
    }

    #[test]
    fn offsets_are_bounded_before_allocating() {
        let mut r = CryptoReassembly::default();
        assert!(matches!(
            r.insert(u64::MAX, &[1]),
            Err(QuicEvent::CryptoFragTooLong)
        ));
        assert!(r.data.is_empty());
    }
}
