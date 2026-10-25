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
    crypto::{decrypt_initial, quic_keys_initial, verify_retry, QuicKeys},
    frames::Frame,
    parser::{QuicData, QuicHeader},
    quic::QuicEvent,
    reassembly::CryptoReassembly,
};
use std::time::Duration;

/// A connection is local to its UDP flow; CID migration across flows is not tracked.
pub(super) struct QuicConnection {
    pub version: u32,
    pub client_scid: Vec<u8>,
    pub original_dcid: Vec<u8>,
    initial_dcid: Vec<u8>,
    server_scid: Option<Vec<u8>>,
    keys: Option<QuicKeys>,
    crypto: [CryptoReassembly; 2],
    hello: [bool; 2],
    has_retried: bool,
    pub last_seen: Duration,
}

impl QuicConnection {
    pub fn new(header: &QuicHeader, now: Duration) -> Self {
        Self {
            version: header.version.into(),
            client_scid: header.scid.clone(),
            original_dcid: header.dcid.clone(),
            initial_dcid: header.dcid.clone(),
            server_scid: None,
            keys: quic_keys_initial(header.version.into(), &header.dcid),
            crypto: Default::default(),
            hello: [false; 2],
            has_retried: false,
            last_seen: now,
        }
    }

    pub fn supported(&self, header: &QuicHeader) -> bool {
        self.keys.is_some() || header.version.is_gquic() || !header.flags.is_long
    }

    pub fn matches(&self, header: &QuicHeader, to_server: bool) -> bool {
        if self.version != u32::from(header.version) {
            return false;
        }
        if self.keys.is_none() {
            // Legacy gQUIC has no Initial key derivation and may omit SCIDs.
            return self.initial_dcid == header.dcid
                || (!to_server && self.initial_dcid == header.scid);
        }
        if to_server {
            self.client_scid == header.scid
                && (self.initial_dcid == header.dcid
                    || self.original_dcid == header.dcid
                    || self.server_scid.as_deref() == Some(header.dcid.as_slice()))
        } else {
            self.client_scid == header.dcid
                && self
                    .server_scid
                    .as_deref()
                    .is_none_or(|scid| scid == header.scid)
        }
    }

    pub fn hello_done(&self, to_server: bool) -> bool {
        self.hello[usize::from(!to_server)]
    }

    pub fn complete(&self) -> bool {
        self.hello[0] && self.hello[1]
    }

    pub fn decode(
        &self, header: &QuicHeader, to_server: bool, packet: &[u8], payload: &[u8], hlen: usize,
    ) -> Result<QuicData, QuicEvent> {
        let mut output = Vec::new();
        let data = if let Some(keys) = &self.keys {
            let len = decrypt_initial(keys, to_server, header, payload, packet, hlen, &mut output)
                .map_err(|_| QuicEvent::FailedDecrypt)?;
            output.truncate(len);
            output.as_slice()
        } else {
            payload
        };
        QuicData::from_bytes(data).map_err(|_| QuicEvent::ErrorOnData)
    }

    pub fn ingest(
        &mut self, data: &mut QuicData, header: &QuicHeader, to_server: bool, now: Duration,
    ) -> Result<(), QuicEvent> {
        let dir = usize::from(!to_server);
        if !data.frames.iter().any(|f| matches!(f, Frame::Crypto(_))) {
            for frame in &data.frames {
                if let Frame::CryptoFrag(frag) = frame {
                    self.crypto[dir].insert(frag.offset, &frag.data)?;
                }
            }
            if let Some(hello) = self.crypto[dir].hello()? {
                data.frames.push(hello);
            }
        }
        if data.frames.iter().any(|f| matches!(f, Frame::Crypto(_))) {
            self.hello[dir] = true;
            self.crypto[dir].clear();
        }
        if !to_server && self.keys.is_some() {
            self.server_scid = Some(header.scid.clone());
        }
        self.last_seen = self.last_seen.max(now);
        Ok(())
    }

    pub fn accepts_retry(&self, header: &QuicHeader, packet: &[u8]) -> bool {
        self.version == u32::from(header.version)
            && header.dcid == self.client_scid
            && !self.has_retried
            && self.server_scid.is_none()
            && header.scid != self.initial_dcid
            && verify_retry(self.version, &self.original_dcid, packet)
    }

    pub fn retry(&mut self, header: &QuicHeader, now: Duration) {
        self.initial_dcid.clone_from(&header.scid);
        self.keys = quic_keys_initial(self.version, &self.initial_dcid);
        self.crypto = Default::default();
        self.hello = [false; 2];
        self.has_retried = true;
        self.last_seen = self.last_seen.max(now);
    }
}
