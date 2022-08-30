/* Copyright (C) 2018-2022 Open Information Security Foundation
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

use crate::smb::smb::*;

#[derive(AppLayerEvent)]
pub enum SMBEvent {
    InternalError,
    MalformedData,
    RecordOverflow,
    MalformedNtlmsspRequest,
    MalformedNtlmsspResponse,
    DuplicateNegotiate,
    NegotiateMalformedDialects,
    FileOverlap,
    /// A request was seen in the to client direction.
    RequestToClient,
    /// A response was seen in the to server direction,
    ResponseToServer,

    /// Negotiated max sizes exceed our limit
    NegotiateMaxReadSizeTooLarge,
    NegotiateMaxWriteSizeTooLarge,

    /// READ request asking for more than `max_read_size`
    ReadRequestTooLarge,
    /// READ response bigger than `max_read_size`
    ReadResponseTooLarge,
    ReadQueueSizeExceeded,
    ReadQueueCntExceeded,
    /// WRITE request for more than `max_write_size`
    WriteRequestTooLarge,
    WriteQueueSizeExceeded,
    WriteQueueCntExceeded,
}

impl SMBTransaction {
    /// Set event.
    pub fn set_event(&mut self, e: SMBEvent) {
        self.tx_data.set_event(e as u8);
    }

    /// Set events from vector of events.
    pub fn set_events(&mut self, events: Vec<SMBEvent>) {
        for e in events {
            self.tx_data.set_event(e as u8);
        }
    }
}

impl SMBState {
    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: SMBEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let tx = &mut self.transactions[len - 1];
        tx.set_event(event);
    }
}
