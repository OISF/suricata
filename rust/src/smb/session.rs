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

use crate::kerberos::*;
use crate::smb::smb::*;
use crate::smb::smb1_session::*;
use crate::smb::auth::*;

#[derive(Default, Debug)]
pub struct SMBTransactionSessionSetup {
    pub request_host: Option<SessionSetupRequest>,
    pub response_host: Option<SessionSetupResponse>,
    pub ntlmssp: Option<NtlmsspData>,
    pub krb_ticket: Option<Kerberos5Ticket>,
}

impl SMBTransactionSessionSetup {
    pub fn new() -> Self {
        return Default::default()
    }
}

impl SMBState {
    pub fn new_sessionsetup_tx(&mut self, hdr: SMBCommonHdr)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();

        tx.hdr = hdr;
        tx.type_data = Some(SMBTransactionTypeData::SESSIONSETUP(
                    SMBTransactionSessionSetup::new()));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        SCLogDebug!("SMB: TX SESSIONSETUP created: ID {}", tx.id);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    pub fn get_sessionsetup_tx(&mut self, hdr: SMBCommonHdr)
        -> Option<&mut SMBTransaction>
    {
        for tx in &mut self.transactions {
            let hit = tx.hdr.compare(&hdr) && match tx.type_data {
                Some(SMBTransactionTypeData::SESSIONSETUP(_)) => { true },
                _ => { false },
            };
            if hit {
                return Some(tx);
            }
        }
        return None;
    }
}
