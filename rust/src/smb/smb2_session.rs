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

use crate::smb::smb2_records::*;
use crate::smb::smb::*;
//use smb::events::*;
use crate::smb::auth::*;

pub fn smb2_session_setup_request(state: &mut SMBState, r: &Smb2Record)
{
    SCLogDebug!("SMB2_COMMAND_SESSION_SETUP: r.data.len() {}", r.data.len());
    match parse_smb2_request_session_setup(r.data) {
        Ok((_, setup)) => {
            let hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER);
            let tx = state.new_sessionsetup_tx(hdr);
            tx.vercmd.set_smb2_cmd(r.command);

            if let Some(SMBTransactionTypeData::SESSIONSETUP(ref mut td)) = tx.type_data {
                if let Some(s) = parse_secblob(setup.data) {
                    td.ntlmssp = s.ntlmssp;
                    td.krb_ticket = s.krb;
                }
            }
        },
            _ => {
//                events.push(SMBEvent::MalformedData);
        },
    }
}

fn smb2_session_setup_update_tx(tx: &mut SMBTransaction, r: &Smb2Record)
{
    tx.hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER); // to overwrite ssn_id 0
    tx.set_status(r.nt_status, false);
    tx.response_done = true;
}

pub fn smb2_session_setup_response(state: &mut SMBState, r: &Smb2Record)
{
    // try exact match with session id already set (e.g. NTLMSSP AUTH phase)
    let found = r.session_id != 0 && match state.get_sessionsetup_tx(
                SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER))
    {
        Some(tx) => {
            smb2_session_setup_update_tx(tx, r);
            SCLogDebug!("smb2_session_setup_response: tx {:?}", tx);
            true
        },
        None => { false },
    };
    // otherwise try match with ssn id 0 (e.g. NTLMSSP_NEGOTIATE)
    if !found {
        match state.get_sessionsetup_tx(
                SMBCommonHdr::new(SMBHDR_TYPE_HEADER, 0, 0, r.message_id))
        {
            Some(tx) => {
                smb2_session_setup_update_tx(tx, r);
                SCLogDebug!("smb2_session_setup_response: tx {:?}", tx);
            },
            None => {
                SCLogDebug!("smb2_session_setup_response: tx not found for {:?}", r);
            },
        }
    }
}
