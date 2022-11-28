/* Copyright (C) 2018 Open Information Security Foundation
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

use crate::smb::smb_records::*;
use crate::smb::smb1_records::*;
use crate::smb::smb::*;
use crate::smb::events::*;
use crate::smb::auth::*;

#[derive(Debug)]
pub struct SessionSetupRequest {
    pub native_os: Vec<u8>,
    pub native_lm: Vec<u8>,
    pub primary_domain: Vec<u8>,
}

#[derive(Debug)]
pub struct SessionSetupResponse {
    pub native_os: Vec<u8>,
    pub native_lm: Vec<u8>,
}

pub fn smb1_session_setup_request_host_info(r: &SmbRecord, blob: &[u8]) -> SessionSetupRequest
{
    if blob.len() > 1 && r.has_unicode_support() {
        let offset = r.data.len() - blob.len();
        let blob = if offset % 2 == 1 { &blob[1..] } else { blob };
        let (native_os, native_lm, primary_domain) = match smb_get_unicode_string(blob) {
            Ok((rem, n1)) => {
                match smb_get_unicode_string(rem) {
                    Ok((rem, n2)) => {
                        match smb_get_unicode_string(rem) {
                            Ok((_, n3)) => { (n1, n2, n3) },
                                _ => { (n1, n2, Vec::new()) },
                        }
                    },
                        _ => { (n1, Vec::new(), Vec::new()) },
                }
            },
                _ => { (Vec::new(), Vec::new(), Vec::new()) },
        };

        SCLogDebug!("name1 {:?} name2 {:?} name3 {:?}", native_os,native_lm,primary_domain);
        SessionSetupRequest {
            native_os,
            native_lm,
            primary_domain,
        }
    } else {
        let (native_os, native_lm, primary_domain) = match smb_get_ascii_string(blob) {
            Ok((rem, n1)) => {
                match smb_get_ascii_string(rem) {
                    Ok((rem, n2)) => {
                        match smb_get_ascii_string(rem) {
                            Ok((_, n3)) => { (n1, n2, n3) },
                                _ => { (n1, n2, Vec::new()) },
                        }
                    },
                        _ => { (n1, Vec::new(), Vec::new()) },
                }
            },
                _ => { (Vec::new(), Vec::new(), Vec::new()) },
        };

        SCLogDebug!("session_setup_request_host_info: not unicode");
        SessionSetupRequest {
            native_os,
            native_lm,
            primary_domain,
        }
    }
}

pub fn smb1_session_setup_response_host_info(r: &SmbRecord, blob: &[u8]) -> SessionSetupResponse
{
    if blob.len() > 1 && r.has_unicode_support() {
        let offset = r.data.len() - blob.len();
        let blob = if offset % 2 == 1 { &blob[1..] } else { blob };
        let (native_os, native_lm) = match smb_get_unicode_string(blob) {
            Ok((rem, n1)) => {
                match smb_get_unicode_string(rem) {
                    Ok((_, n2)) => (n1, n2),
                    _ => { (n1, Vec::new()) },
                }
            },
            _ => { (Vec::new(), Vec::new()) },
        };

        SCLogDebug!("name1 {:?} name2 {:?}", native_os,native_lm);
        SessionSetupResponse {
            native_os,
            native_lm,
        }
    } else {
        SCLogDebug!("session_setup_response_host_info: not unicode");
        let (native_os, native_lm) = match smb_get_ascii_string(blob) {
            Ok((rem, n1)) => {
                match smb_get_ascii_string(rem) {
                    Ok((_, n2)) => (n1, n2),
                    _ => { (n1, Vec::new()) },
                }
            },
            _ => { (Vec::new(), Vec::new()) },
        };
        SessionSetupResponse {
            native_os,
            native_lm,
        }
    }
}

pub fn smb1_session_setup_request(state: &mut SMBState, r: &SmbRecord, andx_offset: usize)
{
    SCLogDebug!("SMB1_COMMAND_SESSION_SETUP_ANDX user_id {}", r.user_id);
    #[allow(clippy::single_match)]
    match parse_smb_setup_andx_record(&r.data[andx_offset-SMB1_HEADER_SIZE..]) {
        Ok((rem, setup)) => {
            let hdr = SMBCommonHdr::new(SMBHDR_TYPE_HEADER,
                    r.ssn_id as u64, 0, r.multiplex_id as u64);
            let tx = state.new_sessionsetup_tx(hdr);
            tx.vercmd.set_smb1_cmd(r.command);

            if let Some(SMBTransactionTypeData::SESSIONSETUP(ref mut td)) = tx.type_data {
                if let Some(s) = parse_secblob(setup.sec_blob) {
                    td.ntlmssp = s.ntlmssp;
                    td.krb_ticket = s.krb;
                }
                td.request_host = Some(smb1_session_setup_request_host_info(r, rem));
            }
        },
        _ => {
            // events.push(SMBEvent::MalformedData);
        },
    }
}

fn smb1_session_setup_update_tx(tx: &mut SMBTransaction, r: &SmbRecord, andx_offset: usize)
{
    match parse_smb_response_setup_andx_record(&r.data[andx_offset-SMB1_HEADER_SIZE..]) {
        Ok((rem, _setup)) => {
            if let Some(SMBTransactionTypeData::SESSIONSETUP(ref mut td)) = tx.type_data {
                td.response_host = Some(smb1_session_setup_response_host_info(r, rem));
            }
        },
        _ => {
            tx.set_event(SMBEvent::MalformedData);
        },
    }
    // update tx even if we can't parse the response
    tx.hdr = SMBCommonHdr::from1(r, SMBHDR_TYPE_HEADER); // to overwrite ssn_id 0
    tx.set_status(r.nt_status, r.is_dos_error);
    tx.response_done = true;
}

pub fn smb1_session_setup_response(state: &mut SMBState, r: &SmbRecord, andx_offset: usize)
{
    // try exact match with session id already set (e.g. NTLMSSP AUTH phase)
    let found = r.ssn_id != 0 && match state.get_sessionsetup_tx(
                SMBCommonHdr::new(SMBHDR_TYPE_HEADER,
                    r.ssn_id as u64, 0, r.multiplex_id as u64))
    {
        Some(tx) => {
            smb1_session_setup_update_tx(tx, r, andx_offset);
            SCLogDebug!("smb1_session_setup_response: tx {:?}", tx);
            true
        },
        None => { false },
    };
    // otherwise try match with ssn id 0 (e.g. NTLMSSP_NEGOTIATE)
    if !found {
        match state.get_sessionsetup_tx(
                SMBCommonHdr::new(SMBHDR_TYPE_HEADER, 0, 0, r.multiplex_id as u64))
        {
            Some(tx) => {
                smb1_session_setup_update_tx(tx, r, andx_offset);
                SCLogDebug!("smb1_session_setup_response: tx {:?}", tx);
            },
            None => {
                SCLogDebug!("smb1_session_setup_response: tx not found for {:?}", r);
            },
        }
    }
}
