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

use crate::smb::smb::*;
use crate::smb::smb2::*;
use crate::smb::smb2_records::*;
use crate::smb::dcerpc::*;
use crate::smb::events::*;
#[cfg(feature = "debug")]
use crate::smb::funcs::*;
use crate::smb::smb_status::*;

#[derive(Debug)]
pub struct SMBTransactionIoctl {
    pub func: u32,
}

impl SMBTransactionIoctl {
    pub fn new(func: u32) -> Self {
        return Self {
            func,
        };
    }
}

impl SMBState {
    pub fn new_ioctl_tx(&mut self, hdr: SMBCommonHdr, func: u32)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();
        tx.hdr = hdr;
        tx.type_data = Some(SMBTransactionTypeData::IOCTL(
                    SMBTransactionIoctl::new(func)));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        SCLogDebug!("SMB: TX IOCTL created: ID {} FUNC {:08x}: {}",
                tx.id, func, &fsctl_func_to_string(func));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }
}

// IOCTL responses ASYNC don't set the tree id
pub fn smb2_ioctl_request_record<'b>(state: &mut SMBState, r: &Smb2Record<'b>)
{
    let hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER);
    match parse_smb2_request_ioctl(r.data) {
        Ok((_, rd)) => {
            SCLogDebug!("IOCTL request data: {:?}", rd);
            let is_dcerpc = if rd.is_pipe {
                state.get_service_for_guid(rd.guid).1
            } else {
                false
            };
            if is_dcerpc {
                SCLogDebug!("IOCTL request data is_pipe. Calling smb_write_dcerpc_record");
                let vercmd = SMBVerCmdStat::new2(SMB2_COMMAND_IOCTL);
                smb_write_dcerpc_record(state, vercmd, hdr, rd.data);
            } else {
                SCLogDebug!("IOCTL {:08x} {}", rd.function, &fsctl_func_to_string(rd.function));
                let tx = state.new_ioctl_tx(hdr, rd.function);
                tx.vercmd.set_smb2_cmd(SMB2_COMMAND_IOCTL);
            }
        },
        _ => {
            let tx = state.new_generic_tx(2, r.command, hdr);
            tx.set_event(SMBEvent::MalformedData);
        },
    };
}

// IOCTL responses ASYNC don't set the tree id
pub fn smb2_ioctl_response_record<'b>(state: &mut SMBState, r: &Smb2Record<'b>)
{
    let hdr = SMBCommonHdr::from2(r, SMBHDR_TYPE_HEADER);
    match parse_smb2_response_ioctl(r.data) {
        Ok((_, rd)) => {
            SCLogDebug!("IOCTL response data: {:?}", rd);

            let is_dcerpc = if rd.is_pipe {
                state.get_service_for_guid(rd.guid).1
            } else {
                false
            };
            if is_dcerpc {
                SCLogDebug!("IOCTL response data is_pipe. Calling smb_read_dcerpc_record");
                let vercmd = SMBVerCmdStat::new2_with_ntstatus(SMB2_COMMAND_IOCTL, r.nt_status);
                SCLogDebug!("TODO passing empty GUID");
                smb_read_dcerpc_record(state, vercmd, hdr, &[],rd.data);
            } else {
                SCLogDebug!("SMB2_COMMAND_IOCTL/SMB_NTSTATUS_PENDING looking for {:?}", hdr);
                if let Some(tx) = state.get_generic_tx(2, SMB2_COMMAND_IOCTL, &hdr) {
                    tx.set_status(r.nt_status, false);
                    if r.nt_status != SMB_NTSTATUS_PENDING {
                        tx.response_done = true;
                    }
                }
            }
        },
        _ => {
            SCLogDebug!("SMB2_COMMAND_IOCTL/SMB_NTSTATUS_PENDING looking for {:?}", hdr);
            if let Some(tx) = state.get_generic_tx(2, SMB2_COMMAND_IOCTL, &hdr) {
                SCLogDebug!("updated status of tx {}", tx.id);
                tx.set_status(r.nt_status, false);
                if r.nt_status != SMB_NTSTATUS_PENDING {
                    tx.response_done = true;
                }
                
                // parsing failed for 'SUCCESS' record, set event
                if r.nt_status == SMB_NTSTATUS_SUCCESS {
                    SCLogDebug!("parse fail {:?}", r);
                    tx.set_event(SMBEvent::MalformedData);
                }
            }
        },
    };
}
