/* Copyright (C) 2017-2022 Open Information Security Foundation
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

// written by Victor Julien

use crate::nfs::nfs::*;
use crate::nfs::types::*;
use crate::nfs::rpc_records::*;
use crate::nfs::nfs2_records::*;

use nom7::IResult;
use nom7::number::streaming::be_u32;

impl NFSState {
    /// complete request record
    pub fn process_request_record_v2<'b>(&mut self, r: &RpcPacket<'b>) {
        SCLogDebug!("NFSv2: REQUEST {} procedure {} ({}) blob size {}",
                r.hdr.xid, r.procedure, self.requestmap.len(), r.prog_data.len());

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);
        let aux_file_name = Vec::new();

        if r.procedure == NFSPROC3_LOOKUP {
            match parse_nfs2_request_lookup(r.prog_data) {
                Ok((_, ar)) => {
                    xidmap.file_handle = ar.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_READ {
            match parse_nfs2_request_read(r.prog_data) {
                Ok((_, read_record)) => {
                    xidmap.chunk_offset = read_record.offset as u64;
                    xidmap.file_handle = read_record.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        }

        if !(r.procedure == NFSPROC3_COMMIT || // commit handled separately
             r.procedure == NFSPROC3_WRITE  || // write handled in file tx
             r.procedure == NFSPROC3_READ)     // read handled in file tx at reply
        {
            let mut tx = self.new_tx();
            tx.xid = r.hdr.xid;
            tx.procedure = r.procedure;
            tx.request_done = true;
            tx.file_name = xidmap.file_name.to_vec();
            tx.file_handle = xidmap.file_handle.to_vec();
            tx.nfs_version = r.progver as u16;

            if r.procedure == NFSPROC3_RENAME {
                tx.type_data = Some(NFSTransactionTypeData::RENAME(aux_file_name));
            }

            tx.auth_type = r.creds_flavor;
            match r.creds {
                RpcRequestCreds::Unix(ref u) => {
                    tx.request_machine_name = u.machine_name_buf.to_vec();
                    tx.request_uid = u.uid;
                    tx.request_gid = u.gid;
                },
                _ => { },
            }
            SCLogDebug!("NFSv2: TX created: ID {} XID {} PROCEDURE {}",
                    tx.id, tx.xid, tx.procedure);
            self.transactions.push(tx);
        }

        SCLogDebug!("NFSv2: TS creating xidmap {}", r.hdr.xid);
        self.requestmap.insert(r.hdr.xid, xidmap);
    }

    pub fn process_reply_record_v2<'b>(&mut self, r: &RpcReplyPacket<'b>, xidmap: &NFSRequestXidMap) {
        let mut nfs_status = 0;
        let resp_handle = Vec::new();

        if xidmap.procedure == NFSPROC3_READ {
            match parse_nfs2_reply_read(r.prog_data) {
                Ok((_, ref reply)) => {
                    SCLogDebug!("NFSv2: READ reply record");
                    self.process_read_record(r, reply, Some(xidmap));
                    nfs_status = reply.status;
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            }
        } else {
            let stat : u32 = match be_u32(r.prog_data) as IResult<&[u8],_> {
                Ok((_, stat)) => stat,
                _ => 0
            };
            nfs_status = stat;
        }
        SCLogDebug!("NFSv2: REPLY {} to procedure {} blob size {}",
                r.hdr.xid, xidmap.procedure, r.prog_data.len());

        self.mark_response_tx_done(r.hdr.xid, r.reply_state, nfs_status, &resp_handle);
    }
}
