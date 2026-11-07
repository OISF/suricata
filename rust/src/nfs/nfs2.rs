/* Copyright (C) 2017-2020 Open Information Security Foundation
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

use crate::flow::Flow;
use crate::nfs::nfs::*;
use crate::nfs::nfs2_records::*;
use crate::nfs::rpc_records::*;
use crate::nfs::types::*;

use nom7::number::streaming::be_u32;
use nom7::IResult;

impl NFSState {
    /// complete request record
    pub fn process_request_record_v2(&mut self, _flow: *mut Flow, r: &RpcPacket) {
        SCLogDebug!(
            "NFSv2: REQUEST {} procedure {} ({}) blob size {}",
            r.hdr.xid,
            r.procedure,
            self.requestmap.len(),
            r.prog_data.len()
        );

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);
        let mut aux_file_name = Vec::new();

        // v2 uses its own opcode space (RFC 1094): it must not be matched
        // against the NFSPROC3_* values (e.g. v2 LOOKUP is 4, v3 is 3;
        // v2 WRITE is 8, v3 is 7). Parse the record and wire the file
        // identity (name + handle) into the transaction, mirroring the v3
        // state machine.
        if r.procedure == NFSPROC2_GETATTR
            || r.procedure == NFSPROC2_SETATTR
            || r.procedure == NFSPROC2_READLINK
            || r.procedure == NFSPROC2_READDIR
            || r.procedure == NFSPROC2_STATFS
        {
            // handle-only ops (sattr/cookie fields after the handle are not
            // needed for the transaction's file identity).
            if let Ok((_, rd)) = parse_nfs2_request_handle_op(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if r.procedure == NFSPROC2_LOOKUP {
            if let Ok((_, rd)) = parse_nfs2_request_lookup(r.prog_data) {
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if r.procedure == NFSPROC2_CREATE
            || r.procedure == NFSPROC2_REMOVE
            || r.procedure == NFSPROC2_SYMLINK
            || r.procedure == NFSPROC2_MKDIR
            || r.procedure == NFSPROC2_RMDIR
        {
            // dir handle + name (CREATE/MKDIR/SYMLINK carry extra fields
            // after the name that are not needed here).
            if let Ok((_, rd)) = parse_nfs2_request_name_op(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if r.procedure == NFSPROC2_RENAME {
            if let Ok((_, rd)) = parse_nfs2_request_rename(r.prog_data) {
                xidmap.file_handle = rd.from_handle.value.to_vec();
                xidmap.file_name = rd.from_name_vec;
                aux_file_name = rd.to_name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if r.procedure == NFSPROC2_LINK {
            if let Ok((_, rd)) = parse_nfs2_request_link(r.prog_data) {
                xidmap.file_handle = rd.linkdir.value.to_vec();
                xidmap.file_name = rd.linkname_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if r.procedure == NFSPROC2_READ {
            if let Ok((_, rd)) = parse_nfs2_request_read(r.prog_data) {
                xidmap.chunk_offset = rd.offset as u64;
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        }

        // READ and WRITE are handled in the file tx (WRITE in the request,
        // READ at reply time); v2 has no COMMIT.
        // v2 WRITE stays a plain record: RFC 1094 has no COMMIT and no stable
        // flag, so a file transaction opened here would have no completion
        // signal, and the reconstruction split files at the 8192 byte record
        // limit. Only READ is tracked as a file.
        if r.procedure != NFSPROC2_READ {
            let mut tx = self.new_tx();
            tx.xid = r.hdr.xid;
            tx.procedure = r.procedure;
            tx.request_done = true;
            tx.file_name = xidmap.file_name.to_vec();
            tx.file_handle = xidmap.file_handle.to_vec();
            tx.nfs_version = r.progver as u16;

            if r.procedure == NFSPROC2_RENAME {
                tx.type_data = Some(NFSTransactionTypeData::RENAME(aux_file_name));
            }

            tx.auth_type = r.creds_flavor;
            #[allow(clippy::single_match)]
            match r.creds {
                RpcRequestCreds::Unix(ref u) => {
                    tx.request_machine_name = u.machine_name_buf.to_vec();
                    tx.request_uid = u.uid;
                    tx.request_gid = u.gid;
                }
                _ => {}
            }
            SCLogDebug!(
                "NFSv2: TX created: ID {} XID {} PROCEDURE {}",
                tx.id,
                tx.xid,
                tx.procedure
            );
            self.transactions.push(tx);
        }

        SCLogDebug!("NFSv2: TS creating xidmap {}", r.hdr.xid);
        self.requestmap.put(r.hdr.xid, xidmap);
    }

    pub fn process_reply_record_v2(
        &mut self, flow: *mut Flow, r: &RpcReplyPacket, xidmap: &NFSRequestXidMap,
    ) {
        let mut nfs_status = 0;
        // a reply shorter than a status word carries none: keep the tx
        // status unset rather than log a fake OK
        let mut nfs_status_set = false;
        let resp_handle = Vec::new();

        if xidmap.procedure == NFSPROC3_READ {
            match parse_nfs2_reply_read(r.prog_data) {
                Ok((_, ref reply)) => {
                    SCLogDebug!("NFSv2: READ reply record");
                    self.process_read_record(flow, r, reply, Some(xidmap), false);
                    nfs_status = reply.status;
                    nfs_status_set = true;
                }
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                }
            }
        } else {
            let stat: u32 = match be_u32(r.prog_data) as IResult<&[u8], _> {
                Ok((_, stat)) => stat,
                _ => 0,
            };
            // the status word is the reply's first 4 bytes
            nfs_status_set = r.prog_data.len() >= 4;
            nfs_status = stat;
        }
        SCLogDebug!(
            "NFSv2: REPLY {} to procedure {} blob size {}",
            r.hdr.xid,
            xidmap.procedure,
            r.prog_data.len()
        );

        let write_handle = if xidmap.procedure == NFSPROC2_WRITE {
            xidmap.file_handle.as_slice()
        } else {
            &[]
        };
        self.mark_response_tx_done(
            flow,
            r.hdr.xid,
            r.reply_state,
            nfs_status,
            nfs_status_set,
            &resp_handle,
            write_handle,
        );
    }
}
