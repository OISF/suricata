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

use crate::direction::Direction;
use crate::flow::Flow;
use crate::nfs::nfs::*;
use crate::nfs::nfs3_records::*;
use crate::nfs::rpc_records::*;
use crate::nfs::types::*;

use nom7::number::streaming::be_u32;
use nom7::IResult;

impl NFSState {
    /// complete NFS3 request record
    pub fn process_request_record_v3(&mut self, flow: *mut Flow, r: &RpcPacket) {
        SCLogDebug!(
            "REQUEST {} procedure {} ({}) blob size {}",
            r.hdr.xid,
            r.procedure,
            self.requestmap.len(),
            r.prog_data.len()
        );

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);
        let mut aux_file_name = Vec::new();

        if self.nfs_version == 0 {
            self.nfs_version = r.progver as u16;
        }

        if r.procedure == NFSPROC3_LOOKUP {
            self.process_request_record_lookup(r, &mut xidmap);
        } else if r.procedure == NFSPROC3_ACCESS {
            if let Ok((_, rd)) = parse_nfs3_request_access(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_GETATTR {
            if let Ok((_, rd)) = parse_nfs3_request_getattr(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_READDIRPLUS {
            if let Ok((_, rd)) = parse_nfs3_request_readdirplus(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_READDIR {
            if let Ok((_, rd)) = parse_nfs3_request_readdir(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_SETATTR {
            if let Ok((_, rd)) = parse_nfs3_request_setattr(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_READ {
            if let Ok((_, rd)) = parse_nfs3_request_read(r.prog_data) {
                xidmap.chunk_offset = rd.offset;
                xidmap.file_handle = rd.handle.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_WRITE {
            if let Ok((_, rd)) = parse_nfs3_request_write(r.prog_data, true) {
                self.process_write_record(flow, r, &rd);
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if r.procedure == NFSPROC3_CREATE {
            if let Ok((_, rd)) = parse_nfs3_request_create(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_REMOVE {
            if let Ok((_, rd)) = parse_nfs3_request_remove(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_RENAME {
            if let Ok((_, rd)) = parse_nfs3_request_rename(r.prog_data) {
                xidmap.file_handle = rd.from_handle.value.to_vec();
                xidmap.file_name = rd.from_name_vec;
                aux_file_name = rd.to_name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_MKDIR {
            if let Ok((_, rd)) = parse_nfs3_request_mkdir(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_RMDIR {
            if let Ok((_, rd)) = parse_nfs3_request_rmdir(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_COMMIT {
            SCLogDebug!("COMMIT, closing shop");
            if let Ok((_, rd)) = parse_nfs3_request_commit(r.prog_data) {
                let file_handle = rd.handle.value.to_vec();
                if let Some(tx) = self.get_file_tx_by_handle(&file_handle, Direction::ToServer) {
                    if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                        tdf.chunk_count += 1;
                        // only caller pushing
                        // so we just need to know we saw this procedure
                        if tdf.file_additional_procs.is_empty() {
                            tdf.file_additional_procs.push(NFSPROC3_COMMIT);
                        }
                        filetracker_close(&mut tdf.file_tracker);
                        tdf.file_last_xid = r.hdr.xid;
                        tx.is_last = true;
                        tx.request_done = true;
                        // The WRITE replies carried no file data and file txs
                        // are invisible to the reply path's xid lookup, so
                        // complete the response side here as well (COMMIT is
                        // the explicit "all writes done" signal for this file).
                        tx.response_done = true;
                        tx.is_file_closed = true;
                    }
                }
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_FSSTAT
            || r.procedure == NFSPROC3_FSINFO
            || r.procedure == NFSPROC3_PATHCONF
            || r.procedure == NFSPROC3_READLINK
        {
            // These take a bare filehandle as their only argument: wire the
            // handle so the record carries hhash + name.
            if let Ok((_, rd)) = parse_nfs3_handle(r.prog_data) {
                xidmap.file_handle = rd.value.to_vec();
                self.xidmap_handle2name(&mut xidmap);
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_MKNOD {
            if let Ok((_, rd)) = parse_nfs3_request_mknod(r.prog_data) {
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_LINK {
            if let Ok((_, rd)) = parse_nfs3_request_link(r.prog_data) {
                // the tx identity is the new link: its name rides the
                // request (diropargs3 link.name), the file handle is the
                // source file
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.linkname;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if r.procedure == NFSPROC3_SYMLINK {
            if let Ok((_, rd)) = parse_nfs3_request_symlink(r.prog_data) {
                // the tx identity is the new symlink (diropargs3 where:
                // dir + name); the sattr3 + target path are consumed, not
                // logged
                xidmap.file_handle = rd.handle.value.to_vec();
                xidmap.file_name = rd.name_vec;
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        }

        if !(r.procedure == NFSPROC3_COMMIT || // commit handled separately
             r.procedure == NFSPROC3_WRITE  || // write handled in file tx
             r.procedure == NFSPROC3_READ)
        // read handled in file tx at reply
        {
            let mut tx = self.new_tx();
            tx.xid = r.hdr.xid;
            tx.procedure = r.procedure;
            tx.request_done = true;
            tx.file_name = xidmap.file_name.to_vec();
            tx.nfs_version = r.progver as u16;
            tx.file_handle = xidmap.file_handle.to_vec();

            if r.procedure == NFSPROC3_RENAME {
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
                "TX created: ID {} XID {} PROCEDURE {}",
                tx.id,
                tx.xid,
                tx.procedure
            );
            self.transactions.push(tx);
        } else if r.procedure == NFSPROC3_READ {
            let found = self
                .get_file_tx_by_handle(&xidmap.file_handle, Direction::ToClient)
                .is_some();
            if !found {
                let tx =
                    self.new_file_tx(&xidmap.file_handle, &xidmap.file_name, Direction::ToClient);
                tx.procedure = NFSPROC3_READ;
                tx.xid = r.hdr.xid;
                tx.is_first = true;
                tx.nfs_version = r.progver as u16;

                tx.auth_type = r.creds_flavor;
                if let RpcRequestCreds::Unix(ref u) = r.creds {
                    tx.request_machine_name = u.machine_name_buf.to_vec();
                    tx.request_uid = u.uid;
                    tx.request_gid = u.gid;
                }
            }
        }

        self.requestmap.put(r.hdr.xid, xidmap);
    }

    pub fn process_reply_record_v3(
        &mut self, flow: *mut Flow, r: &RpcReplyPacket, xidmap: &mut NFSRequestXidMap,
    ) {
        let mut nfs_status = 0;
        let mut resp_handle = Vec::new();

        // An accepted NFS/v3 reply carries its status word first. NULL
        // returns void (RFC 1813 3.3.0) and a rejected reply carries no body
        // at all, so an empty one is only a problem for an accepted call of
        // another procedure (the default 0 would read as a fake OK).
        let accepted = r.accept_state == 0;
        let null_call = xidmap.procedure == NFSPROC3_NULL;
        let nfs_status_set = if null_call {
            accepted
        } else {
            r.prog_data.len() >= 4
        };
        if !nfs_status_set && accepted && !null_call {
            self.set_event(NFSEvent::MalformedData);
        }

        if xidmap.procedure == NFSPROC3_LOOKUP {
            if let Ok((_, rd)) = parse_nfs3_response_lookup(r.prog_data) {
                SCLogDebug!("LOOKUP: {:?}", rd);
                SCLogDebug!("RESPONSE LOOKUP file_name {:?}", xidmap.file_name);

                nfs_status = rd.status;

                SCLogDebug!("LOOKUP handle {:?}", rd.handle);
                self.namemap
                    .put(rd.handle.value.to_vec(), xidmap.file_name.to_vec());
                resp_handle = rd.handle.value.to_vec();
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if xidmap.procedure == NFSPROC3_CREATE {
            if let Ok((_, rd)) = parse_nfs3_response_create(r.prog_data) {
                SCLogDebug!("nfs3_create_record: {:?}", rd);
                SCLogDebug!("RESPONSE CREATE file_name {:?}", xidmap.file_name);
                nfs_status = rd.status;

                if let Some(h) = rd.handle {
                    SCLogDebug!("handle {:?}", h);
                    self.namemap
                        .put(h.value.to_vec(), xidmap.file_name.to_vec());
                    resp_handle = h.value.to_vec();
                }
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if xidmap.procedure == NFSPROC3_READ {
            if let Ok((_, rd)) = parse_nfs3_reply_read(r.prog_data, true) {
                self.process_read_record(flow, r, &rd, Some(xidmap), true);
                nfs_status = rd.status;
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if xidmap.procedure == NFSPROC3_READDIRPLUS {
            // Same tolerance as READDIR: the dirlistplus3 chain, when
            // present, must consume exactly; a truncated or spliced tail
            // (UDP reassembly) only loses the namemap entries; the status
            // is always taken from the record head.
            match parse_nfs3_response_readdirplus(r.prog_data) {
                Ok((_, rd)) => {
                    nfs_status = rd.status;
                    // the entry chain is only there for a successful reply
                    let chain = if rd.status == 0 {
                        many0_nfs3_response_readdirplus_entries(rd.data).ok()
                    } else {
                        None
                    };
                    if let Some((_, entries)) = chain {
                        SCLogDebug!("READDIRPLUS: {} entries", entries.len());
                        // name_handle is the entry's own handle: the follow-up
                        // file data arrives under it
                        for e in &entries {
                            if let Some(nh) = e.handle.as_ref() {
                                self.namemap.put(nh.value.to_vec(), e.name_vec.to_vec());
                            }
                        }
                    }
                }
                Err(_) => {
                    // tail tolerated (see above), but the anomaly stays
                    // observable
                    self.set_event(NFSEvent::MalformedData);
                    if let Ok((_, stat)) = be_u32(r.prog_data) as IResult<&[u8], _> {
                        nfs_status = stat;
                    }
                }
            }
        } else if xidmap.procedure == NFSPROC3_READDIR {
            // The dirlist3 chain is parsed best-effort: real servers pad
            // error replies (e.g. JUKEBOX carries garbage), and
            // Suricata's UDP reassembly can splice datagrams, so a
            // tail that does not pack exactly is tolerated; the status
            // is always taken from the record head.
            nfs_status = match parse_nfs3_response_readdir(r.prog_data) {
                Ok((_, rd)) => rd.status,
                Err(_) => {
                    // tail tolerated (see above), but the anomaly stays
                    // observable
                    self.set_event(NFSEvent::MalformedData);
                    match be_u32(r.prog_data) as IResult<&[u8], _> {
                        Ok((_, stat)) => stat,
                        _ => 0,
                    }
                }
            };
        } else if xidmap.procedure == NFSPROC3_SETATTR {
            // wcc_data is parsed best-effort, same tolerance as READDIR
            nfs_status = match parse_nfs3_response_setattr(r.prog_data) {
                Ok((_, rd)) => rd.status,
                Err(_) => {
                    // tail tolerated (see above), but the anomaly stays
                    // observable
                    self.set_event(NFSEvent::MalformedData);
                    match be_u32(r.prog_data) as IResult<&[u8], _> {
                        Ok((_, stat)) => stat,
                        _ => 0,
                    }
                }
            };
        } else if xidmap.procedure == NFSPROC3_FSINFO {
            // status from the record head, as READDIR and SETATTR do: a
            // broken reply must not log as a fake OK
            nfs_status = match parse_nfs3_response_fsinfo(r.prog_data) {
                Ok((_, rd)) => {
                    if rd.status == 0 {
                        self.fsinfo_max_read = rd.rtm;
                        self.fsinfo_max_write = rd.wtm;
                        SCLogDebug!("FSINFO: max read {} max write {}", rd.rtm, rd.wtm);
                    }
                    rd.status
                }
                Err(_) => {
                    self.set_event(NFSEvent::MalformedData);
                    match be_u32(r.prog_data) as IResult<&[u8], _> {
                        Ok((_, stat)) => stat,
                        _ => 0,
                    }
                }
            };
        }
        // for all other record types only parse the status
        else {
            let stat: u32 = match be_u32(r.prog_data) as IResult<&[u8], _> {
                Ok((_, stat)) => stat,
                _ => 0,
            };
            nfs_status = stat;
        }
        SCLogDebug!(
            "REPLY {} to procedure {} blob size {}",
            r.hdr.xid,
            xidmap.procedure,
            r.prog_data.len()
        );

        if xidmap.procedure != NFSPROC3_READ {
            self.mark_response_tx_done(
                flow,
                r.hdr.xid,
                r.reply_state,
                nfs_status,
                nfs_status_set,
                &resp_handle,
            );
        }
    }
}
