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

use crate::core::*;

use crate::nfs::nfs::*;
use crate::nfs::types::*;
use crate::nfs::rpc_records::*;
use crate::nfs::nfs3_records::*;

use nom7::IResult;
use nom7::number::streaming::be_u32;

impl NFSState {
    /// complete NFS3 request record
    pub fn process_request_record_v3<'b>(&mut self, r: &RpcPacket<'b>) {
        SCLogDebug!("REQUEST {} procedure {} ({}) blob size {}",
                r.hdr.xid, r.procedure, self.requestmap.len(), r.prog_data.len());

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
                self.process_write_record(r, &rd);
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
                        let (files, flags) = tdf.files.get(Direction::ToServer);
                        tdf.chunk_count += 1;
                        tdf.file_additional_procs.push(NFSPROC3_COMMIT);
                        tdf.file_tracker.close(files, flags);
                        tdf.file_last_xid = r.hdr.xid;
                        tx.is_last = true;
                        tx.request_done = true;
                        tx.is_file_closed = true;
                    }
                }
            } else {
                self.set_event(NFSEvent::MalformedData);
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
                },
                _ => { },
            }
            SCLogDebug!("TX created: ID {} XID {} PROCEDURE {}",
                    tx.id, tx.xid, tx.procedure);
            self.transactions.push(tx);

        } else if r.procedure == NFSPROC3_READ {

            let found = match self.get_file_tx_by_handle(&xidmap.file_handle, Direction::ToClient) {
                Some(_) => true,
                None => false,
            };
            if !found {
                let tx = self.new_file_tx(&xidmap.file_handle, &xidmap.file_name, Direction::ToClient);
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

        self.requestmap.insert(r.hdr.xid, xidmap);
    }

    pub fn process_reply_record_v3<'b>(&mut self, r: &RpcReplyPacket<'b>, xidmap: &mut NFSRequestXidMap) {
        let mut nfs_status = 0;
        let mut resp_handle = Vec::new();

        if xidmap.procedure == NFSPROC3_LOOKUP {
            if let Ok((_, rd)) = parse_nfs3_response_lookup(r.prog_data) {
                SCLogDebug!("LOOKUP: {:?}", rd);
                SCLogDebug!("RESPONSE LOOKUP file_name {:?}", xidmap.file_name);

                nfs_status = rd.status;

                SCLogDebug!("LOOKUP handle {:?}", rd.handle);
                self.namemap.insert(rd.handle.value.to_vec(), xidmap.file_name.to_vec());
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
                    self.namemap.insert(h.value.to_vec(), xidmap.file_name.to_vec());
                    resp_handle = h.value.to_vec();
                }
            } else {
                self.set_event(NFSEvent::MalformedData);
            };
        } else if xidmap.procedure == NFSPROC3_READ {
            if let Ok((_, rd)) = parse_nfs3_reply_read(r.prog_data, true) {
                self.process_read_record(r, &rd, Some(xidmap));
                nfs_status = rd.status;
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        } else if xidmap.procedure == NFSPROC3_READDIRPLUS {
            if let Ok((_, rd)) = parse_nfs3_response_readdirplus(r.prog_data) {
                nfs_status = rd.status;

                // cut off final eof field
                let d = if rd.data.len() >= 4 {
                    &rd.data[..rd.data.len()-4_usize]
                } else {
                    rd.data
                };

                // store all handle/filename mappings
                if let Ok((_, ref entries)) = many0_nfs3_response_readdirplus_entries(d) {
                    SCLogDebug!("READDIRPLUS ENTRIES reply {:?}", entries);
                    for ce in entries {
                        SCLogDebug!("ce {:?}", ce);
                        if let Some(ref e) = ce.entry {
                            SCLogDebug!("e {:?}", e);
                            if let Some(ref h) = e.handle {
                                SCLogDebug!("h {:?}", h);
                                self.namemap.insert(h.value.to_vec(),
                                        e.name_vec.to_vec());
                            }
                        }
                    }
                } else {
                    self.set_event(NFSEvent::MalformedData);
                }
            } else {
                self.set_event(NFSEvent::MalformedData);
            }
        }
        // for all other record types only parse the status
        else {
            let stat : u32 = match be_u32(r.prog_data) as IResult<&[u8],_> {
                Ok((_, stat)) => stat,
                _ => 0
            };
            nfs_status = stat;
        }
        SCLogDebug!("REPLY {} to procedure {} blob size {}",
                r.hdr.xid, xidmap.procedure, r.prog_data.len());

        if xidmap.procedure != NFSPROC3_READ {
            self.mark_response_tx_done(r.hdr.xid, r.reply_state, nfs_status, &resp_handle);
        }
    }
}
