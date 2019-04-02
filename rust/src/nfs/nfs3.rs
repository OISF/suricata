/* Copyright (C) 2017-2018 Open Information Security Foundation
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

use nom;
use log::*;
use core::*;

use nfs::nfs::*;
use nfs::types::*;
use nfs::rpc_records::*;
use nfs::nfs3_records::*;

impl NFSState {
    /// complete NFS3 request record
    pub fn process_request_record_v3<'b>(&mut self, r: &RpcPacket<'b>) -> u32 {
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
            match parse_nfs3_request_access(r.prog_data) {
                Ok((_, ar)) => {
                    xidmap.file_handle = ar.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_GETATTR {
            match parse_nfs3_request_getattr(r.prog_data) {
                Ok((_, gar)) => {
                    xidmap.file_handle = gar.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_READDIRPLUS {
            match parse_nfs3_request_readdirplus(r.prog_data) {
                Ok((_, rdp)) => {
                    xidmap.file_handle = rdp.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_READ {
            match parse_nfs3_request_read(r.prog_data) {
                Ok((_, nfs3_read_record)) => {
                    xidmap.chunk_offset = nfs3_read_record.offset;
                    xidmap.file_handle = nfs3_read_record.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_WRITE {
            match parse_nfs3_request_write(r.prog_data) {
                Ok((_, w)) => {
                    self.process_write_record(r, &w);
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            }
        } else if r.procedure == NFSPROC3_CREATE {
            match parse_nfs3_request_create(r.prog_data) {
                Ok((_, nfs3_create_record)) => {
                    xidmap.file_handle = nfs3_create_record.handle.value.to_vec();
                    xidmap.file_name = nfs3_create_record.name_vec;
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };

        } else if r.procedure == NFSPROC3_REMOVE {
            match parse_nfs3_request_remove(r.prog_data) {
                Ok((_, rr)) => {
                    xidmap.file_handle = rr.handle.value.to_vec();
                    xidmap.file_name = rr.name_vec;
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };

        } else if r.procedure == NFSPROC3_RENAME {
            match parse_nfs3_request_rename(r.prog_data) {
                Ok((_, rr)) => {
                    xidmap.file_handle = rr.from_handle.value.to_vec();
                    xidmap.file_name = rr.from_name_vec;
                    aux_file_name = rr.to_name_vec;
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_MKDIR {
            match parse_nfs3_request_mkdir(r.prog_data) {
                Ok((_, mr)) => {
                    xidmap.file_handle = mr.handle.value.to_vec();
                    xidmap.file_name = mr.name_vec;
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_RMDIR {
            match parse_nfs3_request_rmdir(r.prog_data) {
                Ok((_, rr)) => {
                    xidmap.file_handle = rr.handle.value.to_vec();
                    xidmap.file_name = rr.name_vec;
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if r.procedure == NFSPROC3_COMMIT {
            SCLogDebug!("COMMIT, closing shop");

            match parse_nfs3_request_commit(r.prog_data) {
                Ok((_, cr)) => {
                    let file_handle = cr.handle.value.to_vec();
                    match self.get_file_tx_by_handle(&file_handle, STREAM_TOSERVER) {
                        Some((tx, files, flags)) => {
                            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                                tdf.chunk_count += 1;
                                tdf.file_additional_procs.push(NFSPROC3_COMMIT);
                                tdf.file_tracker.close(files, flags);
                                tdf.file_last_xid = r.hdr.xid;
                                tx.is_last = true;
                                tx.request_done = true;
                            }
                        },
                        None => { },
                    }
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
            tx.nfs_version = r.progver as u16;
            tx.file_handle = xidmap.file_handle.to_vec();

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
            SCLogDebug!("TX created: ID {} XID {} PROCEDURE {}",
                    tx.id, tx.xid, tx.procedure);
            self.transactions.push(tx);

        } else if r.procedure == NFSPROC3_READ {

            let found = match self.get_file_tx_by_handle(&xidmap.file_handle, STREAM_TOCLIENT) {
                Some((_, _, _)) => true,
                None => false,
            };
            if !found {
                let (tx, _, _) = self.new_file_tx(&xidmap.file_handle, &xidmap.file_name, STREAM_TOCLIENT);
                tx.procedure = NFSPROC3_READ;
                tx.xid = r.hdr.xid;
                tx.is_first = true;
                tx.nfs_version = r.progver as u16;

                tx.auth_type = r.creds_flavor;
                match r.creds {
                    RpcRequestCreds::Unix(ref u) => {
                        tx.request_machine_name = u.machine_name_buf.to_vec();
                        tx.request_uid = u.uid;
                        tx.request_gid = u.gid;
                    },
                    _ => { },
                }
            }
        }

        self.requestmap.insert(r.hdr.xid, xidmap);
        0
    }

    pub fn process_reply_record_v3<'b>(&mut self, r: &RpcReplyPacket<'b>, xidmap: &mut NFSRequestXidMap) -> u32 {
        let mut nfs_status = 0;
        let mut resp_handle = Vec::new();

        if xidmap.procedure == NFSPROC3_LOOKUP {
            match parse_nfs3_response_lookup(r.prog_data) {
                Ok((_, lookup)) => {
                    SCLogDebug!("LOOKUP: {:?}", lookup);
                    SCLogDebug!("RESPONSE LOOKUP file_name {:?}", xidmap.file_name);

                    nfs_status = lookup.status;

                    SCLogDebug!("LOOKUP handle {:?}", lookup.handle);
                    self.namemap.insert(lookup.handle.value.to_vec(), xidmap.file_name.to_vec());
                    resp_handle = lookup.handle.value.to_vec();
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if xidmap.procedure == NFSPROC3_CREATE {
            match parse_nfs3_response_create(r.prog_data) {
                Ok((_, nfs3_create_record)) => {
                    SCLogDebug!("nfs3_create_record: {:?}", nfs3_create_record);

                    SCLogDebug!("RESPONSE CREATE file_name {:?}", xidmap.file_name);
                    nfs_status = nfs3_create_record.status;

                    if let Some(h) = nfs3_create_record.handle {
                        SCLogDebug!("handle {:?}", h);
                        self.namemap.insert(h.value.to_vec(), xidmap.file_name.to_vec());
                        resp_handle = h.value.to_vec();
                    }

                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            };
        } else if xidmap.procedure == NFSPROC3_READ {
            match parse_nfs3_reply_read(r.prog_data) {
                Ok((_, ref reply)) => {
                    self.process_read_record(r, reply, Some(&xidmap));
                    nfs_status = reply.status;
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            }
        } else if xidmap.procedure == NFSPROC3_READDIRPLUS {
            match parse_nfs3_response_readdirplus(r.prog_data) {
                Ok((_, ref reply)) => {
                    //SCLogDebug!("READDIRPLUS reply {:?}", reply);

                    nfs_status = reply.status;

                    // cut off final eof field
                    let d = if reply.data.len() >= 4 {
                        &reply.data[..reply.data.len()-4 as usize]
                    } else {
                        reply.data
                    };

                    // store all handle/filename mappings
                    match many0_nfs3_response_readdirplus_entries(d) {
                        Ok((_, ref entries)) => {
                            for ce in entries {
                                SCLogDebug!("ce {:?}", ce);
                                match ce.entry {
                                    Some(ref e) => {
                                        SCLogDebug!("e {:?}", e);
                                        match e.handle {
                                            Some(ref h) => {
                                                SCLogDebug!("h {:?}", h);
                                                self.namemap.insert(h.value.to_vec(), e.name_vec.to_vec());
                                            },
                                            _ => { },
                                        }
                                    },
                                    _ => { },
                                }
                            }

                            SCLogDebug!("READDIRPLUS ENTRIES reply {:?}", entries);
                        },
                        _ => {
                            self.set_event(NFSEvent::MalformedData);
                        },
                    }
                },
                _ => {
                    self.set_event(NFSEvent::MalformedData);
                },
            }
        }
        // for all other record types only parse the status
        else {
            let stat = match nom::be_u32(&r.prog_data) {
                Ok((_, stat)) => {
                    stat as u32
                }
                _ => 0 as u32
            };
            nfs_status = stat;
        }
        SCLogDebug!("REPLY {} to procedure {} blob size {}",
                r.hdr.xid, xidmap.procedure, r.prog_data.len());

        if xidmap.procedure != NFSPROC3_READ {
            self.mark_response_tx_done(r.hdr.xid, r.reply_state, nfs_status, &resp_handle);
        }

        0
    }

}

