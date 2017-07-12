/* Copyright (C) 2017 Open Information Security Foundation
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
// TCP buffering code written by Pierre Chifflier

extern crate libc;
use std;
use std::mem::transmute;
use std::collections::{HashMap};
use std::ffi::CStr;

use nom;
use nom::IResult;

use log::*;
use applayer::LoggerFlags;
use core::*;
use filetracker::*;
use filecontainer::*;

use nfs::types::*;
use nfs::rpc_records::*;
use nfs::nfs_records::*;
use nfs::nfs2_records::*;
use nfs::nfs3_records::*;

/// nom bug leads to this wrappers being necessary
/// TODO for some reason putting these in parser.rs and making them public
/// leads to a compile error wrt an unknown lifetime identifier 'a
//named!(many0_nfs3_request_objects<Vec<Nfs3RequestObject<'a>>>, many0!(parse_nfs3_request_object));
//named!(many0_nfs3_reply_objects<Vec<Nfs3ReplyObject<'a>>>, many0!(parse_nfs3_reply_object));
named!(many0_nfs3_response_readdirplus_entries<Vec<Nfs3ResponseReaddirplusEntry<'a>>>,
        many0!(parse_nfs3_response_readdirplus_entry_cond));

pub static mut SURICATA_NFS3_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

/*
 * Record parsing.
 *
 * Incomplete records come in due to TCP splicing. For all record types
 * except READ and WRITE, processing only begins when the full record
 * is available. For READ/WRITE partial records are processed as well to
 * avoid queuing too much data.
 *
 * Getting file names.
 *
 * NFS makes heavy use of 'file handles' for operations. In many cases it
 * uses a file name just once and after that just the handle. For example,
 * if a client did a file listing (e.g. READDIRPLUS) and would READ the
 * file afterwards, the name will only appear in the READDIRPLUS answer.
 * To be able to log the names we store a mapping between file handles
 * and file names in NFSState::namemap.
 *
 * Mapping NFS to Suricata's transaction model.
 *
 * The easiest way to do transactions would be to map each command/reply with
 * the same XID to a transaction. This would allow for per XID logging, detect
 * etc. However this model doesn't fit well with file tracking. The file
 * tracking in Suricata is really expecting to be one or more files to live
 * inside a single transaction. Would XID pairs be a transaction however,
 * there would be many transactions forming a single file. This will be very
 * inefficient.
 *
 * The model implemented here is as follows: each file transfer is a single
 * transaction. All XID pairs unrelated to those file transfers create
 * transactions per pair.
 *
 * A complicating factor is that the procedure matching is per tx, and a
 * file transfer may have multiple procedures involved. Currently now only
 * a COMMIT after WRITEs. A vector of additional procedures is kept to
 * match on this.
 *
 * File tracking
 *
 * Files are tracked per 'FileTransferTracker' and are stored in the
 * NFSTransaction where they can be looked up per handle as part of the
 * Transaction lookup.
 */

#[repr(u32)]
pub enum NFSEvent {
    MalformedData = 0,
    /* remove 'Padding' when more events are added. Rustc 1.7 won't
     *   accept a single field enum with repr(u32) */
    Padding,
}

#[derive(Debug)]
pub enum NFSTransactionTypeData {
    RENAME(Vec<u8>),
    FILE(NFSTransactionFile),
}

#[derive(Debug)]
pub struct NFSTransactionFile {
    /// additional procedures part of a single file transfer. Currently
    /// only COMMIT on WRITEs.
    pub file_additional_procs: Vec<u32>,

    pub chunk_count: u32,

    /// last xid of this file transfer. Last READ or COMMIT normally.
    pub file_last_xid: u32,

    /// file tracker for a single file. Boxed so that we don't use
    /// as much space if we're not a file tx.
    pub file_tracker: FileTransferTracker,
}

impl NFSTransactionFile {
    pub fn new() -> NFSTransactionFile {
        return NFSTransactionFile {
            file_additional_procs: Vec::new(),
            chunk_count:0,
            file_last_xid: 0,
            file_tracker: FileTransferTracker::new(),
        }
    }
}

#[derive(Debug)]
pub struct NFSTransaction {
    pub id: u64,    /// internal id
    pub xid: u32,   /// nfs3 req/reply pair id
    pub procedure: u32,
    /// file name of the object we're dealing with. In case of RENAME
    /// this is the 'from' or original name.
    pub file_name: Vec<u8>,

    pub auth_type: u32,
    pub request_machine_name: Vec<u8>,
    pub request_uid: u32,
    pub request_gid: u32,

    pub rpc_response_status: u32,
    pub nfs_response_status: u32,

    pub is_first: bool,
    pub is_last: bool,

    /// for state tracking. false means this side is in progress, true
    /// that it's complete.
    request_done: bool,
    response_done: bool,

    pub nfs_version: u16,

    /// is a special file tx that we look up by file_handle instead of XID
    pub is_file_tx: bool,
    /// file transactions are unidirectional in the sense that they track
    /// a single file on one direction
    pub file_tx_direction: u8, // STREAM_TOCLIENT or STREAM_TOSERVER
    pub file_handle: Vec<u8>,

    /// Procedure type specific data
    /// TODO see if this can be an Option<Box<NFSTransactionTypeData>>. Initial
    /// attempt failed.
    pub type_data: Option<NFSTransactionTypeData>,

    pub logged: LoggerFlags,
    pub de_state: Option<*mut DetectEngineState>,
    pub events: *mut AppLayerDecoderEvents,
}

impl NFSTransaction {
    pub fn new() -> NFSTransaction {
        return NFSTransaction{
            id: 0,
            xid: 0,
            procedure: 0,
            file_name:Vec::new(),
            request_machine_name:Vec::new(),
            request_uid:0,
            request_gid:0,
            rpc_response_status:0,
            nfs_response_status:0,
            auth_type: 0,
            is_first: false,
            is_last: false,
            request_done: false,
            response_done: false,
            nfs_version:0,
            is_file_tx: false,
            file_tx_direction: 0,
            file_handle:Vec::new(),
            type_data: None,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            sc_app_layer_decoder_events_free_events(&mut self.events);
        }
    }
}

#[derive(Debug)]
pub struct NFSRequestXidMap {
    progver: u32,
    procedure: u32,
    chunk_offset: u64,
    file_name:Vec<u8>,

    /// READ replies can use this to get to the handle the request used
    file_handle:Vec<u8>,
}

impl NFSRequestXidMap {
    pub fn new(progver: u32, procedure: u32, chunk_offset: u64) -> NFSRequestXidMap {
        NFSRequestXidMap {
            progver:progver,
            procedure:procedure,
            chunk_offset:chunk_offset,
            file_name:Vec::new(),
            file_handle:Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct NFSFiles {
    pub files_ts: FileContainer,
    pub files_tc: FileContainer,
    pub flags_ts: u16,
    pub flags_tc: u16,
}

impl NFSFiles {
    pub fn new() -> NFSFiles {
        NFSFiles {
            files_ts:FileContainer::default(),
            files_tc:FileContainer::default(),
            flags_ts:0,
            flags_tc:0,
        }
    }
    pub fn free(&mut self) {
        self.files_ts.free();
        self.files_tc.free();
    }

    pub fn get(&mut self, direction: u8) -> (&mut FileContainer, u16)
    {
        if direction == STREAM_TOSERVER {
            (&mut self.files_ts, self.flags_ts)
        } else {
            (&mut self.files_tc, self.flags_tc)
        }
    }
}

/// little wrapper around the FileTransferTracker::new_chunk method
fn filetracker_newchunk(ft: &mut FileTransferTracker, files: &mut FileContainer,
        flags: u16, name: &Vec<u8>, data: &[u8],
        chunk_offset: u64, chunk_size: u32, fill_bytes: u8, is_last: bool, xid: &u32)
{
    match unsafe {SURICATA_NFS3_FILE_CONFIG} {
        Some(sfcm) => {
            ft.new_chunk(sfcm, files, flags, &name, data, chunk_offset,
                    chunk_size, fill_bytes, is_last, xid); }
        None => panic!("BUG"),
    }
}

#[derive(Debug)]
pub struct NFSState {
    /// map xid to procedure so replies can lookup the procedure
    pub requestmap: HashMap<u32, NFSRequestXidMap>,

    /// map file handle (1) to name (2)
    pub namemap: HashMap<Vec<u8>, Vec<u8>>,

    /// transactions list
    pub transactions: Vec<NFSTransaction>,

    /// TCP segments defragmentation buffer
    pub tcp_buffer_ts: Vec<u8>,
    pub tcp_buffer_tc: Vec<u8>,

    pub files: NFSFiles,

    /// partial record tracking
    ts_chunk_xid: u32,
    tc_chunk_xid: u32,
    /// size of the current chunk that we still need to receive
    ts_chunk_left: u32,
    tc_chunk_left: u32,

    ts_ssn_gap: bool,
    tc_ssn_gap: bool,

    ts_gap: bool, // last TS update was gap
    tc_gap: bool, // last TC update was gap

    is_udp: bool,

    pub nfs_version: u16,

    pub events: u16,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,

    pub de_state_count: u64,

    // HACK flag state if tx has been marked complete in a direction
    // this way we can skip a lot of looping in output-tx.c
    //pub ts_txs_updated: bool,
    //pub tc_txs_updated: bool,
}

impl NFSState {
    /// Allocation function for a new TLS parser instance
    pub fn new() -> NFSState {
        NFSState {
            requestmap:HashMap::new(),
            namemap:HashMap::new(),
            transactions: Vec::new(),
            tcp_buffer_ts:Vec::with_capacity(8192),
            tcp_buffer_tc:Vec::with_capacity(8192),
            files:NFSFiles::new(),
            ts_chunk_xid:0,
            tc_chunk_xid:0,
            ts_chunk_left:0,
            tc_chunk_left:0,
            ts_ssn_gap:false,
            tc_ssn_gap:false,
            ts_gap:false,
            tc_gap:false,
            is_udp:false,
            nfs_version:0,
            events:0,
            tx_id:0,
            de_state_count:0,
            //ts_txs_updated:false,
            //tc_txs_updated:false,
        }
    }
    pub fn free(&mut self) {
        self.files.free();
    }

    pub fn new_tx(&mut self) -> NFSTransaction {
        let mut tx = NFSTransaction::new();
        self.tx_id += 1;
        tx.id = self.tx_id;
        return tx;
    }

    pub fn free_tx(&mut self, tx_id: u64) {
        //SCLogNotice!("Freeing TX with ID {}", tx_id);
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            SCLogDebug!("freeing TX with ID {} at index {}", tx_id, index);
            self.free_tx_at_index(index);
        }
    }

    fn free_tx_at_index(&mut self, index: usize) {
        let tx = self.transactions.remove(index);
        match tx.de_state {
            Some(state) => {
                sc_detect_engine_state_free(state);
                self.de_state_count -= 1;
            }
            _ => {}
        }
    }

    pub fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&NFSTransaction> {
        SCLogDebug!("get_tx_by_id: tx_id={}", tx_id);
        for tx in &mut self.transactions {
            if tx.id == tx_id + 1 {
                SCLogDebug!("Found NFS TX with ID {}", tx_id);
                return Some(tx);
            }
        }
        SCLogDebug!("Failed to find NFS TX with ID {}", tx_id);
        return None;
    }

    pub fn get_tx_by_xid(&mut self, tx_xid: u32) -> Option<&mut NFSTransaction> {
        SCLogDebug!("get_tx_by_xid: tx_xid={}", tx_xid);
        for tx in &mut self.transactions {
            if !tx.is_file_tx && tx.xid == tx_xid {
                SCLogDebug!("Found NFS TX with ID {} XID {}", tx.id, tx.xid);
                return Some(tx);
            }
        }
        SCLogDebug!("Failed to find NFS TX with XID {}", tx_xid);
        return None;
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: NFSEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let mut tx = &mut self.transactions[len - 1];
        sc_app_layer_decoder_events_set_event_raw(&mut tx.events, event as u8);
        self.events += 1;
    }

    // TODO maybe not enough users to justify a func
    fn mark_response_tx_done(&mut self, xid: u32, rpc_status: u32, nfs_status: u32, resp_handle: &Vec<u8>)
    {
        match self.get_tx_by_xid(xid) {
            Some(mut mytx) => {
                mytx.response_done = true;
                mytx.rpc_response_status = rpc_status;
                mytx.nfs_response_status = nfs_status;
                if mytx.file_handle.len() == 0 && resp_handle.len() > 0 {
                    mytx.file_handle = resp_handle.to_vec();
                }

                SCLogDebug!("process_reply_record: tx ID {} XID {} REQUEST {} RESPONSE {}",
                        mytx.id, mytx.xid, mytx.request_done, mytx.response_done);
            },
            None => {
                //SCLogNotice!("process_reply_record: not TX found for XID {}", r.hdr.xid);
            },
        }

        //self.tc_txs_updated = true;
    }

    fn process_request_record_lookup<'b>(&mut self, r: &RpcPacket<'b>, xidmap: &mut NFSRequestXidMap) {
        match parse_nfs3_request_lookup(r.prog_data) {
            IResult::Done(_, lookup) => {
                SCLogDebug!("LOOKUP {:?}", lookup);
                xidmap.file_name = lookup.name_vec;
            },
            IResult::Incomplete(_) => {
                self.set_event(NFSEvent::MalformedData);
            },
            IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
        };
    }

    fn xidmap_handle2name(&mut self, xidmap: &mut NFSRequestXidMap) {
        match self.namemap.get(&xidmap.file_handle) {
            Some(n) => {
                SCLogDebug!("xidmap_handle2name: name {:?}", n);
                xidmap.file_name = n.to_vec();
            },
            _ => {
                SCLogDebug!("xidmap_handle2name: object {:?} not found",
                        xidmap.file_handle);
            },
        }
    }

    /// complete request record
    fn process_request_record<'b>(&mut self, r: &RpcPacket<'b>) -> u32 {
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
                IResult::Done(_, ar) => {
                    xidmap.file_handle = ar.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_GETATTR {
            match parse_nfs3_request_getattr(r.prog_data) {
                IResult::Done(_, gar) => {
                    xidmap.file_handle = gar.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_READDIRPLUS {
            match parse_nfs3_request_readdirplus(r.prog_data) {
                IResult::Done(_, rdp) => {
                    xidmap.file_handle = rdp.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_READ {
            match parse_nfs3_request_read(r.prog_data) {
                IResult::Done(_, nfs3_read_record) => {
                    xidmap.chunk_offset = nfs3_read_record.offset;
                    xidmap.file_handle = nfs3_read_record.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_WRITE {
            match parse_nfs3_request_write(r.prog_data) {
                IResult::Done(_, w) => {
                    self.process_write_record(r, &w);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            }
        } else if r.procedure == NFSPROC3_CREATE {
            match parse_nfs3_request_create(r.prog_data) {
                IResult::Done(_, nfs3_create_record) => {
                    xidmap.file_handle = nfs3_create_record.handle.value.to_vec();
                    xidmap.file_name = nfs3_create_record.name_vec;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };

        } else if r.procedure == NFSPROC3_REMOVE {
            match parse_nfs3_request_remove(r.prog_data) {
                IResult::Done(_, rr) => {
                    xidmap.file_handle = rr.handle.value.to_vec();
                    xidmap.file_name = rr.name_vec;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };

        } else if r.procedure == NFSPROC3_RENAME {
            match parse_nfs3_request_rename(r.prog_data) {
                IResult::Done(_, rr) => {
                    xidmap.file_handle = rr.from_handle.value.to_vec();
                    xidmap.file_name = rr.from_name_vec;
                    aux_file_name = rr.to_name_vec;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_MKDIR {
            match parse_nfs3_request_mkdir(r.prog_data) {
                IResult::Done(_, mr) => {
                    xidmap.file_handle = mr.handle.value.to_vec();
                    xidmap.file_name = mr.name_vec;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_RMDIR {
            match parse_nfs3_request_rmdir(r.prog_data) {
                IResult::Done(_, rr) => {
                    xidmap.file_handle = rr.handle.value.to_vec();
                    xidmap.file_name = rr.name_vec;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_COMMIT {
            SCLogDebug!("COMMIT, closing shop");

            match parse_nfs3_request_commit(r.prog_data) {
                IResult::Done(_, cr) => {
                    let file_handle = cr.handle.value.to_vec();
                    match self.get_file_tx_by_handle(&file_handle, STREAM_TOSERVER) {
                        Some((tx, files, flags)) => {
                            let tdf = match tx.type_data {
                                Some(NFSTransactionTypeData::FILE(ref mut d)) => d,
                                _ => panic!("BUG"),
                            };
                            tdf.chunk_count += 1;
                            tdf.file_additional_procs.push(NFSPROC3_COMMIT);
                            tdf.file_tracker.close(files, flags);
                            tdf.file_last_xid = r.hdr.xid;
                            tx.is_last = true;
                            tx.request_done = true;
                        },
                        None => { },
                    }
                    //self.ts_txs_updated = true;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
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
            //self.ts_txs_updated = true;

            if r.procedure == NFSPROC3_RENAME {
                tx.type_data = Some(NFSTransactionTypeData::RENAME(aux_file_name));
            }

            tx.auth_type = r.creds_flavor;
            match &r.creds_unix {
                &Some(ref u) => {
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
                match &r.creds_unix {
                    &Some(ref u) => {
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

    /// complete request record
    fn process_request_record_v2<'b>(&mut self, r: &RpcPacket<'b>) -> u32 {
        SCLogDebug!("NFSv2 REQUEST {} procedure {} ({}) blob size {}",
                r.hdr.xid, r.procedure, self.requestmap.len(), r.prog_data.len());

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);
        let aux_file_name = Vec::new();

        if r.procedure == NFSPROC3_LOOKUP {
            match parse_nfs2_request_lookup(r.prog_data) {
                IResult::Done(_, ar) => {
                    xidmap.file_handle = ar.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if r.procedure == NFSPROC3_READ {
            match parse_nfs2_request_read(r.prog_data) {
                IResult::Done(_, read_record) => {
                    xidmap.chunk_offset = read_record.offset as u64;
                    xidmap.file_handle = read_record.handle.value.to_vec();
                    self.xidmap_handle2name(&mut xidmap);
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
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
            //self.ts_txs_updated = true;

            if r.procedure == NFSPROC3_RENAME {
                tx.type_data = Some(NFSTransactionTypeData::RENAME(aux_file_name));
            }

            tx.auth_type = r.creds_flavor;
            match &r.creds_unix {
                &Some(ref u) => {
                    tx.request_machine_name = u.machine_name_buf.to_vec();
                    tx.request_uid = u.uid;
                    tx.request_gid = u.gid;
                },
                _ => { },
            }
            SCLogDebug!("NFSv2 TX created: ID {} XID {} PROCEDURE {}",
                    tx.id, tx.xid, tx.procedure);
            self.transactions.push(tx);
        }

        SCLogDebug!("NFSv2: TS creating xidmap {}", r.hdr.xid);
        self.requestmap.insert(r.hdr.xid, xidmap);
        0
    }

    fn new_file_tx(&mut self, file_handle: &Vec<u8>, file_name: &Vec<u8>, direction: u8)
        -> (&mut NFSTransaction, &mut FileContainer, u16)
    {
        let mut tx = self.new_tx();
        tx.file_name = file_name.to_vec();
        tx.file_handle = file_handle.to_vec();
        tx.is_file_tx = true;
        tx.file_tx_direction = direction;

        tx.type_data = Some(NFSTransactionTypeData::FILE(NFSTransactionFile::new()));
        match tx.type_data {
            Some(NFSTransactionTypeData::FILE(ref mut d)) => {
                d.file_tracker.tx_id = tx.id - 1;
            },
            _ => { },
        }
        SCLogDebug!("new_file_tx: TX FILE created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(file_name));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        let (files, flags) = self.files.get(direction);
        return (tx_ref.unwrap(), files, flags)
    }

    fn get_file_tx_by_handle(&mut self, file_handle: &Vec<u8>, direction: u8)
        -> Option<(&mut NFSTransaction, &mut FileContainer, u16)>
    {
        let fh = file_handle.to_vec();
        for tx in &mut self.transactions {
            if tx.is_file_tx &&
                direction == tx.file_tx_direction &&
                tx.file_handle == fh
            {
                SCLogDebug!("Found NFS file TX with ID {} XID {}", tx.id, tx.xid);
                let (files, flags) = self.files.get(direction);
                return Some((tx, files, flags));
            }
        }
        SCLogDebug!("Failed to find NFS TX with handle {:?}", file_handle);
        return None;
    }

    fn process_write_record<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs3RequestWrite<'b>) -> u32 {
        // for now assume that stable FILE_SYNC flags means a single chunk
        let is_last = if w.stable == 2 { true } else { false };

        let mut fill_bytes = 0;
        let pad = w.file_len % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }

        let file_handle = w.handle.value.to_vec();
        let file_name = match self.namemap.get(w.handle.value) {
            Some(n) => {
                SCLogDebug!("WRITE name {:?}", n);
                n.to_vec()
            },
            None => {
                SCLogDebug!("WRITE object {:?} not found", w.handle.value);
                Vec::new()
            },
        };

        let found = match self.get_file_tx_by_handle(&file_handle, STREAM_TOSERVER) {
            Some((tx, files, flags)) => {
                let ref mut tdf = match tx.type_data {
                    Some(NFSTransactionTypeData::FILE(ref mut x)) => x,
                    _ => { panic!("BUG") },
                };
                filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                        &file_name, w.file_data, w.offset,
                        w.file_len, fill_bytes as u8, is_last, &r.hdr.xid);
                tdf.chunk_count += 1;
                if is_last {
                    tdf.file_last_xid = r.hdr.xid;
                    tx.is_last = true;
                    tx.response_done = true;
                }
                true
            },
            None => { false },
        };
        if !found {
            let (tx, files, flags) = self.new_file_tx(&file_handle, &file_name, STREAM_TOSERVER);
            let ref mut tdf = match tx.type_data {
                Some(NFSTransactionTypeData::FILE(ref mut x)) => x,
                    _ => { panic!("BUG") },
            };
            filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                    &file_name, w.file_data, w.offset,
                    w.file_len, fill_bytes as u8, is_last, &r.hdr.xid);
            tx.procedure = NFSPROC3_WRITE;
            tx.xid = r.hdr.xid;
            tx.is_first = true;
            tx.nfs_version = r.progver as u16;
            if is_last {
                tdf.file_last_xid = r.hdr.xid;
                tx.is_last = true;
                tx.request_done = true;
            }
        }
        if !self.is_udp {
            self.ts_chunk_xid = r.hdr.xid;
            let file_data_len = w.file_data.len() as u32 - fill_bytes as u32;
            self.ts_chunk_left = w.file_len as u32 - file_data_len as u32;
        }
        0
    }

    fn process_partial_write_request_record<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs3RequestWrite<'b>) -> u32 {
        SCLogDebug!("REQUEST {} procedure {} blob size {}", r.hdr.xid, r.procedure, r.prog_data.len());

        if r.procedure != NFSPROC3_WRITE {
            panic!("call me for procedure WRITE *only*");
        }

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);
        xidmap.file_handle = w.handle.value.to_vec();
        self.requestmap.insert(r.hdr.xid, xidmap);

        return self.process_write_record(r, w);
    }

    fn process_reply_record_v3<'b>(&mut self, r: &RpcReplyPacket<'b>, xidmap: &mut NFSRequestXidMap) -> u32 {
        let mut nfs_status = 0;
        let mut resp_handle = Vec::new();

        if xidmap.procedure == NFSPROC3_LOOKUP {
            match parse_nfs3_response_lookup(r.prog_data) {
                IResult::Done(_, lookup) => {
                    SCLogDebug!("LOOKUP: {:?}", lookup);
                    SCLogDebug!("RESPONSE LOOKUP file_name {:?}", xidmap.file_name);

                    nfs_status = lookup.status;

                    SCLogDebug!("LOOKUP handle {:?}", lookup.handle);
                    self.namemap.insert(lookup.handle.value.to_vec(), xidmap.file_name.to_vec());
                    resp_handle = lookup.handle.value.to_vec();
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if xidmap.procedure == NFSPROC3_CREATE {
            match parse_nfs3_response_create(r.prog_data) {
                IResult::Done(_, nfs3_create_record) => {
                    SCLogDebug!("nfs3_create_record: {:?}", nfs3_create_record);

                    SCLogDebug!("RESPONSE CREATE file_name {:?}", xidmap.file_name);
                    nfs_status = nfs3_create_record.status;

                    match nfs3_create_record.handle {
                        Some(h) => {
                            SCLogDebug!("handle {:?}", h);
                            self.namemap.insert(h.value.to_vec(), xidmap.file_name.to_vec());
                            resp_handle = h.value.to_vec();
                        },
                        _ => { },
                    }

                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e);  },
            };
        } else if xidmap.procedure == NFSPROC3_READ {
            match parse_nfs3_reply_read(r.prog_data) {
                IResult::Done(_, ref reply) => {
                    self.process_read_record(r, reply, Some(&xidmap));
                    nfs_status = reply.status;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
            }
        } else if xidmap.procedure == NFSPROC3_READDIRPLUS {
            match parse_nfs3_response_readdirplus(r.prog_data) {
                IResult::Done(_, ref reply) => {
                    //SCLogDebug!("READDIRPLUS reply {:?}", reply);

                    nfs_status = reply.status;

                    // cut off final eof field
                    let d = &reply.data[..reply.data.len()-4 as usize];

                    // store all handle/filename mappings
                    match many0_nfs3_response_readdirplus_entries(d) {
                        IResult::Done(_, ref entries) => {
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
                        IResult::Incomplete(_) => {
                            self.set_event(NFSEvent::MalformedData);
                        },
                        IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                    }
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
            }
        }
        // for all other record types only parse the status
        else {
            let stat = match nom::be_u32(&r.prog_data) {
                nom::IResult::Done(_, stat) => {
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

    fn process_reply_record_v2<'b>(&mut self, r: &RpcReplyPacket<'b>, xidmap: &NFSRequestXidMap) -> u32 {
        let mut nfs_status = 0;
        let resp_handle = Vec::new();

        if xidmap.procedure == NFSPROC3_READ {
            match parse_nfs2_reply_read(r.prog_data) {
                IResult::Done(_, ref reply) => {
                    SCLogDebug!("NFSv2 READ reply record");
                    self.process_read_record(r, reply, Some(&xidmap));
                    nfs_status = reply.status;
                },
                IResult::Incomplete(_) => {
                    self.set_event(NFSEvent::MalformedData);
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
            }
        } else {
            let stat = match nom::be_u32(&r.prog_data) {
                nom::IResult::Done(_, stat) => {
                    stat as u32
                }
                _ => 0 as u32
            };
            nfs_status = stat;
        }
        SCLogDebug!("REPLY {} to procedure {} blob size {}",
                r.hdr.xid, xidmap.procedure, r.prog_data.len());

        self.mark_response_tx_done(r.hdr.xid, r.reply_state, nfs_status, &resp_handle);

        0
    }

    fn process_reply_record<'b>(&mut self, r: &RpcReplyPacket<'b>) -> u32 {
        let mut xidmap;
        match self.requestmap.remove(&r.hdr.xid) {
            Some(p) => { xidmap = p; },
            _ => {
                SCLogDebug!("REPLY: xid {} NOT FOUND. GAPS? TS:{} TC:{}",
                        r.hdr.xid, self.ts_ssn_gap, self.tc_ssn_gap);

                // TODO we might be able to try to infer from the size + data
                // that this is a READ reply and pass the data to the file API anyway?
                return 0;
            },
        }

        if self.nfs_version == 0 {
            self.nfs_version = xidmap.progver as u16;
        }

        match xidmap.progver {
            3 => {
                SCLogDebug!("NFSv3 reply record");
                return self.process_reply_record_v3(r, &mut xidmap);
            },
            2 => {
                SCLogDebug!("NFSv2 reply record");
                return self.process_reply_record_v2(r, &xidmap);
            },
            _ => { panic!("unsupported NFS version"); },
        }
    }

    // update in progress chunks for file transfers
    // return how much data we consumed
    fn filetracker_update(&mut self, direction: u8, data: &[u8], gap_size: u32) -> u32 {
        let mut chunk_left = if direction == STREAM_TOSERVER {
            self.ts_chunk_left
        } else {
            self.tc_chunk_left
        };
        if chunk_left == 0 {
            return 0
        }
        let xid = if direction == STREAM_TOSERVER {
            self.ts_chunk_xid
        } else {
            self.tc_chunk_xid
        };
        SCLogDebug!("chunk left {}, input {}", chunk_left, data.len());

        let file_handle;
        // we have the data that we expect
        if chunk_left <= data.len() as u32 {
            chunk_left = 0;

            if direction == STREAM_TOSERVER {
                self.ts_chunk_xid = 0;

                // see if we have a file handle to work on
                match self.requestmap.get(&xid) {
                    None => {
                        SCLogDebug!("no file handle found for XID {:04X}", xid);
                        return 0
                    },
                    Some(ref xidmap) => {
                        file_handle = xidmap.file_handle.to_vec();
                    },
                }
            } else {
                self.tc_chunk_xid = 0;

                // chunk done, remove requestmap entry
                match self.requestmap.remove(&xid) {
                    None => {
                        SCLogDebug!("no file handle found for XID {:04X}", xid);
                        return 0
                    },
                    Some(xidmap) => {
                        file_handle = xidmap.file_handle.to_vec();
                    },
                }
            }
        } else {
            chunk_left -= data.len() as u32;

            // see if we have a file handle to work on
            match self.requestmap.get(&xid) {
                None => {
                    SCLogDebug!("no file handle found for XID {:04X}", xid);
                    return 0 },
                Some(xidmap) => {
                    file_handle = xidmap.file_handle.to_vec();
                },
            }
        }

        if direction == STREAM_TOSERVER {
            self.ts_chunk_left = chunk_left;
        } else {
            self.tc_chunk_left = chunk_left;
        }

        let ssn_gap = self.ts_ssn_gap | self.tc_ssn_gap;
        // get the tx and update it
        let consumed = match self.get_file_tx_by_handle(&file_handle, direction) {
            Some((tx, files, flags)) => {
                let ref mut tdf = match tx.type_data {
                    Some(NFSTransactionTypeData::FILE(ref mut x)) => x,
                    _ => { panic!("BUG") },
                };
                if ssn_gap {
                    let queued_data = tdf.file_tracker.get_queued_size();
                    if queued_data > 2000000 { // TODO should probably be configurable
                        SCLogDebug!("QUEUED size {} while we've seen GAPs. Truncating file.", queued_data);
                        tdf.file_tracker.trunc(files, flags);
                    }
                }

                tdf.chunk_count += 1;
                let cs = tdf.file_tracker.update(files, flags, data, gap_size);
                cs
            },
            None => { 0 },
        };
        return consumed;
    }

    /// xidmapr is an Option as it's already removed from the map if we
    /// have a complete record. Otherwise we do a lookup ourselves.
    fn process_read_record<'b>(&mut self, r: &RpcReplyPacket<'b>,
            reply: &NfsReplyRead<'b>, xidmapr: Option<&NFSRequestXidMap>) -> u32
    {
        let file_name;
        let file_handle;
        let chunk_offset;
        let nfs_version;

        match xidmapr {
            Some(xidmap) => {
                file_name = xidmap.file_name.to_vec();
                file_handle = xidmap.file_handle.to_vec();
                chunk_offset = xidmap.chunk_offset;
                nfs_version = xidmap.progver;
            },
            None => {
                match self.requestmap.get(&r.hdr.xid) {
                    Some(xidmap) => {
                        file_name = xidmap.file_name.to_vec();
                        file_handle = xidmap.file_handle.to_vec();
                        chunk_offset = xidmap.chunk_offset;
                        nfs_version = xidmap.progver;
                    },
                    _ => { panic!("REPLY: xid {} NOT FOUND", r.hdr.xid); },
                }
            },
        }

        let mut is_last = reply.eof;
        let mut fill_bytes = 0;
        let pad = reply.count % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }
        SCLogDebug!("XID {} fill_bytes {} reply.count {} reply.data_len {} reply.data.len() {}", r.hdr.xid, fill_bytes, reply.count, reply.data_len, reply.data.len());

        if nfs_version == 2 {
            let size = match parse_nfs2_attribs(reply.attr_blob) {
                IResult::Done(_, ref attr) => {
                    attr.asize
                },
                _ => { 0 },
            };
            SCLogDebug!("NFSv2 READ reply record: File size {}. Offset {} data len {}: total {}",
                    size, chunk_offset, reply.data_len, chunk_offset + reply.data_len as u64);

            if size as u64 == chunk_offset + reply.data_len as u64 {
                is_last = true;
            }

        }

        let found = match self.get_file_tx_by_handle(&file_handle, STREAM_TOCLIENT) {
            Some((tx, files, flags)) => {
                let ref mut tdf = match tx.type_data {
                    Some(NFSTransactionTypeData::FILE(ref mut x)) => x,
                    _ => { panic!("BUG") },
                };
                filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                        &file_name, reply.data, chunk_offset,
                        reply.count, fill_bytes as u8, reply.eof, &r.hdr.xid);
                tdf.chunk_count += 1;
                if is_last {
                    tdf.file_last_xid = r.hdr.xid;
                    tx.rpc_response_status = r.reply_state;
                    tx.nfs_response_status = reply.status;
                    tx.is_last = true;
                    tx.response_done = true;
                }
                true
            },
            None => { false },
        };
        if !found {
            let (tx, files, flags) = self.new_file_tx(&file_handle, &file_name, STREAM_TOCLIENT);
            let ref mut tdf = match tx.type_data {
                Some(NFSTransactionTypeData::FILE(ref mut x)) => x,
                _ => { panic!("BUG") },
            };
            filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                    &file_name, reply.data, chunk_offset,
                    reply.count, fill_bytes as u8, reply.eof, &r.hdr.xid);
            tx.procedure = NFSPROC3_READ;
            tx.xid = r.hdr.xid;
            tx.is_first = true;
            if is_last {
                tdf.file_last_xid = r.hdr.xid;
                tx.rpc_response_status = r.reply_state;
                tx.nfs_response_status = reply.status;
                tx.is_last = true;
                tx.response_done = true;
            }
        }

        //if is_last {
        //    self.tc_txs_updated = true;
        //}
        if !self.is_udp {
            self.tc_chunk_xid = r.hdr.xid;
            self.tc_chunk_left = (reply.count as u32 + fill_bytes) - reply.data.len() as u32;
        }

        SCLogDebug!("REPLY {} to procedure {} blob size {} / {}: chunk_left {}",
                r.hdr.xid, NFSPROC3_READ, r.prog_data.len(), reply.count, self.tc_chunk_left);
        0
    }

    fn process_partial_read_reply_record<'b>(&mut self, r: &RpcReplyPacket<'b>, reply: &NfsReplyRead<'b>) -> u32 {
        SCLogDebug!("REPLY {} to procedure READ blob size {} / {}",
                r.hdr.xid, r.prog_data.len(), reply.count);

        return self.process_read_record(r, reply, None);
    }

    fn peek_reply_record(&mut self, r: &RpcPacketHeader) -> u32 {
        let xidmap;
        match self.requestmap.get(&r.xid) {
            Some(p) => { xidmap = p; },
            _ => { SCLogDebug!("REPLY: xid {} NOT FOUND", r.xid); return 0; },
        }

        xidmap.procedure
    }

    pub fn parse_tcp_data_ts_gap<'b>(&mut self, gap_size: u32) -> u32 {
        if self.tcp_buffer_ts.len() > 0 {
            self.tcp_buffer_ts.clear();
        }
        let gap = vec![0; gap_size as usize];
        let consumed = self.filetracker_update(STREAM_TOSERVER, &gap, gap_size);
        if consumed > gap_size {
            panic!("consumed more than GAP size: {} > {}", consumed, gap_size);
        }
        self.ts_ssn_gap = true;
        self.ts_gap = true;
        return 0
    }

    pub fn parse_tcp_data_tc_gap<'b>(&mut self, gap_size: u32) -> u32 {
        if self.tcp_buffer_tc.len() > 0 {
            self.tcp_buffer_tc.clear();
        }
        let gap = vec![0; gap_size as usize];
        let consumed = self.filetracker_update(STREAM_TOCLIENT, &gap, gap_size);
        if consumed > gap_size {
            panic!("consumed more than GAP size: {} > {}", consumed, gap_size);
        }
        self.tc_ssn_gap = true;
        self.tc_gap = true;
        return 0
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_ts<'b>(&mut self, i: &'b[u8]) -> u32 {
        let mut v : Vec<u8>;
        let mut status = 0;
        SCLogDebug!("parse_tcp_data_ts ({})",i.len());
        //SCLogDebug!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer_ts.len() {
            0 => i,
            _ => {
                v = self.tcp_buffer_ts.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                if self.tcp_buffer_ts.len() + i.len() > 1000000 {
                    SCLogDebug!("parse_tcp_data_ts: TS buffer exploded {} {}",
                            self.tcp_buffer_ts.len(), i.len());
                    return 1;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        //SCLogDebug!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        if cur_i.len() > 1000000 {
            SCLogDebug!("BUG buffer exploded: {}", cur_i.len());
        }
        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(STREAM_TOSERVER, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 { panic!("BUG consumed more than we gave it"); }
            cur_i = &cur_i[consumed as usize..];
        }
        if self.ts_gap {
            SCLogDebug!("TS trying to catch up after GAP (input {})", cur_i.len());

            let mut cnt = 0;
            while cur_i.len() > 0 {
                cnt += 1;
                match nfs3_probe(cur_i, STREAM_TOSERVER) {
                    1 => {
                        SCLogDebug!("expected data found");
                        self.ts_gap = false;
                        break;
                    },
                    0 => {
                        SCLogDebug!("incomplete, queue and retry with the next block (input {}). Looped {} times.", cur_i.len(), cnt);
                        self.tcp_buffer_tc.extend_from_slice(cur_i);
                        return 0;
                    },
                    -1 => {
                        cur_i = &cur_i[1..];
                        if cur_i.len() == 0 {
                            SCLogDebug!("all post-GAP data in this chunk was bad. Looped {} times.", cnt);
                        }
                    },
                    _ => { panic!("hell just froze over"); },
                }
            }
            SCLogDebug!("TS GAP handling done (input {})", cur_i.len());
        }

        while cur_i.len() > 0 { // min record size
            match parse_rpc_request_partial(cur_i) {
                IResult::Done(_, ref rpc_phdr) => {
                    let rec_size = (rpc_phdr.hdr.frag_len + 4) as usize;
                    //SCLogDebug!("rec_size {}/{}", rec_size, cur_i.len());
                    //SCLogDebug!("cur_i {:?}", cur_i);

                    if rec_size > cur_i.len() {
                        // special case: avoid buffering file write blobs
                        // as these can be large.
                        if rec_size >= 512 && cur_i.len() >= 44 {
                            // large record, likely file xfer
                            SCLogDebug!("large record {}, likely file xfer", rec_size);

                            // quick peek, are in WRITE mode?
                            if rpc_phdr.procedure == NFSPROC3_WRITE {
                                SCLogDebug!("CONFIRMED WRITE: large record {}, file chunk xfer", rec_size);

                                // lets try to parse the RPC record. Might fail with Incomplete.
                                match parse_rpc(cur_i) {
                                    IResult::Done(remaining, ref rpc_record) => {
                                        match parse_nfs3_request_write(rpc_record.prog_data) {
                                            IResult::Done(_, ref nfs_request_write) => {
                                                // deal with the partial nfs write data
                                                status |= self.process_partial_write_request_record(rpc_record, nfs_request_write);
                                                cur_i = remaining; // progress input past parsed record
                                            },
                                            IResult::Incomplete(_) => {
                                                self.set_event(NFSEvent::MalformedData);
                                            },
                                            IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                        }
                                    },
                                    IResult::Incomplete(_) => {
                                        // we just size checked for the minimal record size above,
                                        // so if options are used (creds/verifier), we can still
                                        // have Incomplete data. Fall through to the buffer code
                                        // and try again on our next iteration.
                                        SCLogDebug!("TS data incomplete");
                                    },
                                    IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                }
                            }
                        }
                        self.tcp_buffer_ts.extend_from_slice(cur_i);
                        break;
                    }

                    // we have the full records size worth of data,
                    // let's parse it
                    match parse_rpc(&cur_i[..rec_size]) {
                        IResult::Done(_, ref rpc_record) => {
                            cur_i = &cur_i[rec_size..];
                            status |= self.process_request_record(rpc_record);
                        },
                        IResult::Incomplete(_) => {
                            cur_i = &cur_i[rec_size..]; // progress input past parsed record

                            // we shouldn't get incomplete as we have the full data
                            // so if we got incomplete anyway it's the data that is
                            // bad.
                            self.set_event(NFSEvent::MalformedData);

                            status = 1;
                        },
                        IResult::Error(e) => { panic!("Parsing failed: {:?}",e); //break
                        },
                    }
                },
                IResult::Incomplete(_) => {
                    SCLogDebug!("Fragmentation required (TCP level) 2");
                    self.tcp_buffer_ts.extend_from_slice(cur_i);
                    break;
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); //break
                },
            }
        };
        status
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_tc<'b>(&mut self, i: &'b[u8]) -> u32 {
        let mut v : Vec<u8>;
        let mut status = 0;
        SCLogDebug!("parse_tcp_data_tc ({})",i.len());
        //SCLogDebug!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer_tc.len() {
            0 => i,
            _ => {
                v = self.tcp_buffer_tc.split_off(0);
                // sanity check vector length to avoid memory exhaustion
                if self.tcp_buffer_tc.len() + i.len() > 100000 {
                    SCLogDebug!("TC buffer exploded");
                    return 1;
                };

                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        SCLogDebug!("TC tcp_buffer ({}), input ({})",tcp_buffer.len(), i.len());

        let mut cur_i = tcp_buffer;
        if cur_i.len() > 100000 {
            SCLogDebug!("parse_tcp_data_tc: BUG buffer exploded {}", cur_i.len());
        }

        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(STREAM_TOCLIENT, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 { panic!("BUG consumed more than we gave it"); }
            cur_i = &cur_i[consumed as usize..];
        }
        if self.tc_gap {
            SCLogDebug!("TC trying to catch up after GAP (input {})", cur_i.len());

            let mut cnt = 0;
            while cur_i.len() > 0 {
                cnt += 1;
                match nfs3_probe(cur_i, STREAM_TOCLIENT) {
                    1 => {
                        SCLogDebug!("expected data found");
                        self.tc_gap = false;
                        break;
                    },
                    0 => {
                        SCLogDebug!("incomplete, queue and retry with the next block (input {}). Looped {} times.", cur_i.len(), cnt);
                        self.tcp_buffer_tc.extend_from_slice(cur_i);
                        return 0;
                    },
                    -1 => {
                        cur_i = &cur_i[1..];
                        if cur_i.len() == 0 {
                            SCLogDebug!("all post-GAP data in this chunk was bad. Looped {} times.", cnt);
                        }
                    },
                    _ => { panic!("hell just froze over"); },
                }
            }
            SCLogDebug!("TC GAP handling done (input {})", cur_i.len());
        }

        while cur_i.len() > 0 {
            match parse_rpc_packet_header(cur_i) {
                IResult::Done(_, ref rpc_hdr) => {
                    let rec_size = (rpc_hdr.frag_len + 4) as usize;
                    // see if we have all data available
                    if rec_size > cur_i.len() {
                        // special case: avoid buffering file read blobs
                        // as these can be large.
                        if rec_size >= 512 && cur_i.len() >= 128 {//36 {
                            // large record, likely file xfer
                            SCLogDebug!("large record {}, likely file xfer", rec_size);

                            // quick peek, are in READ mode?
                            if self.peek_reply_record(&rpc_hdr) == NFSPROC3_READ {
                                SCLogDebug!("CONFIRMED large READ record {}, likely file chunk xfer", rec_size);

                                // we should have enough data to parse the RPC record
                                match parse_rpc_reply(cur_i) {
                                    IResult::Done(remaining, ref rpc_record) => {
                                        match parse_nfs3_reply_read(rpc_record.prog_data) {
                                            IResult::Done(_, ref nfs_reply_read) => {
                                                // deal with the partial nfs read data
                                                status |= self.process_partial_read_reply_record(rpc_record, nfs_reply_read);
                                                cur_i = remaining; // progress input past parsed record
                                            },
                                            IResult::Incomplete(_) => {
                                                self.set_event(NFSEvent::MalformedData);
                                            },
                                            IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                        }
                                    },
                                    IResult::Incomplete(_) => {
                                        // size check was done for MINIMAL record size,
                                        // so Incomplete is normal.
                                        SCLogDebug!("TC data incomplete");
                                    },
                                    IResult::Error(e) => { panic!("Parsing failed: {:?}",e); },
                                }
                            }
                        }
                        self.tcp_buffer_tc.extend_from_slice(cur_i);
                        break;
                    }

                    // we have the full data of the record, lets parse
                    match parse_rpc_reply(&cur_i[..rec_size]) {
                        IResult::Done(_, ref rpc_record) => {
                            cur_i = &cur_i[rec_size..]; // progress input past parsed record
                            status |= self.process_reply_record(rpc_record);
                        },
                        IResult::Incomplete(_) => {
                            cur_i = &cur_i[rec_size..]; // progress input past parsed record

                            // we shouldn't get incomplete as we have the full data
                            // so if we got incomplete anyway it's the data that is
                            // bad.
                            self.set_event(NFSEvent::MalformedData);

                            status = 1;
                        },
                        IResult::Error(e) => { panic!("Parsing failed: {:?}",e); //break
                        },
                    }
                },
                IResult::Incomplete(_) => {
                    SCLogDebug!("REPLY: insufficient data for HDR");
                    self.tcp_buffer_tc.extend_from_slice(cur_i);
                    break;
                },
                IResult::Error(e) => { SCLogDebug!("Parsing failed: {:?}",e); break },
            }
        };
        status
    }
    /// Parsing function
    pub fn parse_udp_ts<'b>(&mut self, input: &'b[u8]) -> u32 {
        let mut status = 0;
        SCLogDebug!("parse_udp_ts ({})", input.len());
        if input.len() > 0 {
            match parse_rpc_udp_request(input) {
                IResult::Done(_, ref rpc_record) => {
                    self.is_udp = true;
                    match rpc_record.progver {
                        3 => {
                            status |= self.process_request_record(rpc_record);
                        },
                        2 => {
                            status |= self.process_request_record_v2(rpc_record);
                        },
                        _ => { panic!("unsupported NFS version"); },
                    }
                },
                IResult::Incomplete(_) => {
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); //break
                },
            }
        }
        status
    }

    /// Parsing function
    pub fn parse_udp_tc<'b>(&mut self, input: &'b[u8]) -> u32 {
        let mut status = 0;
        SCLogDebug!("parse_udp_tc ({})", input.len());
        if input.len() > 0 {
            match parse_rpc_udp_reply(input) {
                IResult::Done(_, ref rpc_record) => {
                    self.is_udp = true;
                    status |= self.process_reply_record(rpc_record);
                },
                IResult::Incomplete(_) => {
                },
                IResult::Error(e) => { panic!("Parsing failed: {:?}",e); //break
                },
            }
        };
        status
    }
    fn getfiles(&mut self, direction: u8) -> * mut FileContainer {
        //SCLogDebug!("direction: {}", direction);
        if direction == STREAM_TOCLIENT {
            &mut self.files.files_tc as *mut FileContainer
        } else {
            &mut self.files.files_ts as *mut FileContainer
        }
    }
    fn setfileflags(&mut self, direction: u8, flags: u16) {
        SCLogDebug!("direction: {}, flags: {}", direction, flags);
        if direction == 1 {
            self.files.flags_tc = flags;
        } else {
            self.files.flags_ts = flags;
        }
    }
}

/// Returns *mut NFSState
#[no_mangle]
pub extern "C" fn rs_nfs3_state_new() -> *mut libc::c_void {
    let state = NFSState::new();
    let boxed = Box::new(state);
    SCLogDebug!("allocating state");
    return unsafe{transmute(boxed)};
}

/// Params:
/// - state: *mut NFSState as void pointer
#[no_mangle]
pub extern "C" fn rs_nfs3_state_free(state: *mut libc::c_void) {
    // Just unbox...
    SCLogDebug!("freeing state");
    let mut nfs3_state: Box<NFSState> = unsafe{transmute(state)};
    nfs3_state.free();
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_nfs3_parse_request(_flow: *mut Flow,
                                       state: &mut NFSState,
                                       _pstate: *mut libc::c_void,
                                       input: *mut libc::uint8_t,
                                       input_len: libc::uint32_t,
                                       _data: *mut libc::c_void)
                                       -> libc::int8_t
{
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    SCLogDebug!("parsing {} bytes of request data", input_len);

    if buf.as_ptr().is_null() && input_len > 0 {
        if state.parse_tcp_data_ts_gap(input_len as u32) == 0 {
            return 1
        }
        return -1
    }

    if state.parse_tcp_data_ts(buf) == 0 {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs3_parse_response(_flow: *mut Flow,
                                        state: &mut NFSState,
                                        _pstate: *mut libc::c_void,
                                        input: *mut libc::uint8_t,
                                        input_len: libc::uint32_t,
                                        _data: *mut libc::c_void)
                                        -> libc::int8_t
{
    SCLogDebug!("parsing {} bytes of response data", input_len);
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};

    if buf.as_ptr().is_null() && input_len > 0 {
        if state.parse_tcp_data_tc_gap(input_len as u32) == 0 {
            return 1
        }
        return -1
    }

    if state.parse_tcp_data_tc(buf) == 0 {
        1
    } else {
        -1
    }
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_nfs3_parse_request_udp(_flow: *mut Flow,
                                       state: &mut NFSState,
                                       _pstate: *mut libc::c_void,
                                       input: *mut libc::uint8_t,
                                       input_len: libc::uint32_t,
                                       _data: *mut libc::c_void)
                                       -> libc::int8_t
{
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    SCLogDebug!("parsing {} bytes of request data", input_len);

    if state.parse_udp_ts(buf) == 0 {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs3_parse_response_udp(_flow: *mut Flow,
                                        state: &mut NFSState,
                                        _pstate: *mut libc::c_void,
                                        input: *mut libc::uint8_t,
                                        input_len: libc::uint32_t,
                                        _data: *mut libc::c_void)
                                        -> libc::int8_t
{
    SCLogDebug!("parsing {} bytes of response data", input_len);
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};

    if state.parse_udp_tc(buf) == 0 {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs3_state_get_tx_count(state: &mut NFSState)
                                            -> libc::uint64_t
{
    SCLogDebug!("rs_nfs3_state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_nfs3_state_get_tx(state: &mut NFSState,
                                      tx_id: libc::uint64_t)
                                      -> *mut NFSTransaction
{
    match state.get_tx_by_id(tx_id) {
        Some(tx) => {
            return unsafe{transmute(tx)};
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs3_state_tx_free(state: &mut NFSState,
                                       tx_id: libc::uint64_t)
{
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_nfs3_state_progress_completion_status(
    _direction: libc::uint8_t)
    -> libc::c_int
{
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_nfs3_tx_get_alstate_progress(tx: &mut NFSTransaction,
                                                  direction: libc::uint8_t)
                                                  -> libc::uint8_t
{
    if direction == STREAM_TOSERVER && tx.request_done {
        //SCLogNotice!("TOSERVER progress 1");
        return 1;
    } else if direction == STREAM_TOCLIENT && tx.response_done {
        //SCLogNotice!("TOCLIENT progress 1");
        return 1;
    } else {
        //SCLogNotice!("{} progress 0", direction);
        return 0;
    }
}

/*
#[no_mangle]
pub extern "C" fn rs_nfs3_get_txs_updated(state: &mut NFSState,
                                          direction: u8) -> bool
{
    if direction == STREAM_TOSERVER {
        return state.ts_txs_updated;
    } else {
        return state.tc_txs_updated;
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs3_reset_txs_updated(state: &mut NFSState,
                                            direction: u8)
{
    if direction == STREAM_TOSERVER {
        state.ts_txs_updated = false;
    } else {
        state.tc_txs_updated = false;
    }
}
*/

#[no_mangle]
pub extern "C" fn rs_nfs3_tx_set_logged(_state: &mut NFSState,
                                       tx: &mut NFSTransaction,
                                       logger: libc::uint32_t)
{
    tx.logged.set_logged(logger);
}

#[no_mangle]
pub extern "C" fn rs_nfs3_tx_get_logged(_state: &mut NFSState,
                                       tx: &mut NFSTransaction,
                                       logger: libc::uint32_t)
                                       -> i8
{
    if tx.logged.is_logged(logger) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_nfs3_state_has_detect_state(state: &mut NFSState) -> u8
{
    if state.de_state_count > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_nfs3_state_set_tx_detect_state(
    state: &mut NFSState,
    tx: &mut NFSTransaction,
    de_state: &mut DetectEngineState)
{
    state.de_state_count += 1;
    tx.de_state = Some(de_state);
}

#[no_mangle]
pub extern "C" fn rs_nfs3_state_get_tx_detect_state(
    tx: &mut NFSTransaction)
    -> *mut DetectEngineState
{
    match tx.de_state {
        Some(ds) => {
            return ds;
        },
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_has_events(state: &mut NFSState) -> u8 {
    if state.events > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_get_events(state: &mut NFSState,
                                          tx_id: libc::uint64_t)
                                          -> *mut AppLayerDecoderEvents
{
    match state.get_tx_by_id(tx_id) {
        Some(tx) => {
            return tx.events;
        }
        _ => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_get_event_info(event_name: *const libc::c_char,
                                              event_id: *mut libc::c_int,
                                              event_type: *mut AppLayerEventType)
                                              -> i8
{
    if event_name == std::ptr::null() {
        return -1;
    }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "malformed_data" => NFSEvent::MalformedData as i32,
                _ => -1, // unknown event
            }
        },
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe{
        *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as libc::c_int;
    };
    0
}

/// return procedure(s) in the tx. At 0 return the main proc,
/// otherwise get procs from the 'file_additional_procs'.
/// Keep calling until 0 is returned.
#[no_mangle]
pub extern "C" fn rs_nfs3_tx_get_procedures(tx: &mut NFSTransaction,
                                       i: libc::uint16_t,
                                       procedure: *mut libc::uint32_t)
                                       -> libc::uint8_t
{
    if i == 0 {
        unsafe {
            *procedure = tx.procedure as libc::uint32_t;
        }
        return 1;
    }

    if !tx.is_file_tx {
        return 0;
    }

    /* file tx handling follows */

    let ref tdf = match tx.type_data {
        Some(NFSTransactionTypeData::FILE(ref x)) => x,
        _ => { panic!("BUG") },
    };

    let idx = i as usize - 1;
    if idx < tdf.file_additional_procs.len() {
        let p = tdf.file_additional_procs[idx];
        unsafe {
            *procedure = p as libc::uint32_t;
        }
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_nfs_tx_get_version(tx: &mut NFSTransaction,
                                       version: *mut libc::uint32_t)
{
    unsafe {
        *version = tx.nfs_version as libc::uint32_t;
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs3_init(context: &'static mut SuricataFileContext)
{
    unsafe {
        SURICATA_NFS3_FILE_CONFIG = Some(context);
    }
}

pub fn nfs3_probe(i: &[u8], direction: u8) -> i8 {
    if direction == STREAM_TOCLIENT {
        match parse_rpc_reply(i) {
            IResult::Done(_, ref rpc) => {
                if rpc.hdr.frag_len >= 24 && rpc.hdr.frag_len <= 35000 && rpc.hdr.msgtype == 1 && rpc.reply_state == 0 && rpc.accept_state == 0 {
                    SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc.hdr.frag_len, rpc.hdr.xid, rpc.hdr.msgtype);
                    return 1;
                } else {
                    return -1;
                }
            },
            IResult::Incomplete(_) => {
                match parse_rpc_packet_header (i) {
                    IResult::Done(_, ref rpc_hdr) => {
                        if rpc_hdr.frag_len >= 24 && rpc_hdr.frag_len <= 35000 && rpc_hdr.xid != 0 && rpc_hdr.msgtype == 1 {
                            SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc_hdr.frag_len, rpc_hdr.xid, rpc_hdr.msgtype);
                            return 1;
                        } else {
                            return -1;
                        }
                    },
                    IResult::Incomplete(_) => { },
                    IResult::Error(_) => {
                        return -1;
                    },
                }


                return 0;
            },
            IResult::Error(_) => {
                return -1;
            },
        }
    } else {
        match parse_rpc(i) {
            IResult::Done(_, ref rpc) => {
                if rpc.hdr.frag_len >= 40 && rpc.hdr.msgtype == 0 &&
                   rpc.rpcver == 2 && rpc.progver == 3 && rpc.program == 100003 &&
                   rpc.procedure <= NFSPROC3_COMMIT
                {
                    return 1;
                } else {
                    return -1;
                }
            },
            IResult::Incomplete(_) => {
                return 0;
            },
            IResult::Error(_) => {
                return -1;
            },
        }
    }
}

pub fn nfs3_probe_udp(i: &[u8], direction: u8) -> i8 {
    if direction == STREAM_TOCLIENT {
        match parse_rpc_udp_reply(i) {
            IResult::Done(_, ref rpc) => {
                if i.len() >= 32 && rpc.hdr.msgtype == 1 && rpc.reply_state == 0 && rpc.accept_state == 0 {
                    SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc.hdr.frag_len, rpc.hdr.xid, rpc.hdr.msgtype);
                    return 1;
                } else {
                    return -1;
                }
            },
            IResult::Incomplete(_) => {
                return -1;
            },
            IResult::Error(_) => {
                return -1;
            },
        }
    } else {
        match parse_rpc_udp_request(i) {
            IResult::Done(_, ref rpc) => {
                if i.len() >= 48 && rpc.hdr.msgtype == 0 && rpc.progver == 3 && rpc.program == 100003 {
                    return 1;
                } else if i.len() >= 48 && rpc.hdr.msgtype == 0 && rpc.progver == 2 && rpc.program == 100003 {
                    SCLogDebug!("NFSv2!");
                    return 1;
                } else {
                    return -1;
                }
            },
            IResult::Incomplete(_) => {
                return -1;
            },
            IResult::Error(_) => {
                return -1;
            },
        }
    }
}

/// TOSERVER probe function
#[no_mangle]
pub extern "C" fn rs_nfs_probe_ts(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::int8_t
{
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };
    return nfs3_probe(slice, STREAM_TOSERVER);
}
/// TOCLIENT probe function
#[no_mangle]
pub extern "C" fn rs_nfs_probe_tc(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::int8_t
{
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };
    return nfs3_probe(slice, STREAM_TOCLIENT);
}

/// TOSERVER probe function
#[no_mangle]
pub extern "C" fn rs_nfs_probe_udp_ts(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::int8_t
{
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };
    return nfs3_probe_udp(slice, STREAM_TOSERVER);
}
/// TOCLIENT probe function
#[no_mangle]
pub extern "C" fn rs_nfs_probe_udp_tc(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::int8_t
{
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };
    return nfs3_probe_udp(slice, STREAM_TOCLIENT);
}

#[no_mangle]
pub extern "C" fn rs_nfs3_getfiles(direction: u8, ptr: *mut NFSState) -> * mut FileContainer {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    parser.getfiles(direction)
}
#[no_mangle]
pub extern "C" fn rs_nfs3_setfileflags(direction: u8, ptr: *mut NFSState, flags: u16) {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    SCLogDebug!("direction {} flags {}", direction, flags);
    parser.setfileflags(direction, flags)
}
