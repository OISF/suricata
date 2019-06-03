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

use std;
use std::mem::transmute;
use std::collections::{HashMap};
use std::ffi::CStr;

use nom;

use log::*;
use applayer;
use applayer::LoggerFlags;
use core::*;
use filetracker::*;
use filecontainer::*;

use nfs::types::*;
use nfs::rpc_records::*;
use nfs::nfs_records::*;
use nfs::nfs2_records::*;
use nfs::nfs3_records::*;

pub static mut SURICATA_NFS_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

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
    NonExistingVersion = 1,
    UnsupportedVersion = 2,
}

impl NFSEvent {
    fn from_i32(value: i32) -> Option<NFSEvent> {
        match value {
            0 => Some(NFSEvent::MalformedData),
            1 => Some(NFSEvent::NonExistingVersion),
            2 => Some(NFSEvent::UnsupportedVersion),
            _ => None,
        }
    }
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
    pub xid: u32,   /// nfs req/reply pair id
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
    pub request_done: bool,
    pub response_done: bool,

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

    detect_flags_ts: u64,
    detect_flags_tc: u64,

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
            detect_flags_ts: 0,
            detect_flags_tc: 0,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        match self.de_state {
            Some(state) => {
                sc_detect_engine_state_free(state);
            }
            _ => {}
        }
    }
}

impl Drop for NFSTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

#[derive(Debug)]
pub struct NFSRequestXidMap {
    pub progver: u32,
    pub procedure: u32,
    pub chunk_offset: u64,
    pub file_name:Vec<u8>,

    /// READ replies can use this to get to the handle the request used
    pub file_handle:Vec<u8>,

    pub gssapi_proc: u32,
    pub gssapi_service: u32,
}

impl NFSRequestXidMap {
    pub fn new(progver: u32, procedure: u32, chunk_offset: u64) -> NFSRequestXidMap {
        NFSRequestXidMap {
            progver:progver,
            procedure:procedure,
            chunk_offset:chunk_offset,
            file_name:Vec::new(),
            file_handle:Vec::new(),
            gssapi_proc: 0,
            gssapi_service: 0,
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
pub fn filetracker_newchunk(ft: &mut FileTransferTracker, files: &mut FileContainer,
        flags: u16, name: &Vec<u8>, data: &[u8],
        chunk_offset: u64, chunk_size: u32, fill_bytes: u8, is_last: bool, xid: &u32)
{
    match unsafe {SURICATA_NFS_FILE_CONFIG} {
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
    pub ts_chunk_xid: u32,
    pub tc_chunk_xid: u32,
    /// size of the current chunk that we still need to receive
    pub ts_chunk_left: u32,
    pub tc_chunk_left: u32,
    /// file handle of in progress toserver WRITE file chunk
    ts_chunk_fh: Vec<u8>,

    ts_ssn_gap: bool,
    tc_ssn_gap: bool,

    ts_gap: bool, // last TS update was gap
    tc_gap: bool, // last TC update was gap

    is_udp: bool,

    pub nfs_version: u16,

    pub events: u16,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,
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
            ts_chunk_fh:Vec::new(),
            ts_ssn_gap:false,
            tc_ssn_gap:false,
            ts_gap:false,
            tc_gap:false,
            is_udp:false,
            nfs_version:0,
            events:0,
            tx_id:0,
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
            self.transactions.remove(index);
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
                SCLogDebug!("Found NFS TX with ID {} XID {:04X}", tx.id, tx.xid);
                return Some(tx);
            }
        }
        SCLogDebug!("Failed to find NFS TX with XID {:04X}", tx_xid);
        return None;
    }

    // for use with the C API call StateGetTxIterator
    pub fn get_tx_iterator(&mut self, min_tx_id: u64, state: &mut u64) ->
        Option<(&NFSTransaction, u64, bool)>
    {
        let mut index = *state as usize;
        let len = self.transactions.len();

        // find tx that is >= min_tx_id
        while index < len {
            let tx = &self.transactions[index];
            if tx.id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            // store current index in the state and not the next
            // as transactions might be freed between now and the
            // next time we are called.
            *state = index as u64;
            SCLogDebug!("returning tx_id {} has_next? {} (len {} index {}), tx {:?}",
                    tx.id - 1, (len - index) > 1, len, index, tx);
            return Some((tx, tx.id - 1, (len - index) > 1));
        }
        return None;
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: NFSEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let tx = &mut self.transactions[len - 1];
        sc_app_layer_decoder_events_set_event_raw(&mut tx.events, event as u8);
        self.events += 1;
    }

    // TODO maybe not enough users to justify a func
    pub fn mark_response_tx_done(&mut self, xid: u32, rpc_status: u32, nfs_status: u32, resp_handle: &Vec<u8>)
    {
        match self.get_tx_by_xid(xid) {
            Some(mytx) => {
                mytx.response_done = true;
                mytx.rpc_response_status = rpc_status;
                mytx.nfs_response_status = nfs_status;
                if mytx.file_handle.len() == 0 && resp_handle.len() > 0 {
                    mytx.file_handle = resp_handle.to_vec();
                }

                SCLogDebug!("process_reply_record: tx ID {} XID {:04X} REQUEST {} RESPONSE {}",
                        mytx.id, mytx.xid, mytx.request_done, mytx.response_done);
            },
            None => {
                //SCLogNotice!("process_reply_record: not TX found for XID {}", r.hdr.xid);
            },
        }
    }

    pub fn process_request_record_lookup<'b>(&mut self, r: &RpcPacket<'b>, xidmap: &mut NFSRequestXidMap) {
        match parse_nfs3_request_lookup(r.prog_data) {
            Ok((_, lookup)) => {
                SCLogDebug!("LOOKUP {:?}", lookup);
                xidmap.file_name = lookup.name_vec;
            },
            _ => {
                self.set_event(NFSEvent::MalformedData);
            },
        };
    }

    pub fn xidmap_handle2name(&mut self, xidmap: &mut NFSRequestXidMap) {
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

        match r.progver {
            4 => {
                self.process_request_record_v4(r)
            },
            3 => {
                self.process_request_record_v3(r)
            },
            2 => {
                self.process_request_record_v2(r)
            },
            _ => { 1 },
        }
    }

    pub fn new_file_tx(&mut self, file_handle: &Vec<u8>, file_name: &Vec<u8>, direction: u8)
        -> (&mut NFSTransaction, &mut FileContainer, u16)
    {
        let mut tx = self.new_tx();
        tx.file_name = file_name.to_vec();
        tx.file_handle = file_handle.to_vec();
        tx.is_file_tx = true;
        tx.file_tx_direction = direction;

        tx.type_data = Some(NFSTransactionTypeData::FILE(NFSTransactionFile::new()));
        if let Some(NFSTransactionTypeData::FILE(ref mut d)) = tx.type_data {
            d.file_tracker.tx_id = tx.id - 1;
        }
        SCLogDebug!("new_file_tx: TX FILE created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(file_name));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        let (files, flags) = self.files.get(direction);
        return (tx_ref.unwrap(), files, flags)
    }

    pub fn get_file_tx_by_handle(&mut self, file_handle: &Vec<u8>, direction: u8)
        -> Option<(&mut NFSTransaction, &mut FileContainer, u16)>
    {
        let fh = file_handle.to_vec();
        for tx in &mut self.transactions {
            if tx.is_file_tx &&
                direction == tx.file_tx_direction &&
                tx.file_handle == fh
            {
                SCLogDebug!("Found NFS file TX with ID {} XID {:04X}", tx.id, tx.xid);
                let (files, flags) = self.files.get(direction);
                return Some((tx, files, flags));
            }
        }
        SCLogDebug!("Failed to find NFS TX with handle {:?}", file_handle);
        return None;
    }

    pub fn process_write_record<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs3RequestWrite<'b>) -> u32 {
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
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
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
                } else {
                    false
                }
            },
            None => { false },
        };
        if !found {
            let (tx, files, flags) = self.new_file_tx(&file_handle, &file_name, STREAM_TOSERVER);
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
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
        }
        if !self.is_udp {
            self.ts_chunk_xid = r.hdr.xid;
            let file_data_len = w.file_data.len() as u32 - fill_bytes as u32;
            self.ts_chunk_left = w.file_len as u32 - file_data_len as u32;
            self.ts_chunk_fh = file_handle;
            SCLogDebug!("REQUEST chunk_xid {:04X} chunk_left {}", self.ts_chunk_xid, self.ts_chunk_left);
        }
        0
    }

    fn process_partial_write_request_record<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs3RequestWrite<'b>) -> u32 {
        SCLogDebug!("REQUEST {} procedure {} blob size {}", r.hdr.xid, r.procedure, r.prog_data.len());

        let mut xidmap = NFSRequestXidMap::new(r.progver, r.procedure, 0);
        xidmap.file_handle = w.handle.value.to_vec();
        self.requestmap.insert(r.hdr.xid, xidmap);

        return self.process_write_record(r, w);
    }

    fn process_reply_record<'b>(&mut self, r: &RpcReplyPacket<'b>) -> u32 {
        let mut xidmap;
        match self.requestmap.remove(&r.hdr.xid) {
            Some(p) => { xidmap = p; },
            _ => {
                SCLogDebug!("REPLY: xid {:04X} NOT FOUND. GAPS? TS:{} TC:{}",
                        r.hdr.xid, self.ts_ssn_gap, self.tc_ssn_gap);

                // TODO we might be able to try to infer from the size + data
                // that this is a READ reply and pass the data to the file API anyway?
                return 0;
            },
        }
        SCLogDebug!("process_reply_record: removed xid {:04X} from requestmap",
            r.hdr.xid);

        if self.nfs_version == 0 {
            self.nfs_version = xidmap.progver as u16;
        }

        match xidmap.progver {
            2 => {
                SCLogDebug!("NFSv2 reply record");
                return self.process_reply_record_v2(r, &xidmap);
            },
            3 => {
                SCLogDebug!("NFSv3 reply record");
                return self.process_reply_record_v3(r, &mut xidmap);
            },
            4 => {
                SCLogDebug!("NFSv4 reply record");
                return self.process_reply_record_v4(r, &mut xidmap);
            },
            _ => {
                SCLogDebug!("Invalid NFS version");
                self.set_event(NFSEvent::NonExistingVersion);
                return 0;
            },
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
        SCLogDebug!("filetracker_update: chunk left {}, input {} chunk_xid {:04X}", chunk_left, data.len(), xid);

        let file_handle;
        // we have the data that we expect
        if chunk_left <= data.len() as u32 {
            chunk_left = 0;

            if direction == STREAM_TOSERVER {
                self.ts_chunk_xid = 0;
                file_handle = self.ts_chunk_fh.to_vec();
                self.ts_chunk_fh.clear();
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

            if direction == STREAM_TOSERVER {
                file_handle = self.ts_chunk_fh.to_vec();
            } else {
                // see if we have a file handle to work on
                match self.requestmap.get(&xid) {
                    None => {
                        SCLogDebug!("no file handle found for XID {:04X}", xid);
                        return 0
                    },
                    Some(xidmap) => {
                        file_handle = xidmap.file_handle.to_vec();
                    },
                }
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
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    if ssn_gap {
                        let queued_data = tdf.file_tracker.get_queued_size();
                        if queued_data > 2000000 { // TODO should probably be configurable
                            SCLogDebug!("QUEUED size {} while we've seen GAPs. Truncating file.", queued_data);
                            tdf.file_tracker.trunc(files, flags);
                        }
                    }

                    tdf.chunk_count += 1;
                    let cs = tdf.file_tracker.update(files, flags, data, gap_size);
                    /* see if we need to close the tx */
                    if tdf.file_tracker.is_done() {
                        if direction == STREAM_TOCLIENT {
                            tx.response_done = true;
                            SCLogDebug!("TX {} response is done now that the file track is ready", tx.id);
                        } else {
                            tx.request_done = true;
                            SCLogDebug!("TX {} request is done now that the file track is ready", tx.id);
                        }
                    }
                    cs
                } else {
                    0
                }
            },
            None => { 0 },
        };
        return consumed;
    }

    /// xidmapr is an Option as it's already removed from the map if we
    /// have a complete record. Otherwise we do a lookup ourselves.
    pub fn process_read_record<'b>(&mut self, r: &RpcReplyPacket<'b>,
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
                if let Some(xidmap) = self.requestmap.get(&r.hdr.xid) {
                    file_name = xidmap.file_name.to_vec();
                    file_handle = xidmap.file_handle.to_vec();
                    chunk_offset = xidmap.chunk_offset;
                    nfs_version = xidmap.progver;
                } else {
                    return 0;
                }
            },
        }
        SCLogDebug!("chunk_offset {}", chunk_offset);

        let mut is_last = reply.eof;
        let mut fill_bytes = 0;
        let pad = reply.count % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }
        SCLogDebug!("XID {} is_last {} fill_bytes {} reply.count {} reply.data_len {} reply.data.len() {}",
                r.hdr.xid, is_last, fill_bytes, reply.count, reply.data_len, reply.data.len());

        if nfs_version == 2 {
            let size = match parse_nfs2_attribs(reply.attr_blob) {
                Ok((_, ref attr)) => {
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

        let is_partial = reply.data.len() < reply.count as usize;
        SCLogDebug!("partial data? {}", is_partial);

        let found = match self.get_file_tx_by_handle(&file_handle, STREAM_TOCLIENT) {
            Some((tx, files, flags)) => {
                SCLogDebug!("updated TX {:?}", tx);
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                            &file_name, reply.data, chunk_offset,
                            reply.count, fill_bytes as u8, is_last, &r.hdr.xid);
                    tdf.chunk_count += 1;
                    if is_last {
                        tdf.file_last_xid = r.hdr.xid;
                        tx.rpc_response_status = r.reply_state;
                        tx.nfs_response_status = reply.status;
                        tx.is_last = true;
                        tx.request_done = true;

                        /* if this is a partial record we will close the tx
                         * when we've received the final data */
                        if !is_partial {
                            tx.response_done = true;
                            SCLogDebug!("TX {} is DONE", tx.id);
                        }
                    }
                    true
                } else {
                    false
                }
            },
            None => { false },
        };
        if !found {
            let (tx, files, flags) = self.new_file_tx(&file_handle, &file_name, STREAM_TOCLIENT);
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                        &file_name, reply.data, chunk_offset,
                        reply.count, fill_bytes as u8, is_last, &r.hdr.xid);
                tx.procedure = if nfs_version < 4 { NFSPROC3_READ } else { NFSPROC4_READ };
                tx.xid = r.hdr.xid;
                tx.is_first = true;
                if is_last {
                    tdf.file_last_xid = r.hdr.xid;
                    tx.rpc_response_status = r.reply_state;
                    tx.nfs_response_status = reply.status;
                    tx.is_last = true;
                    tx.request_done = true;

                    /* if this is a partial record we will close the tx
                     * when we've received the final data */
                    if !is_partial {
                        tx.response_done = true;
                        SCLogDebug!("TX {} is DONE", tx.id);
                    }
                }
            }
        }

        if !self.is_udp {
            self.tc_chunk_xid = r.hdr.xid;
            self.tc_chunk_left = (reply.count as u32 + fill_bytes) - reply.data.len() as u32;
        }

        SCLogDebug!("REPLY {} to procedure {} blob size {} / {}: chunk_left {} chunk_xid {:04X}",
                r.hdr.xid, NFSPROC3_READ, r.prog_data.len(), reply.count, self.tc_chunk_left,
                self.tc_chunk_xid);
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
        SCLogDebug!("parse_tcp_data_ts_gap ({})", gap_size);
        if self.tcp_buffer_ts.len() > 0 {
            self.tcp_buffer_ts.clear();
        }
        let gap = vec![0; gap_size as usize];
        let consumed = self.filetracker_update(STREAM_TOSERVER, &gap, gap_size);
        if consumed > gap_size {
            SCLogDebug!("consumed more than GAP size: {} > {}", consumed, gap_size);
            return 1;
        }
        self.ts_ssn_gap = true;
        self.ts_gap = true;
        SCLogDebug!("parse_tcp_data_ts_gap ({}) done", gap_size);
        return 0
    }

    pub fn parse_tcp_data_tc_gap<'b>(&mut self, gap_size: u32) -> u32 {
        SCLogDebug!("parse_tcp_data_tc_gap ({})", gap_size);
        if self.tcp_buffer_tc.len() > 0 {
            self.tcp_buffer_tc.clear();
        }
        let gap = vec![0; gap_size as usize];
        let consumed = self.filetracker_update(STREAM_TOCLIENT, &gap, gap_size);
        if consumed > gap_size {
            SCLogDebug!("consumed more than GAP size: {} > {}", consumed, gap_size);
            return 1;
        }
        self.tc_ssn_gap = true;
        self.tc_gap = true;
        SCLogDebug!("parse_tcp_data_tc_gap ({}) done", gap_size);
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
            if consumed > cur_i.len() as u32 { return 1; }
            cur_i = &cur_i[consumed as usize..];
        }
        if self.ts_gap {
            SCLogDebug!("TS trying to catch up after GAP (input {})", cur_i.len());

            let mut cnt = 0;
            while cur_i.len() > 0 {
                cnt += 1;
                match nfs_probe(cur_i, STREAM_TOSERVER) {
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
                    _ => { return 1; },
                }
            }
            SCLogDebug!("TS GAP handling done (input {})", cur_i.len());
        }

        while cur_i.len() > 0 { // min record size
            match parse_rpc_request_partial(cur_i) {
                Ok((_, ref rpc_phdr)) => {
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
                                    Ok((remaining, ref rpc_record)) => {
                                        match parse_nfs3_request_write(rpc_record.prog_data) {
                                            Ok((_, ref nfs_request_write)) => {
                                                // deal with the partial nfs write data
                                                status |= self.process_partial_write_request_record(rpc_record, nfs_request_write);
                                                cur_i = remaining; // progress input past parsed record
                                            },
                                            _ => {
                                                self.set_event(NFSEvent::MalformedData);
                                            },
                                        }
                                    },
                                    Err(nom::Err::Incomplete(_)) => {
                                        // we just size checked for the minimal record size above,
                                        // so if options are used (creds/verifier), we can still
                                        // have Incomplete data. Fall through to the buffer code
                                        // and try again on our next iteration.
                                        SCLogDebug!("TS data incomplete");
                                    },
                                    Err(nom::Err::Error(_e)) |
                                    Err(nom::Err::Failure(_e)) => {
                                        self.set_event(NFSEvent::MalformedData);
                                        SCLogDebug!("Parsing failed: {:?}", _e);
                                        return 1;
                                    },
                                }
                            }
                        }
                        self.tcp_buffer_ts.extend_from_slice(cur_i);
                        break;
                    }

                    // we have the full records size worth of data,
                    // let's parse it
                    match parse_rpc(&cur_i[..rec_size]) {
                        Ok((_, ref rpc_record)) => {
                            cur_i = &cur_i[rec_size..];
                            status |= self.process_request_record(rpc_record);
                        },
                        Err(nom::Err::Incomplete(_)) => {
                            cur_i = &cur_i[rec_size..]; // progress input past parsed record

                            // we shouldn't get incomplete as we have the full data
                            // so if we got incomplete anyway it's the data that is
                            // bad.
                            self.set_event(NFSEvent::MalformedData);

                            status = 1;
                        },
                        Err(nom::Err::Error(_e)) |
                        Err(nom::Err::Failure(_e)) => {
                            self.set_event(NFSEvent::MalformedData);
                            SCLogDebug!("Parsing failed: {:?}", _e);
                            return 1;
                        },
                    }
                },
                Err(nom::Err::Incomplete(_)) => {
                    SCLogDebug!("Fragmentation required (TCP level) 2");
                    self.tcp_buffer_ts.extend_from_slice(cur_i);
                    break;
                },
                Err(nom::Err::Error(_e)) |
                Err(nom::Err::Failure(_e)) => {
                    self.set_event(NFSEvent::MalformedData);
                    SCLogDebug!("Parsing failed: {:?}", _e);
                    return 1;
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
            if consumed > cur_i.len() as u32 { return 1; }
            cur_i = &cur_i[consumed as usize..];
        }
        if self.tc_gap {
            SCLogDebug!("TC trying to catch up after GAP (input {})", cur_i.len());

            let mut cnt = 0;
            while cur_i.len() > 0 {
                cnt += 1;
                match nfs_probe(cur_i, STREAM_TOCLIENT) {
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
                    _ => { return 1; },
                }
            }
            SCLogDebug!("TC GAP handling done (input {})", cur_i.len());
        }

        while cur_i.len() > 0 {
            match parse_rpc_packet_header(cur_i) {
                Ok((_, ref rpc_hdr)) => {
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
                                    Ok((remaining, ref rpc_record)) => {
                                        match parse_nfs3_reply_read(rpc_record.prog_data) {
                                            Ok((_, ref nfs_reply_read)) => {
                                                // deal with the partial nfs read data
                                                status |= self.process_partial_read_reply_record(rpc_record, nfs_reply_read);
                                                cur_i = remaining; // progress input past parsed record
                                            },
                                            Err(nom::Err::Incomplete(_)) => {
                                                self.set_event(NFSEvent::MalformedData);
                                            },
                                            Err(nom::Err::Error(_e)) |
                                            Err(nom::Err::Failure(_e)) => {
                                                self.set_event(NFSEvent::MalformedData);
                                                SCLogDebug!("Parsing failed: {:?}", _e);
                                                return 1;
                                            }
                                        }
                                    },
                                    Err(nom::Err::Incomplete(_)) => {
                                        // size check was done for MINIMAL record size,
                                        // so Incomplete is normal.
                                        SCLogDebug!("TC data incomplete");
                                    },
                                    Err(nom::Err::Error(_e)) |
                                    Err(nom::Err::Failure(_e)) => {
                                        self.set_event(NFSEvent::MalformedData);
                                        SCLogDebug!("Parsing failed: {:?}", _e);
                                        return 1;
                                    }
                                }
                            }
                        }
                        self.tcp_buffer_tc.extend_from_slice(cur_i);
                        break;
                    }

                    // we have the full data of the record, lets parse
                    match parse_rpc_reply(&cur_i[..rec_size]) {
                        Ok((_, ref rpc_record)) => {
                            cur_i = &cur_i[rec_size..]; // progress input past parsed record
                            status |= self.process_reply_record(rpc_record);
                        },
                        Err(nom::Err::Incomplete(_)) => {
                            cur_i = &cur_i[rec_size..]; // progress input past parsed record

                            // we shouldn't get incomplete as we have the full data
                            // so if we got incomplete anyway it's the data that is
                            // bad.
                            self.set_event(NFSEvent::MalformedData);

                            status = 1;
                        },
                        Err(nom::Err::Error(_e)) |
                        Err(nom::Err::Failure(_e)) => {
                            self.set_event(NFSEvent::MalformedData);
                            SCLogDebug!("Parsing failed: {:?}", _e);
                            return 1;
                        }
                    }
                },
                Err(nom::Err::Incomplete(_)) => {
                    SCLogDebug!("REPLY: insufficient data for HDR");
                    self.tcp_buffer_tc.extend_from_slice(cur_i);
                    break;
                },
                Err(nom::Err::Error(_e)) |
                Err(nom::Err::Failure(_e)) => {
                    self.set_event(NFSEvent::MalformedData);
                    SCLogDebug!("Parsing failed: {:?}", _e);
                    return 1;
                },
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
                Ok((_, ref rpc_record)) => {
                    self.is_udp = true;
                    match rpc_record.progver {
                        3 => {
                            status |= self.process_request_record(rpc_record);
                        },
                        2 => {
                            status |= self.process_request_record_v2(rpc_record);
                        },
                        _ => { status = 1; },
                    }
                },
                Err(nom::Err::Incomplete(_)) => {
                },
                Err(nom::Err::Error(_e)) |
                Err(nom::Err::Failure(_e)) => { SCLogDebug!("Parsing failed: {:?}", _e); }
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
                Ok((_, ref rpc_record)) => {
                    self.is_udp = true;
                    status |= self.process_reply_record(rpc_record);
                },
                Err(nom::Err::Incomplete(_)) => {
                },
                Err(nom::Err::Error(_e)) |
                Err(nom::Err::Failure(_e)) => { SCLogDebug!("Parsing failed: {:?}", _e); }
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
pub extern "C" fn rs_nfs_state_new() -> *mut std::os::raw::c_void {
    let state = NFSState::new();
    let boxed = Box::new(state);
    SCLogDebug!("allocating state");
    return unsafe{transmute(boxed)};
}

/// Params:
/// - state: *mut NFSState as void pointer
#[no_mangle]
pub extern "C" fn rs_nfs_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    SCLogDebug!("freeing state");
    let mut nfs_state: Box<NFSState> = unsafe{transmute(state)};
    nfs_state.free();
}

/// C binding parse a NFS TCP request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_nfs_parse_request(_flow: *mut Flow,
                                       state: &mut NFSState,
                                       _pstate: *mut std::os::raw::c_void,
                                       input: *mut u8,
                                       input_len: u32,
                                       _data: *mut std::os::raw::c_void)
                                       -> i8
{
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    SCLogDebug!("parsing {} bytes of request data", input_len);

    if state.parse_tcp_data_ts(buf) == 0 {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_parse_request_tcp_gap(
                                        state: &mut NFSState,
                                        input_len: u32)
                                        -> i8
{
    if state.parse_tcp_data_ts_gap(input_len as u32) == 0 {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_nfs_parse_response(_flow: *mut Flow,
                                        state: &mut NFSState,
                                        _pstate: *mut std::os::raw::c_void,
                                        input: *mut u8,
                                        input_len: u32,
                                        _data: *mut std::os::raw::c_void)
                                        -> i8
{
    SCLogDebug!("parsing {} bytes of response data", input_len);
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};

    if state.parse_tcp_data_tc(buf) == 0 {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_parse_response_tcp_gap(
                                        state: &mut NFSState,
                                        input_len: u32)
                                        -> i8
{
    if state.parse_tcp_data_tc_gap(input_len as u32) == 0 {
        return 1;
    }
    return -1;
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_nfs_parse_request_udp(_flow: *mut Flow,
                                       state: &mut NFSState,
                                       _pstate: *mut std::os::raw::c_void,
                                       input: *mut u8,
                                       input_len: u32,
                                       _data: *mut std::os::raw::c_void)
                                       -> i8
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
pub extern "C" fn rs_nfs_parse_response_udp(_flow: *mut Flow,
                                        state: &mut NFSState,
                                        _pstate: *mut std::os::raw::c_void,
                                        input: *mut u8,
                                        input_len: u32,
                                        _data: *mut std::os::raw::c_void)
                                        -> i8
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
pub extern "C" fn rs_nfs_state_get_tx_count(state: &mut NFSState)
                                            -> u64
{
    SCLogDebug!("rs_nfs_state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_get_tx(state: &mut NFSState,
                                      tx_id: u64)
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

// for use with the C API call StateGetTxIterator
#[no_mangle]
pub extern "C" fn rs_nfs_state_get_tx_iterator(
                                      state: &mut NFSState,
                                      min_tx_id: u64,
                                      istate: &mut u64)
                                      -> applayer::AppLayerGetTxIterTuple
{
    match state.get_tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(c_tx, out_tx_id, has_next);
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_tx_free(state: &mut NFSState,
                                       tx_id: u64)
{
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_progress_completion_status(
    _direction: u8)
    -> std::os::raw::c_int
{
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_nfs_tx_get_alstate_progress(tx: &mut NFSTransaction,
                                                  direction: u8)
                                                  -> u8
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

#[no_mangle]
pub extern "C" fn rs_nfs_tx_set_logged(_state: &mut NFSState,
                                       tx: &mut NFSTransaction,
                                       logged: u32)
{
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_nfs_tx_get_logged(_state: &mut NFSState,
                                       tx: &mut NFSTransaction)
                                       -> u32
{
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_set_tx_detect_state(
    tx: &mut NFSTransaction,
    de_state: &mut DetectEngineState)
{
    tx.de_state = Some(de_state);
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_get_tx_detect_state(
    tx: &mut NFSTransaction)
    -> *mut DetectEngineState
{
    match tx.de_state {
        Some(ds) => {
            SCLogDebug!("{}: getting de_state", tx.id);
            return ds;
        },
        None => {
            SCLogDebug!("{}: getting de_state: have none", tx.id);
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_tx_set_detect_flags(
                                       tx: &mut NFSTransaction,
                                       direction: u8,
                                       flags: u64)
{
    if (direction & STREAM_TOSERVER) != 0 {
        tx.detect_flags_ts = flags as u64;
    } else {
        tx.detect_flags_tc = flags as u64;
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_tx_get_detect_flags(
                                       tx: &mut NFSTransaction,
                                       direction: u8)
                                       -> u64
{
    if (direction & STREAM_TOSERVER) != 0 {
        return tx.detect_flags_ts as u64;
    } else {
        return tx.detect_flags_tc as u64;
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_get_events(tx: *mut std::os::raw::c_void)
                                          -> *mut AppLayerDecoderEvents
{
    let tx = cast_pointer!(tx, NFSTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_nfs_state_get_event_info_by_id(event_id: std::os::raw::c_int,
                                              event_name: *mut *const std::os::raw::c_char,
                                              event_type: *mut AppLayerEventType)
                                              -> i8
{
    if let Some(e) = NFSEvent::from_i32(event_id as i32) {
        let estr = match e {
            NFSEvent::MalformedData => { "malformed_data\0" },
            NFSEvent::NonExistingVersion => { "non_existing_version\0" },
            NFSEvent::UnsupportedVersion => { "unsupported_version\0" },
        };
        unsafe{
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}
#[no_mangle]
pub extern "C" fn rs_nfs_state_get_event_info(event_name: *const std::os::raw::c_char,
                                              event_id: *mut std::os::raw::c_int,
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
        *event_id = event as std::os::raw::c_int;
    };
    0
}

/// return procedure(s) in the tx. At 0 return the main proc,
/// otherwise get procs from the 'file_additional_procs'.
/// Keep calling until 0 is returned.
#[no_mangle]
pub extern "C" fn rs_nfs_tx_get_procedures(tx: &mut NFSTransaction,
                                           i: u16,
                                           procedure: *mut u32)
                                           -> u8
{
    if i == 0 {
        unsafe {
            *procedure = tx.procedure as u32;
        }
        return 1;
    }

    if !tx.is_file_tx {
        return 0;
    }

    /* file tx handling follows */

    if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
        let idx = i as usize - 1;
        if idx < tdf.file_additional_procs.len() {
            let p = tdf.file_additional_procs[idx];
            unsafe {
                *procedure = p as u32;
            }
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_nfs_tx_get_version(tx: &mut NFSTransaction,
                                        version: *mut u32)
{
    unsafe {
        *version = tx.nfs_version as u32;
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_init(context: &'static mut SuricataFileContext)
{
    unsafe {
        SURICATA_NFS_FILE_CONFIG = Some(context);
    }
}

fn nfs_probe_dir(i: &[u8], rdir: *mut u8) -> i8 {
    match parse_rpc_packet_header(i) {
        Ok((_, ref hdr)) => {
            let dir = if hdr.msgtype == 0 {
                STREAM_TOSERVER
            } else {
                STREAM_TOCLIENT
            };
            unsafe { *rdir = dir };
            return 1;
        },
        Err(nom::Err::Incomplete(_)) => {
            return 0;
        },
        Err(_) => {
            return -1;
        },
    }
}

pub fn nfs_probe(i: &[u8], direction: u8) -> i8 {
    if direction == STREAM_TOCLIENT {
        match parse_rpc_reply(i) {
            Ok((_, ref rpc)) => {
                if rpc.hdr.frag_len >= 24 && rpc.hdr.frag_len <= 35000 && rpc.hdr.msgtype == 1 && rpc.reply_state == 0 && rpc.accept_state == 0 {
                    SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc.hdr.frag_len, rpc.hdr.xid, rpc.hdr.msgtype);
                    return 1;
                } else {
                    return -1;
                }
            },
            Err(nom::Err::Incomplete(_)) => {
                match parse_rpc_packet_header (i) {
                    Ok((_, ref rpc_hdr)) => {
                        if rpc_hdr.frag_len >= 24 && rpc_hdr.frag_len <= 35000 && rpc_hdr.xid != 0 && rpc_hdr.msgtype == 1 {
                            SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc_hdr.frag_len, rpc_hdr.xid, rpc_hdr.msgtype);
                            return 1;
                        } else {
                            return -1;
                        }
                    },
                    Err(nom::Err::Incomplete(_)) => { },
                    Err(_) => {
                        return -1;
                    },
                }


                return 0;
            },
            Err(_) => {
                return -1;
            },
        }
    } else {
        match parse_rpc(i) {
            Ok((_, ref rpc)) => {
                if rpc.hdr.frag_len >= 40 && rpc.hdr.msgtype == 0 &&
                   rpc.rpcver == 2 && (rpc.progver == 3 || rpc.progver == 4) &&
                   rpc.program == 100003 &&
                   rpc.procedure <= NFSPROC3_COMMIT
                {
                    return 1;
                } else {
                    return -1;
                }
            },
            Err(nom::Err::Incomplete(_)) => {
                return 0;
            },
            Err(_) => {
                return -1;
            },
        }
    }
}

pub fn nfs_probe_udp(i: &[u8], direction: u8) -> i8 {
    if direction == STREAM_TOCLIENT {
        match parse_rpc_udp_reply(i) {
            Ok((_, ref rpc)) => {
                if i.len() >= 32 && rpc.hdr.msgtype == 1 && rpc.reply_state == 0 && rpc.accept_state == 0 {
                    SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc.hdr.frag_len, rpc.hdr.xid, rpc.hdr.msgtype);
                    return 1;
                } else {
                    return -1;
                }
            },
            Err(_) => {
                return -1;
            },
        }
    } else {
        match parse_rpc_udp_request(i) {
            Ok((_, ref rpc)) => {
                if i.len() >= 48 && rpc.hdr.msgtype == 0 && rpc.progver == 3 && rpc.program == 100003 {
                    return 1;
                } else if i.len() >= 48 && rpc.hdr.msgtype == 0 && rpc.progver == 2 && rpc.program == 100003 {
                    SCLogDebug!("NFSv2!");
                    return 1;
                } else {
                    return -1;
                }
            },
            Err(_) => {
                return -1;
            },
        }
    }
}

/// MIDSTREAM
#[no_mangle]
pub extern "C" fn rs_nfs_probe_ms(
        direction: u8, input: *const u8,
        len: u32, rdir: *mut u8) -> i8
{
    let slice: &[u8] = build_slice!(input, len as usize);
    SCLogDebug!("rs_nfs_probe_ms: probing direction {:02x}", direction);
    let mut adirection : u8 = 0;
    match nfs_probe_dir(slice, &mut adirection) {
        1 => {
            if adirection == STREAM_TOSERVER {
                SCLogDebug!("nfs_probe_dir said STREAM_TOSERVER");
            } else {
                SCLogDebug!("nfs_probe_dir said STREAM_TOCLIENT");
            }
            let r = nfs_probe(slice, adirection);
            if r == 1 {
                SCLogDebug!("nfs_probe success: dir {:02x} adir {:02x}", direction, adirection);
                if (direction & (STREAM_TOSERVER|STREAM_TOCLIENT)) != adirection {
                    unsafe { *rdir = adirection; }
                }
                return 1;
            }
            return r;
        },
        0 => {
            return 0;
        },
        _ => {
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_nfs_probe(direction: u8,
        input: *const u8, len: u32)
    -> i8
{
    let slice: &[u8] = build_slice!(input, len as usize);
    SCLogDebug!("rs_nfs_probe: running probe");
    return nfs_probe(slice, direction);
}

/// TOSERVER probe function
#[no_mangle]
pub extern "C" fn rs_nfs_probe_udp_ts(input: *const u8, len: u32)
                               -> i8
{
    let slice: &[u8] = build_slice!(input, len as usize);
    return nfs_probe_udp(slice, STREAM_TOSERVER);
}

/// TOCLIENT probe function
#[no_mangle]
pub extern "C" fn rs_nfs_probe_udp_tc(input: *const u8, len: u32)
                               -> i8
{
    let slice: &[u8] = build_slice!(input, len as usize);
    return nfs_probe_udp(slice, STREAM_TOCLIENT);
}

#[no_mangle]
pub extern "C" fn rs_nfs_getfiles(direction: u8, ptr: *mut NFSState) -> * mut FileContainer {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    parser.getfiles(direction)
}
#[no_mangle]
pub extern "C" fn rs_nfs_setfileflags(direction: u8, ptr: *mut NFSState, flags: u16) {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    SCLogDebug!("direction {} flags {}", direction, flags);
    parser.setfileflags(direction, flags)
}
