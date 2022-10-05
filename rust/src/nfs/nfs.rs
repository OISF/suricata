/* Copyright (C) 2017-2021 Open Information Security Foundation
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

use std;
use std::cmp;
use std::collections::HashMap;
use std::ffi::CString;

use nom7::{Err, Needed};

use crate::applayer;
use crate::applayer::*;
use crate::frames::*;
use crate::core::*;
use crate::conf::*;
use crate::filetracker::*;
use crate::filecontainer::*;

use crate::nfs::types::*;
use crate::nfs::rpc_records::*;
use crate::nfs::nfs_records::*;
use crate::nfs::nfs2_records::*;
use crate::nfs::nfs3_records::*;

pub static mut SURICATA_NFS_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

pub const NFS_MIN_FRAME_LEN: u16 = 32;

static mut NFS_MAX_TX: usize = 1024;

pub const RPC_TCP_PRE_CREDS: usize = 28;
pub const RPC_UDP_PRE_CREDS: usize = 24;

static mut ALPROTO_NFS: AppProto = ALPROTO_UNKNOWN;
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

#[derive(AppLayerFrameType)]
pub enum NFSFrameType {
    RPCPdu,
    RPCHdr,
    RPCData,
    RPCCreds, // for rpc calls | rpc.creds [creds_flavor + creds_len + creds]

    NFSPdu,
    NFSStatus,

    NFS4Pdu,
    NFS4Hdr,
    NFS4Ops,
    NFS4Status,
}

#[derive(FromPrimitive, Debug, AppLayerEvent)]
pub enum NFSEvent {
    MalformedData = 0,
    NonExistingVersion = 1,
    UnsupportedVersion = 2,
    TooManyTransactions = 3,
}

#[derive(Debug)]
pub enum NFSTransactionTypeData {
    RENAME(Vec<u8>),
    FILE(NFSTransactionFile),
}

#[derive(Default, Debug)]
pub struct NFSTransactionFile {
    /// additional procedures part of a single file transfer. Currently
    /// only COMMIT on WRITEs.
    pub file_additional_procs: Vec<u32>,

    pub chunk_count: u32,

    /// last xid of this file transfer. Last READ or COMMIT normally.
    pub file_last_xid: u32,

    /// after a gap, this will be set to a time in the future. If the file
    /// receives no updates before that, it will be considered complete.
    pub post_gap_ts: u64,

    /// file tracker for a single file. Boxed so that we don't use
    /// as much space if we're not a file tx.
    pub file_tracker: FileTransferTracker,

    /// storage for the actual file
    pub files: Files,
}

impl NFSTransactionFile {
    pub fn new() -> Self {
        Self {
            file_tracker: FileTransferTracker::new(),
            ..Default::default()
        }
    }
    pub fn update_file_flags(&mut self, flow_file_flags: u16) {
        self.files.flags_ts = unsafe { FileFlowFlagsToFlags(flow_file_flags, STREAM_TOSERVER) | FILE_USE_DETECT };
        self.files.flags_tc = unsafe { FileFlowFlagsToFlags(flow_file_flags, STREAM_TOCLIENT) | FILE_USE_DETECT };
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_gettxfiles(tx_ptr: *mut std::ffi::c_void, direction: u8) -> * mut FileContainer {
    let tx = cast_pointer!(tx_ptr, NFSTransaction);
    if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
        let (files, _flags) = tdf.files.get(direction.into());
        files
    } else {
        std::ptr::null_mut()
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
    pub is_file_closed: bool,
    /// file transactions are unidirectional in the sense that they track
    /// a single file on one direction
    pub file_tx_direction: Direction, // Direction::ToClient or Direction::ToServer
    pub file_handle: Vec<u8>,

    /// Procedure type specific data
    /// TODO see if this can be an Option<Box<NFSTransactionTypeData>>. Initial
    /// attempt failed.
    pub type_data: Option<NFSTransactionTypeData>,

    pub tx_data: AppLayerTxData,
}

impl NFSTransaction {
    pub fn new() -> Self {
        Self {
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
            is_file_closed: false,
            file_tx_direction: Direction::ToServer,
            file_handle:Vec::new(),
            type_data: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    pub fn free(&mut self) {
        debug_validate_bug_on!(self.tx_data.files_opened > 1);
        debug_validate_bug_on!(self.tx_data.files_logged > 1);
    }
}

impl Transaction for NFSTransaction {
    fn id(&self) -> u64 {
        self.id
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
            progver,
            procedure,
            chunk_offset,
            file_name:Vec::new(),
            file_handle:Vec::new(),
            gssapi_proc: 0,
            gssapi_service: 0,
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
            ft.new_chunk(sfcm, files, flags, name, data, chunk_offset,
                    chunk_size, fill_bytes, is_last, xid); }
        None => panic!("no SURICATA_NFS_FILE_CONFIG"),
    }
}

#[derive(Debug)]
pub struct NFSState {
    state_data: AppLayerStateData,

    /// map xid to procedure so replies can lookup the procedure
    pub requestmap: HashMap<u32, NFSRequestXidMap>,

    /// map file handle (1) to name (2)
    pub namemap: HashMap<Vec<u8>, Vec<u8>>,

    /// transactions list
    pub transactions: Vec<NFSTransaction>,

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

    /// true as long as we have file txs that are in a post-gap
    /// state. It means we'll do extra house keeping for those.
    check_post_gap_file_txs: bool,
    post_gap_files_checked: bool,

    pub nfs_version: u16,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,

    /// Timestamp in seconds of last update. This is packet time,
    /// potentially coming from pcaps.
    ts: u64,
}

impl State<NFSTransaction> for NFSState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&NFSTransaction> {
        self.transactions.get(index)
    }
}

impl NFSState {
    /// Allocation function for a new TLS parser instance
    pub fn new() -> NFSState {
        NFSState {
            state_data: AppLayerStateData::new(),
            requestmap:HashMap::new(),
            namemap:HashMap::new(),
            transactions: Vec::new(),
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
            check_post_gap_file_txs:false,
            post_gap_files_checked:false,
            nfs_version:0,
            tx_id:0,
            ts: 0,
        }
    }

    fn update_ts(&mut self, ts: u64) {
        if ts != self.ts {
            self.ts = ts;
            self.post_gap_files_checked = false;
        }
    }

    pub fn new_tx(&mut self) -> NFSTransaction {
        let mut tx = NFSTransaction::new();
        self.tx_id += 1;
        tx.id = self.tx_id;
        if self.transactions.len() > unsafe { NFS_MAX_TX } {
            // set at least one another transaction to the drop state
            for tx_old in &mut self.transactions {
                if !tx_old.request_done || !tx_old.response_done {
                    tx_old.request_done = true;
                    tx_old.response_done = true;
                    tx_old.is_file_closed = true;
                    tx_old.tx_data.set_event(NFSEvent::TooManyTransactions as u8);
                    break;
                }
            }
        }
        tx
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
        None
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
        None
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: NFSEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let tx = &mut self.transactions[len - 1];
        tx.tx_data.set_event(event as u8);
    }

    // TODO maybe not enough users to justify a func
    pub fn mark_response_tx_done(&mut self, xid: u32, rpc_status: u32, nfs_status: u32, resp_handle: &Vec<u8>)
    {
        match self.get_tx_by_xid(xid) {
            Some(mytx) => {
                mytx.response_done = true;
                mytx.rpc_response_status = rpc_status;
                mytx.nfs_response_status = nfs_status;
                if mytx.file_handle.is_empty() && !resp_handle.is_empty() {
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

    fn add_rpc_udp_ts_pdu(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], rpc_len: i64) -> Option<Frame> {
        
        SCLogDebug!("rpc_udp_pdu ts frame {:?}", rpc_udp_ts_pdu);
        Frame::new(flow, stream_slice, input, rpc_len, NFSFrameType::RPCPdu as u8)
    }

    fn add_rpc_udp_ts_creds(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], creds_len: i64) {
        let _rpc_udp_ts_creds = Frame::new(flow, stream_slice, input, creds_len, NFSFrameType::RPCCreds as u8);
        SCLogDebug!("rpc_creds ts frame {:?}", _rpc_udp_ts_creds);
    }

    fn add_rpc_tcp_ts_pdu(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], rpc_len: i64) -> Option<Frame> {
        
        SCLogDebug!("rpc_tcp_pdu ts frame {:?}", rpc_tcp_ts_pdu);
        Frame::new(flow, stream_slice, input, rpc_len, NFSFrameType::RPCPdu as u8)
    }

    fn add_rpc_tcp_ts_creds(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], creds_len: i64) {
        let _rpc_tcp_ts_creds = Frame::new(flow, stream_slice, input, creds_len, NFSFrameType::RPCCreds as u8);
        SCLogDebug!("rpc_tcp_ts_creds {:?}", _rpc_tcp_ts_creds);
    }

    fn add_nfs_ts_frame(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nfs_len: i64) {
        let _nfs_req_pdu = Frame::new(flow, stream_slice, input, nfs_len, NFSFrameType::NFSPdu as u8);
        SCLogDebug!("nfs_ts_pdu Frame {:?}", _nfs_req_pdu);
    }

    fn add_nfs4_ts_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nfs4_len: i64) {
        let _nfs4_ts_pdu = Frame::new(flow, stream_slice, input, nfs4_len, NFSFrameType::NFS4Pdu as u8);
        SCLogDebug!("nfs4_ts_pdu Frame: {:?}", _nfs4_ts_pdu);
        if nfs4_len > 8 {
            let _nfs4_ts_hdr = Frame::new(flow, stream_slice, input, 8, NFSFrameType::NFS4Hdr as u8);
            SCLogDebug!("nfs4_ts_hdr Frame {:?}", _nfs4_ts_hdr);
            let _nfs4_ts_ops = Frame::new(flow, stream_slice, &input[8..], nfs4_len - 8, NFSFrameType::NFS4Ops as u8);
            SCLogDebug!("nfs4_ts_ops Frame {:?}", _nfs4_ts_ops);
        }
    }

    fn add_rpc_udp_tc_pdu(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], rpc_len: i64) -> Option<Frame> {
        
        SCLogDebug!("rpc_tc_pdu frame {:?}", rpc_udp_tc_pdu);
        Frame::new(flow, stream_slice, input, rpc_len, NFSFrameType::RPCPdu as u8)
    }

    fn add_rpc_udp_tc_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], rpc_len: i64) {
        if rpc_len > 8 {
            let _rpc_udp_tc_hdr = Frame::new(flow, stream_slice, input, 8, NFSFrameType::RPCHdr as u8);
            let _rpc_udp_tc_data = Frame::new(flow, stream_slice, &input[8..], rpc_len - 8, NFSFrameType::RPCData as u8);
            SCLogDebug!("rpc_udp_tc_hdr frame {:?}", _rpc_udp_tc_hdr);
            SCLogDebug!("rpc_udp_tc_data frame {:?}", _rpc_udp_tc_data);
        }
    }

    fn add_rpc_tcp_tc_pdu(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], rpc_tcp_len: i64) -> Option<Frame> {
        
        SCLogDebug!("rpc_tcp_pdu tc frame {:?}", rpc_tcp_tc_pdu);
        Frame::new(flow, stream_slice, input, rpc_tcp_len, NFSFrameType::RPCPdu as u8)
    }

    fn add_rpc_tcp_tc_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], rpc_tcp_len: i64) {
        if rpc_tcp_len > 12 {
            let _rpc_tcp_tc_hdr = Frame::new(flow, stream_slice, input, 12, NFSFrameType::RPCHdr as u8);
            let _rpc_tcp_tc_data = Frame::new(flow, stream_slice, &input[12..], rpc_tcp_len - 12, NFSFrameType::RPCData as u8);
            SCLogDebug!("rpc_tcp_tc_hdr frame {:?}", _rpc_tcp_tc_hdr);
            SCLogDebug!("rpc_tcp_tc_data frame {:?}", _rpc_tcp_tc_data);
        }
    }

    fn add_nfs_tc_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nfs_len: i64) {
        if nfs_len > 0 {
            let _nfs_tc_pdu = Frame::new(flow, stream_slice, input, nfs_len, NFSFrameType::NFSPdu as u8);
            SCLogDebug!("nfs_tc_pdu frame {:?}", _nfs_tc_pdu);
            let _nfs_res_status = Frame::new(flow, stream_slice, input, 4, NFSFrameType::NFSStatus as u8);
            SCLogDebug!("nfs_tc_status frame {:?}", _nfs_res_status);
        }
    }

    fn add_nfs4_tc_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nfs4_len: i64) {
        if nfs4_len > 0 {
            let _nfs4_tc_pdu = Frame::new(flow, stream_slice, input, nfs4_len, NFSFrameType::NFS4Pdu as u8);
            SCLogDebug!("nfs4_tc_pdu frame {:?}", _nfs4_tc_pdu);
            let _nfs4_tc_status = Frame::new(flow, stream_slice, input, 4, NFSFrameType::NFS4Status as u8);
            SCLogDebug!("nfs4_tc_status frame {:?}", _nfs4_tc_status);
        }
        if nfs4_len > 8 {
            let _nfs4_tc_hdr = Frame::new(flow, stream_slice, input, 8, NFSFrameType::NFS4Hdr as u8);
            SCLogDebug!("nfs4_tc_hdr frame {:?}", _nfs4_tc_hdr);
            let _nfs4_tc_ops = Frame::new(flow, stream_slice, &input[8..], nfs4_len - 8, NFSFrameType::NFS4Ops as u8);
            SCLogDebug!("nfs4_tc_ops frame {:?}", _nfs4_tc_ops);
        }
    }

    fn post_gap_housekeeping_for_files(&mut self)
    {
        let mut post_gap_txs = false;
        for tx in &mut self.transactions {
            if let Some(NFSTransactionTypeData::FILE(ref mut f)) = tx.type_data {
                if f.post_gap_ts > 0 {
                    if self.ts > f.post_gap_ts {
                        tx.request_done = true;
                        tx.response_done = true;
                        let (files, flags) = f.files.get(tx.file_tx_direction);
                        f.file_tracker.trunc(files, flags);
                    } else {
                        post_gap_txs = true;
                    }
                }
            }
        }
        self.check_post_gap_file_txs = post_gap_txs;
    }

    /* after a gap we will consider all transactions complete for our
     * direction. File transfer transactions are an exception. Those
     * can handle gaps. For the file transactions we set the current
     * (flow) time and prune them in 60 seconds if no update for them
     * was received. */
    fn post_gap_housekeeping(&mut self, dir: Direction)
    {
        if self.ts_ssn_gap && dir == Direction::ToServer {
            for tx in &mut self.transactions {
                if tx.id >= self.tx_id {
                    SCLogDebug!("post_gap_housekeeping: done");
                    break;
                }
                if let Some(NFSTransactionTypeData::FILE(ref mut f)) = tx.type_data {
                    // leaving FILE txs open as they can deal with gaps. We
                    // remove them after 60 seconds of no activity though.
                    if f.post_gap_ts == 0 {
                        f.post_gap_ts = self.ts + 60;
                        self.check_post_gap_file_txs = true;
                    }
                } else {
                    SCLogDebug!("post_gap_housekeeping: tx {} marked as done TS", tx.id);
                    tx.request_done = true;
                }
            }
        } else if self.tc_ssn_gap && dir == Direction::ToClient {
            for tx in &mut self.transactions {
                if tx.id >= self.tx_id {
                    SCLogDebug!("post_gap_housekeeping: done");
                    break;
                }
                if let Some(NFSTransactionTypeData::FILE(ref mut f)) = tx.type_data {
                    // leaving FILE txs open as they can deal with gaps. We
                    // remove them after 60 seconds of no activity though.
                    if f.post_gap_ts == 0 {
                        f.post_gap_ts = self.ts + 60;
                        self.check_post_gap_file_txs = true;
                    }
                } else {
                    SCLogDebug!("post_gap_housekeeping: tx {} marked as done TC", tx.id);
                    tx.request_done = true;
                    tx.response_done = true;
                }
            }
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
    fn process_request_record<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice, r: &RpcPacket<'b>) {
        SCLogDebug!("REQUEST {} procedure {} ({}) blob size {}",
                r.hdr.xid, r.procedure, self.requestmap.len(), r.prog_data.len());

        match r.progver {
            4 => {
                self.add_nfs4_ts_frames(flow, stream_slice, r.prog_data, r.prog_data_size as i64);
                self.process_request_record_v4(r)
            },
            3 => {
                self.add_nfs_ts_frame(flow, stream_slice, r.prog_data, r.prog_data_size as i64);
                self.process_request_record_v3(r)
            },
            2 => {
                self.add_nfs_ts_frame(flow, stream_slice, r.prog_data, r.prog_data_size as i64);
                self.process_request_record_v2(r)
            },
            _ => { },
        }
    }

    pub fn new_file_tx(&mut self, file_handle: &Vec<u8>, file_name: &Vec<u8>, direction: Direction)
        -> &mut NFSTransaction
    {
        let mut tx = self.new_tx();
        tx.file_name = file_name.to_vec();
        tx.file_handle = file_handle.to_vec();
        tx.is_file_tx = true;
        tx.file_tx_direction = direction;

        tx.type_data = Some(NFSTransactionTypeData::FILE(NFSTransactionFile::new()));
        if let Some(NFSTransactionTypeData::FILE(ref mut d)) = tx.type_data {
            d.file_tracker.tx_id = tx.id - 1;
            tx.tx_data.update_file_flags(self.state_data.file_flags);
            d.update_file_flags(tx.tx_data.file_flags);
        }
        tx.tx_data.init_files_opened();
        tx.tx_data.file_tx = if direction == Direction::ToServer { STREAM_TOSERVER } else { STREAM_TOCLIENT }; // TODO direction to flag func?
        SCLogDebug!("new_file_tx: TX FILE created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(file_name));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        tx_ref.unwrap()
    }

    pub fn get_file_tx_by_handle(&mut self, file_handle: &Vec<u8>, direction: Direction)
        -> Option<&mut NFSTransaction>
    {
        let fh = file_handle.to_vec();
        for tx in &mut self.transactions {
            if let Some(NFSTransactionTypeData::FILE(ref mut d)) = tx.type_data {
                if tx.is_file_tx && !tx.is_file_closed &&
                    direction == tx.file_tx_direction &&
                        tx.file_handle == fh
                {
                    tx.tx_data.update_file_flags(self.state_data.file_flags);
                    d.update_file_flags(tx.tx_data.file_flags);
                    SCLogDebug!("Found NFS file TX with ID {} XID {:04X}", tx.id, tx.xid);
                    return Some(tx);
                }
            }
        }
        SCLogDebug!("Failed to find NFS TX with handle {:?}", file_handle);
        None
    }

    pub fn process_write_record<'b>(&mut self, r: &RpcPacket<'b>, w: &Nfs3RequestWrite<'b>) -> u32 {
        let mut fill_bytes = 0;
        let pad = w.count % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }

        // linux defines a max of 1mb. Allow several multiples.
        if w.count == 0 || w.count > 16777216 {
            return 0;
        }

        // for now assume that stable FILE_SYNC flags means a single chunk
        let is_last = w.stable == 2;
        let file_handle = w.handle.value.to_vec();
        let file_name = if let Some(name) = self.namemap.get(w.handle.value) {
            SCLogDebug!("WRITE name {:?}", name);
            name.to_vec()
        } else {
            SCLogDebug!("WRITE object {:?} not found", w.handle.value);
            Vec::new()
        };

        let found = match self.get_file_tx_by_handle(&file_handle, Direction::ToServer) {
            Some(tx) => {
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    let (files, flags) = tdf.files.get(Direction::ToServer);
                    filetracker_newchunk(&mut tdf.file_tracker, files, flags,
                            &file_name, w.file_data, w.offset,
                            w.file_len, fill_bytes as u8, is_last, &r.hdr.xid);
                    tdf.chunk_count += 1;
                    if is_last {
                        tdf.file_last_xid = r.hdr.xid;
                        tx.is_last = true;
                        tx.response_done = true;
                        tx.is_file_closed = true;
                    }
                    true
                } else {
                    false
                }
            },
            None => { false },
        };
        if !found {
            let tx = self.new_file_tx(&file_handle, &file_name, Direction::ToServer);
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                let (files, flags) = tdf.files.get(Direction::ToServer);
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
                    tx.is_file_closed = true;
                }
            }
        }
        if !self.is_udp {
            self.ts_chunk_xid = r.hdr.xid;
            debug_validate_bug_on!(w.file_data.len() as u32 > w.count);
            self.ts_chunk_left = w.count - w.file_data.len() as u32;
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

        self.process_write_record(r, w)
    }

    fn process_reply_record<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice, r: &RpcReplyPacket<'b>) -> u32 {
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
                self.add_nfs_tc_frames(flow, stream_slice, r.prog_data, r.prog_data_size as i64);
                self.process_reply_record_v2(r, &xidmap);
                0
            },
            3 => {
                SCLogDebug!("NFSv3 reply record");
                self.add_nfs_tc_frames(flow, stream_slice, r.prog_data, r.prog_data_size as i64);
                self.process_reply_record_v3(r, &mut xidmap);
                0
            },
            4 => {
                SCLogDebug!("NFSv4 reply record");
                self.add_nfs4_tc_frames(flow, stream_slice, r.prog_data, r.prog_data_size as i64);
                self.process_reply_record_v4(r, &mut xidmap);
                0
            },
            _ => {
                SCLogDebug!("Invalid NFS version");
                self.set_event(NFSEvent::NonExistingVersion);
                0
            },
        }
    }

    // update in progress chunks for file transfers
    // return how much data we consumed
    fn filetracker_update(&mut self, direction: Direction, data: &[u8], gap_size: u32) -> u32 {
        let mut chunk_left = if direction == Direction::ToServer {
            self.ts_chunk_left
        } else {
            self.tc_chunk_left
        };
        if chunk_left == 0 {
            return 0
        }
        let xid = if direction == Direction::ToServer {
            self.ts_chunk_xid
        } else {
            self.tc_chunk_xid
        };
        SCLogDebug!("filetracker_update: chunk left {}, input {} chunk_xid {:04X}", chunk_left, data.len(), xid);

        let file_handle;
        // we have the data that we expect
        if chunk_left <= data.len() as u32 {
            chunk_left = 0;

            if direction == Direction::ToServer {
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

            if direction == Direction::ToServer {
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

        if direction == Direction::ToServer {
            self.ts_chunk_left = chunk_left;
        } else {
            self.tc_chunk_left = chunk_left;
        }

        let ssn_gap = self.ts_ssn_gap | self.tc_ssn_gap;
        // get the tx and update it
        let consumed = match self.get_file_tx_by_handle(&file_handle, direction) {
            Some(tx) => {
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    let (files, flags) = tdf.files.get(direction);
                    if ssn_gap {
                        let queued_data = tdf.file_tracker.get_queued_size();
                        if queued_data > 2000000 { // TODO should probably be configurable
                            SCLogDebug!("QUEUED size {} while we've seen GAPs. Truncating file.", queued_data);
                            tdf.file_tracker.trunc(files, flags);
                        }
                    }

                    // reset timestamp if we get called after a gap
                    if tdf.post_gap_ts > 0 {
                        tdf.post_gap_ts = 0;
                    }

                    tdf.chunk_count += 1;
                    let cs = tdf.file_tracker.update(files, flags, data, gap_size);
                    /* see if we need to close the tx */
                    if tdf.file_tracker.is_done() {
                        if direction == Direction::ToClient {
                            tx.response_done = true;
                            tx.is_file_closed = true;
                            SCLogDebug!("TX {} response is done now that the file track is ready", tx.id);
                        } else {
                            tx.request_done = true;
                            tx.is_file_closed = true;
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
        consumed
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

        let mut fill_bytes = 0;
        let pad = reply.count % 4;
        if pad != 0 {
            fill_bytes = 4 - pad;
        }

        // linux defines a max of 1mb. Allow several multiples.
        if reply.count == 0 || reply.count > 16777216 {
            return 0;
        }

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
        SCLogDebug!("XID {} is_last {} fill_bytes {} reply.count {} reply.data_len {} reply.data.len() {}",
                r.hdr.xid, is_last, fill_bytes, reply.count, reply.data_len, reply.data.len());

        if nfs_version == 2 {
            let size = match parse_nfs2_attribs(reply.attr_blob) {
                Ok((_, ref attr)) => attr.asize,
                _ => 0,
            };
            SCLogDebug!("NFSv2 READ reply record: File size {}. Offset {} data len {}: total {}",
                    size, chunk_offset, reply.data_len, chunk_offset + reply.data_len as u64);

            if size as u64 == chunk_offset + reply.data_len as u64 {
                is_last = true;
            }

        }

        let is_partial = reply.data.len() < reply.count as usize;
        SCLogDebug!("partial data? {}", is_partial);

        let found = match self.get_file_tx_by_handle(&file_handle, Direction::ToClient) {
            Some(tx) => {
                SCLogDebug!("updated TX {:?}", tx);
                if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    let (files, flags) = tdf.files.get(Direction::ToClient);
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
            let tx = self.new_file_tx(&file_handle, &file_name, Direction::ToClient);
            if let Some(NFSTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                let (files, flags) = tdf.files.get(Direction::ToClient);
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
            debug_validate_bug_on!(reply.data.len() as u32 > reply.count);
            self.tc_chunk_left = reply.count - reply.data.len() as u32;
        }

        SCLogDebug!("REPLY {} to procedure {} blob size {} / {}: chunk_left {} chunk_xid {:04X}",
                r.hdr.xid, NFSPROC3_READ, r.prog_data.len(), reply.count, self.tc_chunk_left,
                self.tc_chunk_xid);
        0
    }

    fn process_partial_read_reply_record<'b>(&mut self, r: &RpcReplyPacket<'b>, reply: &NfsReplyRead<'b>) -> u32 {
        SCLogDebug!("REPLY {} to procedure READ blob size {} / {}",
                r.hdr.xid, r.prog_data.len(), reply.count);

        self.process_read_record(r, reply, None)
    }

    fn peek_reply_record(&mut self, r: &RpcPacketHeader) -> u32 {
        if let Some(xidmap) = self.requestmap.get(&r.xid) {
            xidmap.procedure
        } else {
            SCLogDebug!("REPLY: xid {} NOT FOUND", r.xid);
            0
        }
    }

    pub fn parse_tcp_data_ts_gap<'b>(&mut self, gap_size: u32) -> AppLayerResult {
        SCLogDebug!("parse_tcp_data_ts_gap ({})", gap_size);
        let gap = vec![0; gap_size as usize];
        let consumed = self.filetracker_update(Direction::ToServer, &gap, gap_size);
        if consumed > gap_size {
            SCLogDebug!("consumed more than GAP size: {} > {}", consumed, gap_size);
            return AppLayerResult::ok();
        }
        self.ts_ssn_gap = true;
        self.ts_gap = true;
        SCLogDebug!("parse_tcp_data_ts_gap ({}) done", gap_size);
        AppLayerResult::ok()
    }

    pub fn parse_tcp_data_tc_gap<'b>(&mut self, gap_size: u32) -> AppLayerResult {
        SCLogDebug!("parse_tcp_data_tc_gap ({})", gap_size);
        let gap = vec![0; gap_size as usize];
        let consumed = self.filetracker_update(Direction::ToClient, &gap, gap_size);
        if consumed > gap_size {
            SCLogDebug!("consumed more than GAP size: {} > {}", consumed, gap_size);
            return AppLayerResult::ok();
        }
        self.tc_ssn_gap = true;
        self.tc_gap = true;
        SCLogDebug!("parse_tcp_data_tc_gap ({}) done", gap_size);
        AppLayerResult::ok()
    }

    /// Handle partial records
    fn parse_tcp_partial_data_ts<'b>(&mut self, base_input: &'b[u8], cur_i: &'b[u8],
            phdr: &RpcRequestPacketPartial, rec_size: usize) -> AppLayerResult {
        // special case: avoid buffering file write blobs
        // as these can be large.
        if rec_size >= 512 && cur_i.len() >= 44 {
            // large record, likely file xfer
            SCLogDebug!("large record {}, likely file xfer", rec_size);

            // quick peek, are we in WRITE mode?
            if phdr.procedure == NFSPROC3_WRITE {
                SCLogDebug!("CONFIRMED WRITE: large record {}, file chunk xfer", rec_size);

                // lets try to parse the RPC record. Might fail with Incomplete.
                match parse_rpc(cur_i, false) {
                    Ok((_rem, ref hdr)) => {
                        // we got here because rec_size > input, so we should never have
                        // remaining data
                        debug_validate_bug_on!(_rem.len() != 0);

                        match parse_nfs3_request_write(hdr.prog_data, false) {
                            Ok((_, ref w)) => {
                                // deal with the partial nfs write data
                                self.process_partial_write_request_record(hdr, w);
                                return AppLayerResult::ok();
                            }
                            Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                                self.set_event(NFSEvent::MalformedData);
                                SCLogDebug!("Parsing failed: {:?}", _e);
                                return AppLayerResult::err();
                            }
                            Err(Err::Incomplete(_)) => {
                                // this is normal, fall through to incomplete handling
                            }
                        }
                    }
                    Err(Err::Incomplete(_)) => {
                        // size check was done for a minimal RPC record size,
                        // so Incomplete is normal.
                        SCLogDebug!("TS data incomplete");
                    }
                    Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                        self.set_event(NFSEvent::MalformedData);
                        SCLogDebug!("Parsing failed: {:?}", _e);
                        return AppLayerResult::err();
                    }
                }
            }
        }
        // make sure we pass a value higher than current input
        // but lower than the record size
        let n1 = cmp::max(cur_i.len(), 1024);
        let n2 = cmp::min(n1, rec_size);
        AppLayerResult::incomplete((base_input.len() - cur_i.len()) as u32, n2 as u32)
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_ts<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult {
        let mut cur_i = stream_slice.as_slice();
        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(Direction::ToServer, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                return AppLayerResult::err();
            }
            cur_i = &cur_i[consumed as usize..];
        }
        if cur_i.is_empty() {
            return AppLayerResult::ok();
        }
        if self.ts_gap {
            SCLogDebug!("TS trying to catch up after GAP (input {})", cur_i.len());

            let mut _cnt = 0;
            while !cur_i.is_empty() {
                _cnt += 1;
                match nfs_probe(cur_i, Direction::ToServer) {
                    1 => {
                        SCLogDebug!("expected data found");
                        self.ts_gap = false;
                        break;
                    },
                    0 => {
                        SCLogDebug!("incomplete, queue and retry with the next block (input {}). Looped {} times.",
                                cur_i.len(), _cnt);
                        return AppLayerResult::incomplete(stream_slice.len() - cur_i.len() as u32, (cur_i.len() + 1) as u32);
                    },
                    -1 => {
                        cur_i = &cur_i[1..];
                        if cur_i.is_empty() {
                            SCLogDebug!("all post-GAP data in this chunk was bad. Looped {} times.", _cnt);
                        }
                    },
                    _ => {
                        return AppLayerResult::err();
                    },
                }
            }
            SCLogDebug!("TS GAP handling done (input {})", cur_i.len());
        }

        while !cur_i.is_empty() { // min record size
            self.add_rpc_tcp_ts_pdu(flow, stream_slice, cur_i, cur_i.len() as i64);
            match parse_rpc_request_partial(cur_i) {
                Ok((_, ref rpc_phdr)) => {
                    let rec_size = (rpc_phdr.hdr.frag_len + 4) as usize;

                    // Handle partial records
                    if rec_size > cur_i.len() {
                        return self.parse_tcp_partial_data_ts(stream_slice.as_slice(), cur_i, rpc_phdr, rec_size);
                    }

                    // we have the full records size worth of data,
                    // let's parse it. Errors lead to event, but are
                    // not fatal as we already have enough info to
                    // go to the next record.
                    match parse_rpc(cur_i, true) {
                        Ok((_, ref rpc_record)) => {
                            self.add_rpc_tcp_ts_creds(flow, stream_slice, &cur_i[RPC_TCP_PRE_CREDS..], (rpc_record.creds_len + 8) as i64);
                            self.process_request_record(flow, stream_slice, rpc_record);
                        }
                        Err(Err::Incomplete(_)) => {
                            self.set_event(NFSEvent::MalformedData);
                        }
                        Err(Err::Error(_e)) |
                        Err(Err::Failure(_e)) => {
                            self.set_event(NFSEvent::MalformedData);
                            SCLogDebug!("Parsing failed: {:?}", _e);
                        }
                    }
                    cur_i = &cur_i[rec_size..];
                }
                Err(Err::Incomplete(needed)) => {
                    if let Needed::Size(n) = needed {
                        SCLogDebug!("Not enough data for partial RPC header {:?}", needed);
                        // 28 is the partial RPC header size parse_rpc_request_partial
                        // looks for.
                        let n = usize::from(n);
                        let need = if n > 28 { n } else { 28 };
                        return AppLayerResult::incomplete(stream_slice.len() - cur_i.len() as u32, need as u32);
                    }
                    return AppLayerResult::err();
                }
                /* This error is fatal. If we failed to parse the RPC hdr we don't
                 * have a length and we don't know where the next record starts. */
                Err(Err::Error(_e)) |
                Err(Err::Failure(_e)) => {
                    self.set_event(NFSEvent::MalformedData);
                    SCLogDebug!("Parsing failed: {:?}", _e);
                    return AppLayerResult::err();
                }
            }
        };

        self.post_gap_housekeeping(Direction::ToServer);
        if self.check_post_gap_file_txs && !self.post_gap_files_checked {
            self.post_gap_housekeeping_for_files();
            self.post_gap_files_checked = true;
        }

        AppLayerResult::ok()
    }

    /// Handle partial records
    fn parse_tcp_partial_data_tc<'b>(&mut self, base_input: &'b[u8], cur_i: &'b[u8],
            phdr: &RpcPacketHeader, rec_size: usize) -> AppLayerResult {
        // special case: avoid buffering file read blobs
        // as these can be large.
        if rec_size >= 512 && cur_i.len() >= 128 {//36 {
            // large record, likely file xfer
            SCLogDebug!("large record {}, likely file xfer", rec_size);

            // quick peek, are in READ mode?
            if self.peek_reply_record(phdr) == NFSPROC3_READ {
                SCLogDebug!("CONFIRMED large READ record {}, likely file chunk xfer", rec_size);

                // we should have enough data to parse the RPC record
                match parse_rpc_reply(cur_i, false) {
                    Ok((_rem, ref hdr)) => {
                        // we got here because rec_size > input, so we should never have
                        // remaining data
                        debug_validate_bug_on!(_rem.len() != 0);

                        match parse_nfs3_reply_read(hdr.prog_data, false) {
                            Ok((_, ref r)) => {
                                // deal with the partial nfs read data
                                self.process_partial_read_reply_record(hdr, r);
                                return AppLayerResult::ok();
                            }
                            Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                                self.set_event(NFSEvent::MalformedData);
                                SCLogDebug!("Parsing failed: {:?}", _e);
                                return AppLayerResult::err();
                            }
                            Err(Err::Incomplete(_)) => {
                                // this is normal, fall through to incomplete handling
                            }
                        }
                    }
                    Err(Err::Incomplete(_)) => {
                        // size check was done for a minimal RPC record size,
                        // so Incomplete is normal.
                        SCLogDebug!("TC data incomplete");
                    }
                    Err(Err::Error(_e)) | Err(Err::Failure(_e)) => {
                        self.set_event(NFSEvent::MalformedData);
                        SCLogDebug!("Parsing failed: {:?}", _e);
                        return AppLayerResult::err();
                    }
                }
            }
        }
        // make sure we pass a value higher than current input
        // but lower than the record size
        let n1 = cmp::max(cur_i.len(), 1024);
        let n2 = cmp::min(n1, rec_size);
        AppLayerResult::incomplete((base_input.len() - cur_i.len()) as u32, n2 as u32)
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_tc<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult {
        let mut cur_i = stream_slice.as_slice();
        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(Direction::ToClient, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                return AppLayerResult::err();
            }
            cur_i = &cur_i[consumed as usize..];
        }
        if cur_i.is_empty() {
            return AppLayerResult::ok();
        }
        if self.tc_gap {
            SCLogDebug!("TC trying to catch up after GAP (input {})", cur_i.len());

            let mut _cnt = 0;
            while !cur_i.is_empty() {
                _cnt += 1;
                match nfs_probe(cur_i, Direction::ToClient) {
                    1 => {
                        SCLogDebug!("expected data found");
                        self.tc_gap = false;
                        break;
                    },
                    0 => {
                        SCLogDebug!("incomplete, queue and retry with the next block (input {}). Looped {} times.",
                                cur_i.len(), _cnt);
                        return AppLayerResult::incomplete(stream_slice.len() - cur_i.len() as u32, (cur_i.len() + 1) as u32);
                    },
                    -1 => {
                        cur_i = &cur_i[1..];
                        if cur_i.is_empty() {
                            SCLogDebug!("all post-GAP data in this chunk was bad. Looped {} times.", _cnt);
                        }
                    },
                    _ => {
                        return AppLayerResult::err();
                    }
                }
            }
            SCLogDebug!("TC GAP handling done (input {})", cur_i.len());
        }

        while !cur_i.is_empty() {
            self.add_rpc_tcp_tc_pdu(flow, stream_slice, cur_i, cur_i.len() as i64);
            match parse_rpc_packet_header(cur_i) {
                Ok((_, ref rpc_phdr)) => {
                    let rec_size = (rpc_phdr.frag_len + 4) as usize;
                    // see if we have all data available
                    if rec_size > cur_i.len() {
                        return self.parse_tcp_partial_data_tc(stream_slice.as_slice(), cur_i, rpc_phdr, rec_size);
                    }

                    // we have the full data of the record, lets parse
                    match parse_rpc_reply(cur_i, true) {
                        Ok((_, ref rpc_record)) => {
                            self.add_rpc_tcp_tc_frames(flow, stream_slice, cur_i, cur_i.len() as i64);
                            self.process_reply_record(flow, stream_slice, rpc_record);
                        }
                        Err(Err::Incomplete(_)) => {
                            // we shouldn't get incomplete as we have the full data
                            // so if we got incomplete anyway it's the data that is
                            // bad.
                            self.set_event(NFSEvent::MalformedData);
                        }
                        Err(Err::Error(_e)) |
                        Err(Err::Failure(_e)) => {
                            self.set_event(NFSEvent::MalformedData);
                            SCLogDebug!("Parsing failed: {:?}", _e);
                        }
                    }
                    cur_i = &cur_i[rec_size..]; // progress input past parsed record
                }
                Err(Err::Incomplete(needed)) => {
                    if let Needed::Size(n) = needed {
                        SCLogDebug!("Not enough data for partial RPC header {:?}", needed);
                        // 12 is the partial RPC header size parse_rpc_packet_header
                        // looks for.
                        let n = usize::from(n);
                        let need = if n > 12 { n } else { 12 };
                        return AppLayerResult::incomplete(stream_slice.len() - cur_i.len() as u32, need as u32);
                    }
                    return AppLayerResult::err();
                }
                /* This error is fatal. If we failed to parse the RPC hdr we don't
                 * have a length and we don't know where the next record starts. */
                Err(Err::Error(_e)) |
                Err(Err::Failure(_e)) => {
                    self.set_event(NFSEvent::MalformedData);
                    SCLogDebug!("Parsing failed: {:?}", _e);
                    return AppLayerResult::err();
                }
            }
        };
        self.post_gap_housekeeping(Direction::ToClient);
        if self.check_post_gap_file_txs && !self.post_gap_files_checked {
            self.post_gap_housekeeping_for_files();
            self.post_gap_files_checked = true;
        }
        AppLayerResult::ok()
    }
    /// Parsing function
    pub fn parse_udp_ts<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        SCLogDebug!("parse_udp_ts ({})", input.len());
        self.add_rpc_udp_ts_pdu(flow, stream_slice, input, input.len() as i64);
        if !input.is_empty() {
            match parse_rpc_udp_request(input) {
                Ok((_, ref rpc_record)) => {
                    self.is_udp = true;
                    self.add_rpc_udp_ts_creds(flow, stream_slice, &input[RPC_UDP_PRE_CREDS..], (rpc_record.creds_len + 8) as i64);
                    match rpc_record.progver {
                        3 => {
                            self.process_request_record(flow, stream_slice, rpc_record);
                        },
                        2 => {
                            self.add_nfs_ts_frame(flow, stream_slice, rpc_record.prog_data, rpc_record.prog_data_size as i64);
                            self.process_request_record_v2(rpc_record);
                        },
                        _ => { },
                    }
                },
                Err(Err::Incomplete(_)) => {
                },
                Err(Err::Error(_e)) |
                Err(Err::Failure(_e)) => {
                    SCLogDebug!("Parsing failed: {:?}", _e);
                }
            }
        }
        AppLayerResult::ok()
    }

    /// Parsing function
    pub fn parse_udp_tc<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        SCLogDebug!("parse_udp_tc ({})", input.len());
        self.add_rpc_udp_tc_pdu(flow, stream_slice, input, input.len() as i64);
        if !input.is_empty() {
            match parse_rpc_udp_reply(input) {
                Ok((_, ref rpc_record)) => {
                    self.is_udp = true;
                    self.add_rpc_udp_tc_frames(flow, stream_slice, input, input.len() as i64);
                    self.process_reply_record(flow, stream_slice, rpc_record);
                },
                Err(Err::Incomplete(_)) => {
                },
                Err(Err::Error(_e)) |
                Err(Err::Failure(_e)) => {
                    SCLogDebug!("Parsing failed: {:?}", _e);
                }
            }
        }
        AppLayerResult::ok()
    }
}

/// Returns *mut NFSState
#[no_mangle]
pub extern "C" fn rs_nfs_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = NFSState::new();
    let boxed = Box::new(state);
    SCLogDebug!("allocating state");
    Box::into_raw(boxed) as *mut _
}

/// Params:
/// - state: *mut NFSState as void pointer
#[no_mangle]
pub extern "C" fn rs_nfs_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    SCLogDebug!("freeing state");
    std::mem::drop(unsafe { Box::from_raw(state as *mut NFSState) });
}

/// C binding parse a NFS TCP request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn rs_nfs_parse_request(flow: *const Flow,
                                       state: *mut std::os::raw::c_void,
                                       _pstate: *mut std::os::raw::c_void,
                                       stream_slice: StreamSlice,
                                       _data: *const std::os::raw::c_void,
                                       ) -> AppLayerResult
{
    let state = cast_pointer!(state, NFSState);
    let flow = cast_pointer!(flow, Flow);

    if stream_slice.is_gap() {
        return rs_nfs_parse_request_tcp_gap(state, stream_slice.gap_size());
    }
    SCLogDebug!("parsing {} bytes of request data", stream_slice.len());

    state.update_ts(flow.get_last_time().as_secs());
    state.parse_tcp_data_ts(flow, &stream_slice)
}

#[no_mangle]
pub extern "C" fn rs_nfs_parse_request_tcp_gap(
                                        state: &mut NFSState,
                                        input_len: u32)
                                        -> AppLayerResult
{
    state.parse_tcp_data_ts_gap(input_len as u32)
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_parse_response(flow: *const Flow,
                                        state: *mut std::os::raw::c_void,
                                        _pstate: *mut std::os::raw::c_void,
                                        stream_slice: StreamSlice,
                                        _data: *const std::os::raw::c_void,
                                        ) -> AppLayerResult
{
    let state = cast_pointer!(state, NFSState);
    let flow = cast_pointer!(flow, Flow);

    if stream_slice.is_gap() {
        return rs_nfs_parse_response_tcp_gap(state, stream_slice.gap_size());
    }
    SCLogDebug!("parsing {} bytes of response data", stream_slice.len());

    state.update_ts(flow.get_last_time().as_secs());
    state.parse_tcp_data_tc(flow, &stream_slice)
}

#[no_mangle]
pub extern "C" fn rs_nfs_parse_response_tcp_gap(
                                        state: &mut NFSState,
                                        input_len: u32)
                                        -> AppLayerResult
{
    state.parse_tcp_data_tc_gap(input_len as u32)
}

/// C binding to parse an NFS/UDP request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn rs_nfs_parse_request_udp(f: *const Flow,
                                       state: *mut std::os::raw::c_void,
                                       _pstate: *mut std::os::raw::c_void,
                                       stream_slice: StreamSlice,
                                       _data: *const std::os::raw::c_void,
                                       ) -> AppLayerResult
{
    let state = cast_pointer!(state, NFSState);

    SCLogDebug!("parsing {} bytes of request data", stream_slice.len());
    state.parse_udp_ts(f, &stream_slice)
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_parse_response_udp(f: *const Flow,
                                        state: *mut std::os::raw::c_void,
                                        _pstate: *mut std::os::raw::c_void,
                                        stream_slice: StreamSlice,
                                        _data: *const std::os::raw::c_void,
                                        ) -> AppLayerResult
{
    let state = cast_pointer!(state, NFSState);
    SCLogDebug!("parsing {} bytes of response data", stream_slice.len());
    state.parse_udp_tc(f, &stream_slice)
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_state_get_tx_count(state: *mut std::os::raw::c_void)
                                            -> u64
{
    let state = cast_pointer!(state, NFSState);
    SCLogDebug!("rs_nfs_state_get_tx_count: returning {}", state.tx_id);
    state.tx_id
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_state_get_tx(state: *mut std::os::raw::c_void,
                                      tx_id: u64)
                                      -> *mut std::os::raw::c_void
{
    let state = cast_pointer!(state, NFSState);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => {
            tx as *const _ as *mut _
        }
        None => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_state_tx_free(state: *mut std::os::raw::c_void,
                                       tx_id: u64)
{
    let state = cast_pointer!(state, NFSState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_tx_get_alstate_progress(tx: *mut std::os::raw::c_void,
                                                  direction: u8)
                                                  -> std::os::raw::c_int
{
    let tx = cast_pointer!(tx, NFSTransaction);
    if direction == Direction::ToServer.into() && tx.request_done {
        //SCLogNotice!("TOSERVER progress 1");
        1
    } else if direction == Direction::ToClient.into() && tx.response_done {
        //SCLogNotice!("TOCLIENT progress 1");
        1
    } else {
        //SCLogNotice!("{} progress 0", direction);
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_get_tx_data(
    tx: *mut std::os::raw::c_void)
    -> *mut AppLayerTxData
{
    let tx = cast_pointer!(tx, NFSTransaction);
    &mut tx.tx_data
}

export_state_data_get!(rs_nfs_get_state_data, NFSState);

/// return procedure(s) in the tx. At 0 return the main proc,
/// otherwise get procs from the 'file_additional_procs'.
/// Keep calling until 0 is returned.
#[no_mangle]
pub unsafe extern "C" fn rs_nfs_tx_get_procedures(tx: &mut NFSTransaction,
                                           i: u16,
                                           procedure: *mut u32)
                                           -> u8
{
    if i == 0 {
        *procedure = tx.procedure as u32;
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
            *procedure = p as u32;
            return 1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_tx_get_version(tx: &mut NFSTransaction,
                                        version: *mut u32)
{
    *version = tx.nfs_version as u32;
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_init(context: &'static mut SuricataFileContext)
{
    SURICATA_NFS_FILE_CONFIG = Some(context);
}

fn nfs_probe_dir(i: &[u8], rdir: *mut u8) -> i8 {
    match parse_rpc_packet_header(i) {
        Ok((_, ref hdr)) => {
            let dir = if hdr.msgtype == 0 {
                Direction::ToServer
            } else {
                Direction::ToClient
            };
            unsafe { *rdir = dir as u8 };
            1
        },
        Err(Err::Incomplete(_)) => {
            0
        },
        Err(_) => {
            -1
        },
    }
}

pub fn nfs_probe(i: &[u8], direction: Direction) -> i32 {
    if direction == Direction::ToClient {
        match parse_rpc_reply(i, false) {
            Ok((_, ref rpc)) => {
                if rpc.hdr.frag_len >= 24 && rpc.hdr.frag_len <= 35000 && rpc.hdr.msgtype == 1 && rpc.reply_state == 0 && rpc.accept_state == 0 {
                    SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc.hdr.frag_len, rpc.hdr.xid, rpc.hdr.msgtype);
                    1
                } else {
                    -1
                }
            },
            Err(Err::Incomplete(_)) => {
                match parse_rpc_packet_header (i) {
                    Ok((_, ref rpc_hdr)) => {
                        if rpc_hdr.frag_len >= 24 && rpc_hdr.frag_len <= 35000 && rpc_hdr.xid != 0 && rpc_hdr.msgtype == 1 {
                            SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc_hdr.frag_len, rpc_hdr.xid, rpc_hdr.msgtype);
                            1
                        } else {
                            -1
                        }
                    },
                    Err(Err::Incomplete(_)) => {
                        0
                    },
                    Err(_) => {
                        -1
                    },
                }
            },
            Err(_) => {
                -1
            },
        }
    } else {
        match parse_rpc(i, false) {
            Ok((_, ref rpc)) => {
                if rpc.hdr.frag_len >= 40 && rpc.hdr.msgtype == 0 &&
                   rpc.rpcver == 2 && (rpc.progver == 3 || rpc.progver == 4) &&
                   rpc.program == 100003 &&
                   rpc.procedure <= NFSPROC3_COMMIT
                {
                    rpc_auth_type_known(rpc.creds_flavor) as i32
                } else {
                    -1
                }
            },
            Err(Err::Incomplete(_)) => {
                0
            },
            Err(_) => {
                -1
            },
        }
    }
}

pub fn nfs_probe_udp(i: &[u8], direction: Direction) -> i32 {
    if direction == Direction::ToClient {
        match parse_rpc_udp_reply(i) {
            Ok((_, ref rpc)) => {
                if i.len() >= 32 && rpc.hdr.msgtype == 1 && rpc.reply_state == 0 && rpc.accept_state == 0 {
                    SCLogDebug!("TC PROBE LEN {} XID {} TYPE {}", rpc.hdr.frag_len, rpc.hdr.xid, rpc.hdr.msgtype);
                    1
                } else {
                    -1
                }
            },
            Err(_) => {
                -1
            },
        }
    } else {
        match parse_rpc_udp_request(i) {
            Ok((_, ref rpc)) => {
                if i.len() >= 48 && rpc.hdr.msgtype == 0 && rpc.progver == 3 && rpc.program == 100003 {
                    1
                } else if i.len() >= 48 && rpc.hdr.msgtype == 0 && rpc.progver == 2 && rpc.program == 100003 {
                    SCLogDebug!("NFSv2!");
                    1
                } else {
                    -1
                }
            },
            Err(_) => {
                -1
            },
        }
    }
}

/// MIDSTREAM
#[no_mangle]
pub unsafe extern "C" fn rs_nfs_probe_ms(
        _flow: *const Flow,
        direction: u8, input: *const u8,
        len: u32, rdir: *mut u8) -> AppProto
{
    let slice: &[u8] = build_slice!(input, len as usize);
    SCLogDebug!("rs_nfs_probe_ms: probing direction {:02x}", direction);
    let mut adirection : u8 = 0;
    match nfs_probe_dir(slice, &mut adirection) {
        1 => {
            if adirection == Direction::ToServer.into() {
                SCLogDebug!("nfs_probe_dir said Direction::ToServer");
            } else {
                SCLogDebug!("nfs_probe_dir said Direction::ToClient");
            }
            match nfs_probe(slice, adirection.into()) {
                1 => {
                    SCLogDebug!("nfs_probe success: dir {:02x} adir {:02x}", direction, adirection);
                    if (direction & DIR_BOTH) != adirection {
                        *rdir = adirection;
                    }
                    ALPROTO_NFS
                },
                0 => { ALPROTO_UNKNOWN },
                _ => { ALPROTO_FAILED },
            }
        },
        0 => {
            ALPROTO_UNKNOWN
        },
        _ => {
            ALPROTO_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_probe(_f: *const Flow,
                               direction: u8,
                               input: *const u8,
                               len: u32,
                               _rdir: *mut u8)
    -> AppProto
{
    let slice: &[u8] = build_slice!(input, len as usize);
    SCLogDebug!("rs_nfs_probe: running probe");
    match nfs_probe(slice, direction.into()) {
        1 => { ALPROTO_NFS },
        -1 => { ALPROTO_FAILED },
        _ => { ALPROTO_UNKNOWN },
    }
}

/// TOSERVER probe function
#[no_mangle]
pub unsafe extern "C" fn rs_nfs_probe_udp_ts(_f: *const Flow,
                               _direction: u8,
                               input: *const u8,
                               len: u32,
                               _rdir: *mut u8)
    -> AppProto
{
    let slice: &[u8] = build_slice!(input, len as usize);
    match nfs_probe_udp(slice, Direction::ToServer) {
        1 => { ALPROTO_NFS },
        -1 => { ALPROTO_FAILED },
        _ => { ALPROTO_UNKNOWN },
    }
}

/// TOCLIENT probe function
#[no_mangle]
pub unsafe extern "C" fn rs_nfs_probe_udp_tc(_f: *const Flow,
                               _direction: u8,
                               input: *const u8,
                               len: u32,
                               _rdir: *mut u8)
    -> AppProto
{
    let slice: &[u8] = build_slice!(input, len as usize);
    match nfs_probe_udp(slice, Direction::ToClient) {
        1 => { ALPROTO_NFS },
        -1 => { ALPROTO_FAILED },
        _ => { ALPROTO_UNKNOWN },
    }
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"nfs\0";

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_register_parser() {
    let default_port = CString::new("[2049]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_nfs_state_new,
        state_free: rs_nfs_state_free,
        tx_free: rs_nfs_state_tx_free,
        parse_ts: rs_nfs_parse_request,
        parse_tc: rs_nfs_parse_response,
        get_tx_count: rs_nfs_state_get_tx_count,
        get_tx: rs_nfs_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_nfs_tx_get_alstate_progress,
        get_eventinfo: Some(NFSEvent::get_event_info),
        get_eventinfo_byid : Some(NFSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: Some(rs_nfs_gettxfiles),
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<NFSState, NFSTransaction>),
        get_tx_data: rs_nfs_get_tx_data,
        get_state_data: rs_nfs_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: Some(NFSFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(NFSFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_NFS = alproto;

        let midstream = conf_get_bool("stream.midstream");
        if midstream {
            if AppLayerProtoDetectPPParseConfPorts(ip_proto_str.as_ptr(), IPPROTO_TCP as u8,
                    parser.name, ALPROTO_NFS, 0, NFS_MIN_FRAME_LEN,
                    rs_nfs_probe_ms, rs_nfs_probe_ms) == 0 {
                SCLogDebug!("No NFSTCP app-layer configuration, enabling NFSTCP
                            detection TCP detection on port {:?}.",
                            default_port);
                /* register 'midstream' probing parsers if midstream is enabled. */
                AppLayerProtoDetectPPRegister(IPPROTO_TCP as u8,
                    default_port.as_ptr(), ALPROTO_NFS, 0,
                    NFS_MIN_FRAME_LEN, Direction::ToServer.into(),
                    rs_nfs_probe_ms, rs_nfs_probe_ms);
            }
        } else {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP as u8,
                default_port.as_ptr(), ALPROTO_NFS, 0,
                NFS_MIN_FRAME_LEN, Direction::ToServer.into(),
                rs_nfs_probe, rs_nfs_probe);
        }
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust nfs parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for nfs.");
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_nfs_udp_register_parser() {
    let default_port = CString::new("[2049]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_UDP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_nfs_state_new,
        state_free: rs_nfs_state_free,
        tx_free: rs_nfs_state_tx_free,
        parse_ts: rs_nfs_parse_request_udp,
        parse_tc: rs_nfs_parse_response_udp,
        get_tx_count: rs_nfs_state_get_tx_count,
        get_tx: rs_nfs_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_nfs_tx_get_alstate_progress,
        get_eventinfo: Some(NFSEvent::get_event_info),
        get_eventinfo_byid : Some(NFSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: Some(rs_nfs_gettxfiles),
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<NFSState, NFSTransaction>),
        get_tx_data: rs_nfs_get_tx_data,
        get_state_data: rs_nfs_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate: None,
        get_frame_id_by_name: Some(NFSFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(NFSFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_NFS = alproto;

        if AppLayerProtoDetectPPParseConfPorts(ip_proto_str.as_ptr(), IPPROTO_UDP as u8,
                parser.name, ALPROTO_NFS, 0, NFS_MIN_FRAME_LEN,
                rs_nfs_probe_udp_ts, rs_nfs_probe_udp_tc) == 0 {
            SCLogDebug!("No NFSUDP app-layer configuration, enabling NFSUDP
                        detection UDP detection on port {:?}.",
                        default_port);
            AppLayerProtoDetectPPRegister(IPPROTO_UDP as u8,
                default_port.as_ptr(), ALPROTO_NFS, 0,
                NFS_MIN_FRAME_LEN, Direction::ToServer.into(),
                rs_nfs_probe_udp_ts, rs_nfs_probe_udp_tc);
        }
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.nfs.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                NFS_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for nfs.max-tx");
            }
        }
        SCLogDebug!("Rust nfs parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for nfs.");
    }
}
