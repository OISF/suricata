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

/* TODO
 * - check all parsers for calls on non-SUCCESS status
 */

/*  GAP processing:
 *  - if post-gap we've seen a succesful tx req/res: we consider "re-sync'd"
 */

// written by Victor Julien

use std;
use std::str;
use std::ffi::{self, CString};

use std::collections::HashMap;

use nom7::{Err, Needed};
use nom7::error::{make_error, ErrorKind};

use crate::core::*;
use crate::applayer;
use crate::applayer::*;
use crate::frames::*;
use crate::conf::*;
use crate::applayer::{AppLayerResult, AppLayerTxData, AppLayerEvent};

use crate::smb::nbss_records::*;
use crate::smb::smb1_records::*;
use crate::smb::smb2_records::*;

use crate::smb::smb1::*;
use crate::smb::smb2::*;
use crate::smb::smb3::*;
use crate::smb::dcerpc::*;
use crate::smb::session::*;
use crate::smb::events::*;
use crate::smb::files::*;
use crate::smb::smb2_ioctl::*;

#[derive(AppLayerFrameType)]
pub enum SMBFrameType {
    NBSSPdu,
    NBSSHdr,
    NBSSData,
    SMB1Pdu,
    SMB1Hdr,
    SMB1Data,
    SMB2Pdu,
    SMB2Hdr,
    SMB2Data,
    SMB3Pdu,
    SMB3Hdr,
    SMB3Data,
}

pub const MIN_REC_SIZE: u16 = 32 + 4; // SMB hdr + nbss hdr
pub const SMB_CONFIG_DEFAULT_STREAM_DEPTH: u32 = 0;

pub static mut SMB_CFG_MAX_READ_SIZE: u32 = 0;
pub static mut SMB_CFG_MAX_READ_QUEUE_SIZE: u32 = 0;
pub static mut SMB_CFG_MAX_READ_QUEUE_CNT: u32 = 0;
pub static mut SMB_CFG_MAX_WRITE_SIZE: u32 = 0;
pub static mut SMB_CFG_MAX_WRITE_QUEUE_SIZE: u32 = 0;
pub static mut SMB_CFG_MAX_WRITE_QUEUE_CNT: u32 = 0;

static mut ALPROTO_SMB: AppProto = ALPROTO_UNKNOWN;

pub static mut SURICATA_SMB_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

#[no_mangle]
pub extern "C" fn rs_smb_init(context: &'static mut SuricataFileContext)
{
    unsafe {
        SURICATA_SMB_FILE_CONFIG = Some(context);
    }
}

pub const SMB_SRV_ERROR:                u16 = 1;
pub const SMB_SRV_BADPW:                u16 = 2;
pub const SMB_SRV_BADTYPE:              u16 = 3;
pub const SMB_SRV_ACCESS:               u16 = 4;
pub const SMB_SRV_BADUID:               u16 = 91;

pub fn smb_srv_error_string(c: u16) -> String {
    match c {
        SMB_SRV_ERROR           => "SRV_ERROR",
        SMB_SRV_BADPW           => "SRV_BADPW",
        SMB_SRV_BADTYPE         => "SRV_BADTYPE",
        SMB_SRV_ACCESS          => "SRV_ACCESS",
        SMB_SRV_BADUID          => "SRV_BADUID",
        _ => { return (c).to_string(); },
    }.to_string()
}

pub const SMB_DOS_SUCCESS:                u16 = 0;
pub const SMB_DOS_BAD_FUNC:               u16 = 1;
pub const SMB_DOS_BAD_FILE:               u16 = 2;
pub const SMB_DOS_BAD_PATH:               u16 = 3;
pub const SMB_DOS_TOO_MANY_OPEN_FILES:    u16 = 4;
pub const SMB_DOS_ACCESS_DENIED:          u16 = 5;

pub fn smb_dos_error_string(c: u16) -> String {
    match c {
        SMB_DOS_SUCCESS           => "DOS_SUCCESS",
        SMB_DOS_BAD_FUNC          => "DOS_BAD_FUNC",
        SMB_DOS_BAD_FILE          => "DOS_BAD_FILE",
        SMB_DOS_BAD_PATH          => "DOS_BAD_PATH",
        SMB_DOS_TOO_MANY_OPEN_FILES => "DOS_TOO_MANY_OPEN_FILES",
        SMB_DOS_ACCESS_DENIED     => "DOS_ACCESS_DENIED",
        _ => { return (c).to_string(); },
    }.to_string()
}

pub const NTLMSSP_NEGOTIATE:               u32 = 1;
pub const NTLMSSP_CHALLENGE:               u32 = 2;
pub const NTLMSSP_AUTH:                    u32 = 3;

pub fn ntlmssp_type_string(c: u32) -> String {
    match c {
        NTLMSSP_NEGOTIATE   => "NTLMSSP_NEGOTIATE",
        NTLMSSP_CHALLENGE   => "NTLMSSP_CHALLENGE",
        NTLMSSP_AUTH        => "NTLMSSP_AUTH",
        _ => { return (c).to_string(); },
    }.to_string()
}

#[derive(Default, Eq, PartialEq, Debug, Clone)]
pub struct SMBVerCmdStat {
    smb_ver: u8,
    smb1_cmd: u8,
    smb2_cmd: u16,

    status_set: bool,
    status_is_dos_error: bool,
    status_error_class: u8,
    status: u32,
}

impl SMBVerCmdStat {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn new1(cmd: u8) -> Self {
        return Self {
            smb_ver: 1,
            smb1_cmd: cmd,
            ..Default::default()
        }
    }
    pub fn new1_with_ntstatus(cmd: u8, status: u32) -> Self {
        return Self {
            smb_ver: 1,
            smb1_cmd: cmd,
            status_set: true,
            status: status,
            ..Default::default()
        }
    }
    pub fn new2(cmd: u16) -> Self {
        return Self {
            smb_ver: 2,
            smb2_cmd: cmd,
            ..Default::default()
        }
    }

    pub fn new2_with_ntstatus(cmd: u16, status: u32) -> Self {
        return Self {
            smb_ver: 2,
            smb2_cmd: cmd,
            status_set: true,
            status: status,
            ..Default::default()
        }
    }

    pub fn set_smb1_cmd(&mut self, cmd: u8) -> bool {
        if self.smb_ver != 0 {
            return false;
        }
        self.smb_ver = 1;
        self.smb1_cmd = cmd;
        return true;
    }

    pub fn set_smb2_cmd(&mut self, cmd: u16) -> bool {
        if self.smb_ver != 0 {
            return false;
        }
        self.smb_ver = 2;
        self.smb2_cmd = cmd;
        return true;
    }

    pub fn get_version(&self) -> u8 {
        self.smb_ver
    }

    pub fn get_smb1_cmd(&self) -> (bool, u8) {
        if self.smb_ver != 1 {
            return (false, 0);
        }
        return (true, self.smb1_cmd);
    }

    pub fn get_smb2_cmd(&self) -> (bool, u16) {
        if self.smb_ver != 2 {
            return (false, 0);
        }
        return (true, self.smb2_cmd);
    }

    pub fn get_ntstatus(&self) -> (bool, u32) {
        (self.status_set && !self.status_is_dos_error, self.status)
    }

    pub fn get_dos_error(&self) -> (bool, u8, u16) {
        (self.status_set && self.status_is_dos_error, self.status_error_class, self.status as u16)
    }

    fn set_status(&mut self, status: u32, is_dos_error: bool)
    {
        if is_dos_error {
            self.status_is_dos_error = true;
            self.status_error_class = (status & 0x0000_00ff) as u8;
            self.status = (status & 0xffff_0000) >> 16;
        } else {
            self.status = status;
        }
        self.status_set = true;
    }

    pub fn set_ntstatus(&mut self, status: u32)
    {
        self.set_status(status, false)
    }

    pub fn set_status_dos_error(&mut self, status: u32)
    {
        self.set_status(status, true)
    }
}

/// "The FILETIME structure is a 64-bit value that represents the number of
/// 100-nanosecond intervals that have elapsed since January 1, 1601,
/// Coordinated Universal Time (UTC)."
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct SMBFiletime {
    ts: u64, 
}

impl SMBFiletime {
    pub fn new(raw: u64) -> Self {
        Self {
            ts: raw,
        }
    }

    /// inspired by Bro, convert FILETIME to secs since unix epoch
    pub fn as_unix(&self) -> u32 {
        if self.ts > 116_444_736_000_000_000_u64 {
            let ts = self.ts / 10000000 - 11644473600;
            ts as u32
        } else {
            0
        }
    }
}

#[derive(Debug)]
pub enum SMBTransactionTypeData {
    FILE(SMBTransactionFile),
    TREECONNECT(SMBTransactionTreeConnect),
    NEGOTIATE(SMBTransactionNegotiate),
    DCERPC(SMBTransactionDCERPC),
    CREATE(SMBTransactionCreate),
    SESSIONSETUP(SMBTransactionSessionSetup),
    IOCTL(SMBTransactionIoctl),
    RENAME(SMBTransactionRename),
    SETFILEPATHINFO(SMBTransactionSetFilePathInfo),
}

// Used for Trans2 SET_PATH_INFO and SET_FILE_INFO
#[derive(Debug)]
pub struct SMBTransactionSetFilePathInfo {
    pub subcmd: u16,
    pub loi: u16,
    pub delete_on_close: bool,
    pub filename: Vec<u8>,
    pub fid: Vec<u8>,
}

impl SMBTransactionSetFilePathInfo {
    pub fn new(filename: Vec<u8>, fid: Vec<u8>, subcmd: u16, loi: u16, delete_on_close: bool)
        -> Self
    {
        return Self {
            filename: filename, fid: fid,
            subcmd: subcmd,
            loi: loi,
            delete_on_close: delete_on_close,
        }
    }
}

impl SMBState {
    pub fn new_setfileinfo_tx(&mut self, filename: Vec<u8>, fid: Vec<u8>,
            subcmd: u16, loi: u16, delete_on_close: bool)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();

        tx.type_data = Some(SMBTransactionTypeData::SETFILEPATHINFO(
                    SMBTransactionSetFilePathInfo::new(
                        filename, fid, subcmd, loi, delete_on_close)));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        SCLogDebug!("SMB: TX SETFILEPATHINFO created: ID {}", tx.id);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    pub fn new_setpathinfo_tx(&mut self, filename: Vec<u8>,
            subcmd: u16, loi: u16, delete_on_close: bool)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();

        let fid : Vec<u8> = Vec::new();
        tx.type_data = Some(SMBTransactionTypeData::SETFILEPATHINFO(
                    SMBTransactionSetFilePathInfo::new(filename, fid,
                        subcmd, loi, delete_on_close)));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        SCLogDebug!("SMB: TX SETFILEPATHINFO created: ID {}", tx.id);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }
}

#[derive(Debug)]
pub struct SMBTransactionRename {
    pub oldname: Vec<u8>,
    pub newname: Vec<u8>,
    pub fuid: Vec<u8>,
}

impl SMBTransactionRename {
    pub fn new(fuid: Vec<u8>, oldname: Vec<u8>, newname: Vec<u8>) -> Self {
        return Self {
            fuid: fuid, oldname: oldname, newname: newname,
        }
    }
}

impl SMBState {
    pub fn new_rename_tx(&mut self, fuid: Vec<u8>, oldname: Vec<u8>, newname: Vec<u8>)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();

        tx.type_data = Some(SMBTransactionTypeData::RENAME(
                    SMBTransactionRename::new(fuid, oldname, newname)));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        SCLogDebug!("SMB: TX RENAME created: ID {}", tx.id);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }
}

#[derive(Default, Debug)]
pub struct SMBTransactionCreate {
    pub disposition: u32,
    pub delete_on_close: bool,
    pub directory: bool,
    pub filename: Vec<u8>,
    pub guid: Vec<u8>,

    pub create_ts: u32,
    pub last_access_ts: u32,
    pub last_write_ts: u32,
    pub last_change_ts: u32,

    pub size: u64,
}

impl SMBTransactionCreate {
    pub fn new(filename: Vec<u8>, disp: u32, del: bool, dir: bool) -> Self {
        return Self {
            disposition: disp,
            delete_on_close: del,
            directory: dir,
            filename: filename,
            ..Default::default()
        }
    }
}

#[derive(Default, Debug)]
pub struct SMBTransactionNegotiate {
    pub smb_ver: u8,
    pub dialects: Vec<Vec<u8>>,
    pub dialects2: Vec<Vec<u8>>,

    // SMB1 doesn't have the client GUID
    pub client_guid: Option<Vec<u8>>,
    pub server_guid: Vec<u8>,
}

impl SMBTransactionNegotiate {
    pub fn new(smb_ver: u8) -> Self {
        return Self {
            smb_ver: smb_ver,
            server_guid: Vec::with_capacity(16),
            ..Default::default()
        }
    }
}

#[derive(Default, Debug)]
pub struct SMBTransactionTreeConnect {
    pub is_pipe: bool,
    pub share_type: u8,
    pub tree_id: u32,
    pub share_name: Vec<u8>,

    /// SMB1 service strings
    pub req_service: Option<Vec<u8>>,
    pub res_service: Option<Vec<u8>>,
}

impl SMBTransactionTreeConnect {
    pub fn new(share_name: Vec<u8>) -> Self {
        return Self {
            share_name:share_name,
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct SMBTransaction {
    pub id: u64,    /// internal id

    /// version, command and status
    pub vercmd: SMBVerCmdStat,
    /// session id, tree id, etc.
    pub hdr: SMBCommonHdr,

    /// for state tracking. false means this side is in progress, true
    /// that it's complete.
    pub request_done: bool,
    pub response_done: bool,

    /// Command specific data
    pub type_data: Option<SMBTransactionTypeData>,

    pub tx_data: AppLayerTxData,
}

impl Transaction for SMBTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl SMBTransaction {
    pub fn new() -> Self {
        return Self {
              id: 0,
              vercmd: SMBVerCmdStat::new(),
              hdr: SMBCommonHdr::init(),
              request_done: false,
              response_done: false,
              type_data: None,
              tx_data: AppLayerTxData::new(),
        }
    }

    pub fn set_status(&mut self, status: u32, is_dos_error: bool)
    {
        if is_dos_error {
            self.vercmd.set_status_dos_error(status);
        } else {
            self.vercmd.set_ntstatus(status);
        }
    }

    pub fn free(&mut self) {
        SCLogDebug!("SMB TX {:p} free ID {}", &self, self.id);
        debug_validate_bug_on!(self.tx_data.files_opened > 1);
        debug_validate_bug_on!(self.tx_data.files_logged > 1);
    }
}

impl Drop for SMBTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct SMBFileGUIDOffset {
    pub guid: Vec<u8>,
    pub offset: u64,
}

impl SMBFileGUIDOffset {
    pub fn new(guid: Vec<u8>, offset: u64) -> Self {
        Self {
            guid:guid,
            offset:offset,
        }
    }
}

/// type values to make sure we're not mixing things
/// up in hashmap lookups
pub const SMBHDR_TYPE_GUID:        u32 = 1;
pub const SMBHDR_TYPE_SHARE:       u32 = 2;
pub const SMBHDR_TYPE_FILENAME:    u32 = 3;
pub const SMBHDR_TYPE_OFFSET:      u32 = 4;
pub const SMBHDR_TYPE_GENERICTX:   u32 = 5;
pub const SMBHDR_TYPE_HEADER:      u32 = 6;
pub const SMBHDR_TYPE_MAX_SIZE:    u32 = 7; // max resp size for SMB1_COMMAND_TRANS
pub const SMBHDR_TYPE_TRANS_FRAG:  u32 = 8;
pub const SMBHDR_TYPE_TREE:        u32 = 9;
pub const SMBHDR_TYPE_DCERPCTX:    u32 = 10;

#[derive(Default, Hash, Eq, PartialEq, Debug)]
pub struct SMBCommonHdr {
    pub ssn_id: u64,
    pub tree_id: u32,
    pub rec_type: u32,
    pub msg_id: u64,
}

impl SMBCommonHdr {
    pub fn init() -> Self {
        Default::default()
    }
    pub fn new(rec_type: u32, ssn_id: u64, tree_id: u32, msg_id: u64) -> Self {
        Self {
            rec_type : rec_type,
            ssn_id : ssn_id,
            tree_id : tree_id,
            msg_id : msg_id,
        }
    }
    pub fn from2(r: &Smb2Record, rec_type: u32) -> SMBCommonHdr {
        let tree_id = match rec_type {
            SMBHDR_TYPE_TREE => { 0 },
            _ => r.tree_id,
        };
        let msg_id = match rec_type {
            SMBHDR_TYPE_TRANS_FRAG | SMBHDR_TYPE_SHARE => { 0 },
            _ => { r.message_id as u64 },
        };

        SMBCommonHdr {
            rec_type : rec_type,
            ssn_id : r.session_id,
            tree_id : tree_id,
            msg_id : msg_id,
        }

    }
    pub fn from2_notree(r: &Smb2Record, rec_type: u32) -> SMBCommonHdr {
        // async responses do not have a tree id (even if the request has it)
        // making thus the match between the two impossible.
        // Per spec, MessageId should be enough to identifiy a message request and response uniquely
        // across all messages that are sent on the same SMB2 Protocol transport connection.
        // cf https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
        let msg_id = match rec_type {
            SMBHDR_TYPE_TRANS_FRAG | SMBHDR_TYPE_SHARE => { 0 },
            _ => { r.message_id as u64 },
        };

        SMBCommonHdr {
            rec_type : rec_type,
            ssn_id : r.session_id,
            tree_id : 0,
            msg_id : msg_id,
        }
    }
    pub fn from1(r: &SmbRecord, rec_type: u32) -> SMBCommonHdr {
        let tree_id = match rec_type {
            SMBHDR_TYPE_TREE => { 0 },
            _ => r.tree_id as u32,
        };
        let msg_id = match rec_type {
            SMBHDR_TYPE_TRANS_FRAG | SMBHDR_TYPE_SHARE => { 0 },
            _ => { r.multiplex_id as u64 },
        };

        SMBCommonHdr {
            rec_type : rec_type,
            ssn_id : r.ssn_id as u64,
            tree_id : tree_id,
            msg_id : msg_id,
        }
    }

    // don't include tree id
    pub fn compare(&self, hdr: &SMBCommonHdr) -> bool {
        self.rec_type == hdr.rec_type && self.ssn_id == hdr.ssn_id &&
            self.msg_id == hdr.msg_id
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct SMBHashKeyHdrGuid {
    hdr: SMBCommonHdr,
    guid: Vec<u8>,
}

impl SMBHashKeyHdrGuid {
    pub fn new(hdr: SMBCommonHdr, guid: Vec<u8>) -> Self {
        Self {
            hdr: hdr, guid: guid,
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct SMBTree {
    pub name: Vec<u8>,
    pub is_pipe: bool,
}

impl SMBTree {
    pub fn new(name: Vec<u8>, is_pipe: bool) -> Self {
        Self {
            name:name,
            is_pipe:is_pipe,
        }
    }
}

pub fn u32_as_bytes(i: u32) -> [u8;4] {
    let o1: u8 = ((i >> 24) & 0xff) as u8;
    let o2: u8 = ((i >> 16) & 0xff) as u8;
    let o3: u8 = ((i >> 8)  & 0xff) as u8;
    let o4: u8 =  (i        & 0xff) as u8;
    return [o1, o2, o3, o4]
}

#[derive(Default, Debug)]
pub struct SMBState<> {
    pub state_data: AppLayerStateData,

    /// map ssn/tree/msgid to vec (guid/name/share)
    pub ssn2vec_map: HashMap<SMBCommonHdr, Vec<u8>>,
    /// map guid to filename
    pub guid2name_map: HashMap<Vec<u8>, Vec<u8>>,
    /// map ssn key to read offset
    pub ssn2vecoffset_map: HashMap<SMBCommonHdr, SMBFileGUIDOffset>,

    pub ssn2tree_map: HashMap<SMBCommonHdr, SMBTree>,

    // store partial data records that are transfered in multiple
    // requests for DCERPC.
    pub ssnguid2vec_map: HashMap<SMBHashKeyHdrGuid, Vec<u8>>,

    skip_ts: u32,
    skip_tc: u32,

    pub file_ts_left : u32,
    pub file_tc_left : u32,
    pub file_ts_guid : Vec<u8>,
    pub file_tc_guid : Vec<u8>,

    pub ts_ssn_gap: bool,
    pub tc_ssn_gap: bool,

    pub ts_gap: bool, // last TS update was gap
    pub tc_gap: bool, // last TC update was gap

    pub ts_trunc: bool, // no more data for TOSERVER
    pub tc_trunc: bool, // no more data for TOCLIENT

    /// true as long as we have file txs that are in a post-gap
    /// state. It means we'll do extra house keeping for those.
    check_post_gap_file_txs: bool,
    post_gap_files_checked: bool,

    /// transactions list
    pub transactions: Vec<SMBTransaction>,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,

    /// SMB2 dialect or 0 if not set or SMB1
    pub dialect: u16,
    /// contains name of SMB1 dialect
    pub dialect_vec: Option<Vec<u8>>, // used if dialect == 0

    /// dcerpc interfaces, stored here to be able to match
    /// them while inspecting DCERPC REQUEST txs
    pub dcerpc_ifaces: Option<Vec<DCERPCIface>>,

    pub max_read_size: u32,
    pub max_write_size: u32,

    /// Timestamp in seconds of last update. This is packet time,
    /// potentially coming from pcaps.
    ts: u64,
}

impl State<SMBTransaction> for SMBState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&SMBTransaction> {
        self.transactions.get(index)
    }
}

impl SMBState {
    /// Allocation function for a new TLS parser instance
    pub fn new() -> Self {
        Self {
            state_data:AppLayerStateData::new(),
            ssn2vec_map:HashMap::new(),
            guid2name_map:HashMap::new(),
            ssn2vecoffset_map:HashMap::new(),
            ssn2tree_map:HashMap::new(),
            ssnguid2vec_map:HashMap::new(),
            skip_ts:0,
            skip_tc:0,
            file_ts_left:0,
            file_tc_left:0,
            file_ts_guid:Vec::new(),
            file_tc_guid:Vec::new(),
            ts_ssn_gap: false,
            tc_ssn_gap: false,
            ts_gap: false,
            tc_gap: false,
            ts_trunc: false,
            tc_trunc: false,
            check_post_gap_file_txs: false,
            post_gap_files_checked: false,
            transactions: Vec::new(),
            tx_id:0,
            dialect:0,
            dialect_vec: None,
            dcerpc_ifaces: None,
            ts: 0,
            ..Default::default()
        }
    }

    pub fn free(&mut self) {
        //self._debug_state_stats();
        self._debug_tx_stats();
    }

    pub fn new_tx(&mut self) -> SMBTransaction {
        let mut tx = SMBTransaction::new();
        self.tx_id += 1;
        tx.id = self.tx_id;
        SCLogDebug!("TX {} created", tx.id);
        return tx;
    }

    pub fn free_tx(&mut self, tx_id: u64) {
        SCLogDebug!("Freeing TX with ID {} TX.ID {}", tx_id, tx_id+1);
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.id == tx_id + 1 {
                found = true;
                index = i;
                SCLogDebug!("tx {} progress {}/{}", tx.id, tx.request_done, tx.response_done);
                break;
            }
        }
        if found {
            SCLogDebug!("freeing TX with ID {} TX.ID {} at index {} left: {} max id: {}",
                    tx_id, tx_id+1, index, self.transactions.len(), self.tx_id);
            self.transactions.remove(index);
        }
    }

    pub fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&SMBTransaction> {
/*
        if self.transactions.len() > 100 {
            SCLogNotice!("get_tx_by_id: tx_id={} in list={}", tx_id, self.transactions.len());
            self._dump_txs();
            panic!("txs exploded");
        }
*/
        for tx in &mut self.transactions {
            if tx.id == tx_id + 1 {
                let ver = tx.vercmd.get_version();
                let mut _smbcmd;
                if ver == 2 {
                    let (_, cmd) = tx.vercmd.get_smb2_cmd();
                    _smbcmd = cmd;
                } else {
                    let (_, cmd) = tx.vercmd.get_smb1_cmd();
                    _smbcmd = cmd as u16;
                }
                SCLogDebug!("Found SMB TX: id {} ver:{} cmd:{} progress {}/{} type_data {:?}",
                        tx.id, ver, _smbcmd, tx.request_done, tx.response_done, tx.type_data);
                /* hack: apply flow file flags to file tx here to make sure its propegated */
                if let Some(SMBTransactionTypeData::FILE(ref mut d)) = tx.type_data {
                    tx.tx_data.update_file_flags(self.state_data.file_flags);
                    d.update_file_flags(tx.tx_data.file_flags);
                }
                return Some(tx);
            }
        }
        SCLogDebug!("Failed to find SMB TX with ID {}", tx_id);
        return None;
    }

    fn update_ts(&mut self, ts: u64) {
        if ts != self.ts {
            self.ts = ts;
            self.post_gap_files_checked = false;
        }
    }

    /* generic TX has no type_data and is only used to
     * track a single cmd request/reply pair. */

    pub fn new_generic_tx(&mut self, smb_ver: u8, smb_cmd: u16, key: SMBCommonHdr)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();
        if smb_ver == 1 && smb_cmd <= 255 {
            tx.vercmd.set_smb1_cmd(smb_cmd as u8);
        } else if smb_ver == 2 {
            tx.vercmd.set_smb2_cmd(smb_cmd);
        }

        tx.type_data = None;
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated
        tx.hdr = key;

        SCLogDebug!("SMB: TX GENERIC created: ID {} tx list {} {:?}",
                tx.id, self.transactions.len(), &tx);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    pub fn get_last_tx(&mut self, smb_ver: u8, smb_cmd: u16)
        -> Option<&mut SMBTransaction>
    {
        let tx_ref = self.transactions.last_mut();
        match tx_ref {
            Some(tx) => {
                let found = if tx.vercmd.get_version() == smb_ver {
                    if smb_ver == 1 {
                        let (_, cmd) = tx.vercmd.get_smb1_cmd();
                        cmd as u16 == smb_cmd
                    } else if smb_ver == 2 {
                        let (_, cmd) = tx.vercmd.get_smb2_cmd();
                        cmd == smb_cmd
                    } else {
                        false
                    }
                } else {
                    false
                };
                if found {
                    return Some(tx);
                }
            },
            None => { },
        }
        return None;
    }

    pub fn get_generic_tx(&mut self, smb_ver: u8, smb_cmd: u16, key: &SMBCommonHdr)
        -> Option<&mut SMBTransaction>
    {
        for tx in &mut self.transactions {
            let found = if tx.vercmd.get_version() == smb_ver {
                if smb_ver == 1 {
                    let (_, cmd) = tx.vercmd.get_smb1_cmd();
                    cmd as u16 == smb_cmd && tx.hdr.compare(key)
                } else if smb_ver == 2 {
                    let (_, cmd) = tx.vercmd.get_smb2_cmd();
                    cmd == smb_cmd && tx.hdr.compare(key)
                } else {
                    false
                }
            } else {
                false
            };
            if found {
                return Some(tx);
            }
        }
        return None;
    }

    pub fn new_negotiate_tx(&mut self, smb_ver: u8)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();
        if smb_ver == 1 {
            tx.vercmd.set_smb1_cmd(SMB1_COMMAND_NEGOTIATE_PROTOCOL);
        } else if smb_ver == 2 {
            tx.vercmd.set_smb2_cmd(SMB2_COMMAND_NEGOTIATE_PROTOCOL);
        }

        tx.type_data = Some(SMBTransactionTypeData::NEGOTIATE(
                    SMBTransactionNegotiate::new(smb_ver)));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        SCLogDebug!("SMB: TX NEGOTIATE created: ID {} SMB ver {}", tx.id, smb_ver);
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    pub fn get_negotiate_tx(&mut self, smb_ver: u8)
        -> Option<&mut SMBTransaction>
    {
        for tx in &mut self.transactions {
            let found = match tx.type_data {
                Some(SMBTransactionTypeData::NEGOTIATE(ref x)) => {
                    if x.smb_ver == smb_ver {
                        true
                    } else {
                        false
                    }
                },
                _ => { false },
            };
            if found {
                return Some(tx);
            }
        }
        return None;
    }

    pub fn new_treeconnect_tx(&mut self, hdr: SMBCommonHdr, name: Vec<u8>)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();

        tx.hdr = hdr;
        tx.type_data = Some(SMBTransactionTypeData::TREECONNECT(
                    SMBTransactionTreeConnect::new(name.to_vec())));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        SCLogDebug!("SMB: TX TREECONNECT created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(&name));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    pub fn get_treeconnect_tx(&mut self, hdr: SMBCommonHdr)
        -> Option<&mut SMBTransaction>
    {
        for tx in &mut self.transactions {
            let hit = tx.hdr.compare(&hdr) && match tx.type_data {
                Some(SMBTransactionTypeData::TREECONNECT(_)) => { true },
                _ => { false },
            };
            if hit {
                return Some(tx);
            }
        }
        return None;
    }

    pub fn new_create_tx(&mut self, file_name: &Vec<u8>,
            disposition: u32, del: bool, dir: bool,
            hdr: SMBCommonHdr)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();
        tx.hdr = hdr;
        tx.type_data = Some(SMBTransactionTypeData::CREATE(
                            SMBTransactionCreate::new(
                                file_name.to_vec(), disposition,
                                del, dir)));
        tx.request_done = true;
        tx.response_done = self.tc_trunc; // no response expected if tc is truncated

        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    pub fn get_create_tx_by_hdr(&mut self, hdr: &SMBCommonHdr)
        -> Option<&mut SMBTransaction>
    {
        for tx in &mut self.transactions {
            let found = match tx.type_data {
                Some(SMBTransactionTypeData::CREATE(ref _d)) => {
                    tx.hdr.compare(hdr)
                },
                _ => { false },
            };

            if found {
                SCLogDebug!("SMB: Found SMB create TX with ID {}", tx.id);
                return Some(tx);
            }
        }
        SCLogDebug!("SMB: Failed to find SMB create TX with key {:?}", hdr);
        return None;
    }

    pub fn get_service_for_guid(&self, guid: &[u8]) -> (&'static str, bool)
    {
        let (name, is_dcerpc) = match self.guid2name_map.get(&guid.to_vec()) {
            Some(n) => {
                let mut s = n.as_slice();
                // skip leading \ if we have it
                if s.len() > 1 && s[0] == 0x5c_u8 {
                    s = &s[1..];
                }
                match str::from_utf8(s) {
                    Ok("PSEXESVC") => ("PSEXESVC", false),
                    Ok("svcctl") => ("svcctl", true),
                    Ok("srvsvc") => ("srvsvc", true),
                    Ok("atsvc") => ("atsvc", true),
                    Ok("lsarpc") => ("lsarpc", true),
                    Ok("samr") => ("samr", true),
                    Ok("spoolss") => ("spoolss", true),
                    Ok("winreg") => ("winreg", true),
                    Ok("suricata::dcerpc") => ("unknown", true),
                    Err(_) => ("MALFORMED", false),
                    Ok(&_) => {
                        SCLogDebug!("don't know {}", String::from_utf8_lossy(&n));
                        ("UNKNOWN", false)
                    },
                }
            },
            _ => { ("UNKNOWN", false) },
        };
        SCLogDebug!("service {} is_dcerpc {}", name, is_dcerpc);
        (name, is_dcerpc)
    }

    fn post_gap_housekeeping_for_files(&mut self)
    {
        let mut post_gap_txs = false;
        for tx in &mut self.transactions {
            if let Some(SMBTransactionTypeData::FILE(ref mut f)) = tx.type_data {
                if f.post_gap_ts > 0 {
                    if self.ts > f.post_gap_ts {
                        tx.request_done = true;
                        tx.response_done = true;
                        let (files, flags) = f.files.get(f.direction);
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
                if let Some(SMBTransactionTypeData::FILE(ref mut f)) = tx.type_data {
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
                if let Some(SMBTransactionTypeData::FILE(ref mut f)) = tx.type_data {
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

    pub fn set_file_left(&mut self, direction: Direction, rec_size: u32, data_size: u32, fuid: Vec<u8>)
    {
        let left = rec_size.saturating_sub(data_size);
        if direction == Direction::ToServer {
            self.file_ts_left = left;
            self.file_ts_guid = fuid;
        } else {
            self.file_tc_left = left;
            self.file_tc_guid = fuid;
        }
    }

    pub fn set_skip(&mut self, direction: Direction, rec_size: u32, data_size: u32)
    {
        let skip = rec_size.saturating_sub(data_size);
        if direction == Direction::ToServer {
            self.skip_ts = skip;
        } else {
            self.skip_tc = skip;
        }
    }

    // return how much data we consumed
    fn handle_skip(&mut self, direction: Direction, input_size: u32) -> u32 {
        let mut skip_left = if direction == Direction::ToServer {
            self.skip_ts
        } else {
            self.skip_tc
        };
        if skip_left == 0 {
            return 0
        }
        SCLogDebug!("skip_left {} input_size {}", skip_left, input_size);

        let consumed = if skip_left >= input_size {
            input_size
        } else {
            skip_left
        };

        if skip_left <= input_size {
            skip_left = 0;
        } else {
            skip_left -= input_size;
        }

        if direction == Direction::ToServer {
            self.skip_ts = skip_left;
        } else {
            self.skip_tc = skip_left;
        }
        return consumed;
    }

    fn add_nbss_ts_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) -> (Option<Frame>, Option<Frame>, Option<Frame>) {
        let nbss_pdu = Frame::new(flow, stream_slice, input, nbss_len + 4, SMBFrameType::NBSSPdu as u8);
        SCLogDebug!("NBSS PDU frame {:?}", nbss_pdu);
        let nbss_hdr_frame = Frame::new(flow, stream_slice, input, 4 as i64, SMBFrameType::NBSSHdr as u8);
        SCLogDebug!("NBSS HDR frame {:?}", nbss_hdr_frame);
        let nbss_data_frame = Frame::new(flow, stream_slice, &input[4..], nbss_len, SMBFrameType::NBSSData as u8);
        SCLogDebug!("NBSS DATA frame {:?}", nbss_data_frame);
        (nbss_pdu, nbss_hdr_frame, nbss_data_frame)
    }

    fn add_smb1_ts_pdu_frame(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) -> Option<Frame> {
        let smb_pdu = Frame::new(flow, stream_slice, input, nbss_len, SMBFrameType::SMB1Pdu as u8);
        SCLogDebug!("SMB PDU frame {:?}", smb_pdu);
        smb_pdu
    }
    fn add_smb1_ts_hdr_data_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) {
        let _smb1_hdr = Frame::new(flow, stream_slice, input, 32 as i64, SMBFrameType::SMB1Hdr as u8);
        SCLogDebug!("SMBv1 HDR frame {:?}", _smb1_hdr);
        if input.len() > 32 {
            let _smb1_data = Frame::new(flow, stream_slice, &input[32..], (nbss_len - 32) as i64, SMBFrameType::SMB1Data as u8);
            SCLogDebug!("SMBv1 DATA frame {:?}", _smb1_data);
        }
    }

    fn add_smb2_ts_pdu_frame(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) -> Option<Frame> {
        let smb_pdu = Frame::new(flow, stream_slice, input, nbss_len, SMBFrameType::SMB2Pdu as u8);
        SCLogDebug!("SMBv2 PDU frame {:?}", smb_pdu);
        smb_pdu
    }
    fn add_smb2_ts_hdr_data_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64, hdr_len: i64) {
        let _smb2_hdr = Frame::new(flow, stream_slice, input, hdr_len, SMBFrameType::SMB2Hdr as u8);
        SCLogDebug!("SMBv2 HDR frame {:?}", _smb2_hdr);
        if input.len() > hdr_len as usize {
            let _smb2_data = Frame::new(flow, stream_slice, &input[hdr_len as usize..], nbss_len - hdr_len, SMBFrameType::SMB2Data as u8);
            SCLogDebug!("SMBv2 DATA frame {:?}", _smb2_data);
        }
    }

    fn add_smb3_ts_pdu_frame(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) -> Option<Frame> {
        let smb_pdu = Frame::new(flow, stream_slice, input, nbss_len, SMBFrameType::SMB3Pdu as u8);
        SCLogDebug!("SMBv3 PDU frame {:?}", smb_pdu);
        smb_pdu
    }
    fn add_smb3_ts_hdr_data_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) {
        let _smb3_hdr = Frame::new(flow, stream_slice, input, 52 as i64, SMBFrameType::SMB3Hdr as u8);
        SCLogDebug!("SMBv3 HDR frame {:?}", _smb3_hdr);
        if input.len() > 52 {
            let _smb3_data = Frame::new(flow, stream_slice, &input[52..], (nbss_len - 52) as i64, SMBFrameType::SMB3Data as u8);
            SCLogDebug!("SMBv3 DATA frame {:?}", _smb3_data);
        }
    }

    /// return bytes consumed
    pub fn parse_tcp_data_ts_partial<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &'b[u8]) -> usize
    {
        SCLogDebug!("incomplete of size {}", input.len());
        if input.len() < 512 {
            // check for malformed data. Wireshark reports as
            // 'NBSS continuation data'. If it's invalid we're
            // lost so we give up.
            if input.len() > 8 {
                match parse_nbss_record_partial(input) {
                    Ok((_, ref hdr)) => {
                        if !hdr.is_smb() {
                            SCLogDebug!("partial NBSS, not SMB and no known msg type {}", hdr.message_type);
                            self.trunc_ts();
                            return 0;
                        }
                    },
                    _ => {},
                }
            }
            return 0;
        }

        match parse_nbss_record_partial(input) {
            Ok((output, ref nbss_part_hdr)) => {
                SCLogDebug!("parse_nbss_record_partial ok, output len {}", output.len());
                if nbss_part_hdr.message_type == NBSS_MSGTYPE_SESSION_MESSAGE {
                    match parse_smb_version(nbss_part_hdr.data) {
                        Ok((_, ref smb)) => {
                            SCLogDebug!("SMB {:?}", smb);
                            if smb.version == 0xff_u8 { // SMB1
                                SCLogDebug!("SMBv1 record");
                                match parse_smb_record(nbss_part_hdr.data) {
                                    Ok((_, ref r)) => {
                                        if r.command == SMB1_COMMAND_WRITE_ANDX {
                                            // see if it's a write to a pipe. We only handle those
                                            // if complete.
                                            let tree_key = SMBCommonHdr::new(SMBHDR_TYPE_SHARE,
                                                    r.ssn_id as u64, r.tree_id as u32, 0);
                                            let is_pipe = match self.ssn2tree_map.get(&tree_key) {
                                                Some(n) => n.is_pipe,
                                                None => false,
                                            };
                                            if is_pipe {
                                                return 0;
                                            }
                                            smb1_write_request_record(self, r, SMB1_HEADER_SIZE, SMB1_COMMAND_WRITE_ANDX);

                                            self.add_nbss_ts_frames(flow, stream_slice, input, nbss_part_hdr.length as i64);
                                            self.add_smb1_ts_pdu_frame(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64);
                                            self.add_smb1_ts_hdr_data_frames(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64);

                                            let consumed = input.len() - output.len();
                                            return consumed;
                                        }
                                    },
                                    _ => { },

                                }
                            } else if smb.version == 0xfe_u8 { // SMB2
                                SCLogDebug!("SMBv2 record");
                                match parse_smb2_request_record(nbss_part_hdr.data) {
                                    Ok((_, ref smb_record)) => {
                                        SCLogDebug!("SMB2: partial record {}",
                                                &smb2_command_string(smb_record.command));
                                        if smb_record.command == SMB2_COMMAND_WRITE {
                                            smb2_write_request_record(self, smb_record);

                                            self.add_nbss_ts_frames(flow, stream_slice, input, nbss_part_hdr.length as i64);
                                            self.add_smb2_ts_pdu_frame(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64);
                                            self.add_smb2_ts_hdr_data_frames(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64, smb_record.header_len as i64);

                                            let consumed = input.len() - output.len();
                                            SCLogDebug!("consumed {}", consumed);
                                            return consumed;
                                        }
                                    },
                                    _ => { },
                                }
                            }
                            // no SMB3 here yet, will buffer full records
                        },
                        _ => { },
                    }
                }
            },
            _ => { },
        }

        return 0;
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_ts<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult
    {
        let mut cur_i = stream_slice.as_slice();
        let consumed = self.handle_skip(Direction::ToServer, cur_i.len() as u32);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return AppLayerResult::err();
            }
            cur_i = &cur_i[consumed as usize..];
        }
        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(Direction::ToServer, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return AppLayerResult::err();
            }
            cur_i = &cur_i[consumed as usize..];
        }
        if cur_i.len() == 0 {
            return AppLayerResult::ok();
        }
        // gap
        if self.ts_gap {
            SCLogDebug!("TS trying to catch up after GAP (input {})", cur_i.len());
            while cur_i.len() > 0 { // min record size
                match search_smb_record(cur_i) {
                    Ok((_, pg)) => {
                        SCLogDebug!("smb record found");
                        let smb2_offset = cur_i.len() - pg.len();
                        if smb2_offset < 4 {
                            cur_i = &cur_i[smb2_offset+4..];
                            continue; // see if we have another record in our data
                        }
                        let nbss_offset = smb2_offset - 4;
                        cur_i = &cur_i[nbss_offset..];

                        self.ts_gap = false;
                        break;
                    },
                    _ => {
                        let mut consumed = stream_slice.len();
                        if consumed < 4 {
                            consumed = 0;
                        } else {
                            consumed = consumed - 3;
                        }
                        SCLogDebug!("smb record NOT found");
                        return AppLayerResult::incomplete(consumed as u32, 8);
                    },
                }
            }
        }
        while cur_i.len() > 0 { // min record size
            match parse_nbss_record(cur_i) {
                Ok((rem, ref nbss_hdr)) => {
                    SCLogDebug!("nbss frame offset {} len {}", stream_slice.offset_from(cur_i), cur_i.len() - rem.len());
                    let (_, _, nbss_data_frame) = self.add_nbss_ts_frames(flow, stream_slice, cur_i, nbss_hdr.length as i64);

                    if nbss_hdr.message_type == NBSS_MSGTYPE_SESSION_MESSAGE {
                        // we have the full records size worth of data,
                        // let's parse it
                        match parse_smb_version(nbss_hdr.data) {
                            Ok((_, ref smb)) => {

                                SCLogDebug!("SMB {:?}", smb);
                                if smb.version == 0xff_u8 { // SMB1

                                    SCLogDebug!("SMBv1 record");
                                    match parse_smb_record(nbss_hdr.data) {
                                        Ok((_, ref smb_record)) => {
                                            let pdu_frame = self.add_smb1_ts_pdu_frame(flow, stream_slice, nbss_hdr.data, nbss_hdr.length as i64);
                                            self.add_smb1_ts_hdr_data_frames(flow, stream_slice, nbss_hdr.data, nbss_hdr.length as i64);
                                            if smb_record.is_request() {
                                                smb1_request_record(self, smb_record);
                                            } else {
                                                // If we recevied a response when expecting a request, set an event
                                                // on the PDU frame instead of handling the response.
                                                SCLogDebug!("SMB1 reply seen from client to server");
                                                if let Some(frame) = pdu_frame {
                                                    frame.add_event(flow, SMBEvent::ResponseToServer as u8);
                                                }
                                            }
                                        },
                                        _ => {
                                            if let Some(frame) = nbss_data_frame {
                                                frame.add_event(flow, SMBEvent::MalformedData as u8);
                                            }
                                            self.set_event(SMBEvent::MalformedData);
                                            return AppLayerResult::err();
                                        },
                                    }
                                } else if smb.version == 0xfe_u8 { // SMB2
                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv2 record");
                                        match parse_smb2_request_record(nbss_data) {
                                            Ok((nbss_data_rem, ref smb_record)) => {
                                                let record_len = (nbss_data.len() - nbss_data_rem.len()) as i64;
                                                let pdu_frame = self.add_smb2_ts_pdu_frame(flow, stream_slice, nbss_data, record_len);
                                                self.add_smb2_ts_hdr_data_frames(flow, stream_slice, nbss_data, record_len, smb_record.header_len as i64);
                                                SCLogDebug!("nbss_data_rem {}", nbss_data_rem.len());
                                                if smb_record.is_request() {
                                                    smb2_request_record(self, smb_record);
                                                } else {
                                                    // If we recevied a response when expecting a request, set an event
                                                    // on the PDU frame instead of handling the response.
                                                    SCLogDebug!("SMB2 reply seen from client to server");
                                                    if let Some(frame) = pdu_frame {
                                                        frame.add_event(flow, SMBEvent::ResponseToServer as u8);
                                                    }
                                                }
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                if let Some(frame) = nbss_data_frame {
                                                    frame.add_event(flow, SMBEvent::MalformedData as u8);
                                                }
                                                self.set_event(SMBEvent::MalformedData);
                                                return AppLayerResult::err();
                                            },
                                        }
                                    }
                                } else if smb.version == 0xfd_u8 { // SMB3 transform

                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv3 transform record");
                                        match parse_smb3_transform_record(nbss_data) {
                                            Ok((nbss_data_rem, ref _smb3_record)) => {
                                                let record_len = (nbss_data.len() - nbss_data_rem.len()) as i64;
                                                self.add_smb3_ts_pdu_frame(flow, stream_slice, nbss_data, record_len);
                                                self.add_smb3_ts_hdr_data_frames(flow, stream_slice, nbss_data, record_len);
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                if let Some(frame) = nbss_data_frame {
                                                    frame.add_event(flow, SMBEvent::MalformedData as u8);
                                                }
                                                self.set_event(SMBEvent::MalformedData);
                                                return AppLayerResult::err();
                                            },
                                        }
                                    }
                                }
                            },
                            _ => {
                                self.set_event(SMBEvent::MalformedData);
                                return AppLayerResult::err();
                            },
                        }
                    } else {
                        SCLogDebug!("NBSS message {:X}", nbss_hdr.message_type);
                    }
                    cur_i = rem;
                },
                Err(Err::Incomplete(needed)) => {
                    if let Needed::Size(n) = needed {
                        let n = usize::from(n) + cur_i.len();
                        // 512 is the minimum for parse_tcp_data_ts_partial
                        if n >= 512 && cur_i.len() < 512 {
                            let total_consumed = stream_slice.offset_from(cur_i);
                            return AppLayerResult::incomplete(total_consumed, 512);
                        }
                        let consumed = self.parse_tcp_data_ts_partial(flow, stream_slice, cur_i);
                        if consumed == 0 {
                            // if we consumed none we will buffer the entire record
                            let total_consumed = stream_slice.offset_from(cur_i);
                            SCLogDebug!("setting consumed {} need {} needed {:?} total input {}",
                                    total_consumed, n, needed, stream_slice.len());
                            let need = n;
                            return AppLayerResult::incomplete(total_consumed as u32, need as u32);
                        }
                        // tracking a write record, which we don't need to
                        // queue up at the stream level, but can feed to us
                        // in small chunks
                        return AppLayerResult::ok();
                    } else {
                        self.set_event(SMBEvent::InternalError);
                        return AppLayerResult::err();
                    }
                },
                Err(_) => {
                    self.set_event(SMBEvent::MalformedData);
                    return AppLayerResult::err();
                },
            }
        };

        self.post_gap_housekeeping(Direction::ToServer);
        if self.check_post_gap_file_txs && !self.post_gap_files_checked {
            self.post_gap_housekeeping_for_files();
            self.post_gap_files_checked = true;
        }
        AppLayerResult::ok()
    }

    fn add_nbss_tc_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) -> (Option<Frame>, Option<Frame>, Option<Frame>) {
        let nbss_pdu = Frame::new(flow, stream_slice, input, nbss_len + 4, SMBFrameType::NBSSPdu as u8);
        SCLogDebug!("NBSS PDU frame {:?}", nbss_pdu);
        let nbss_hdr_frame = Frame::new(flow, stream_slice, input, 4 as i64, SMBFrameType::NBSSHdr as u8);
        SCLogDebug!("NBSS HDR frame {:?}", nbss_hdr_frame);
        let nbss_data_frame = Frame::new(flow, stream_slice, &input[4..], nbss_len, SMBFrameType::NBSSData as u8);
        SCLogDebug!("NBSS DATA frame {:?}", nbss_data_frame);
        (nbss_pdu, nbss_hdr_frame, nbss_data_frame)
    }

    fn add_smb1_tc_pdu_frame(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) -> Option<Frame> {
        let smb_pdu = Frame::new(flow, stream_slice, input, nbss_len, SMBFrameType::SMB1Pdu as u8);
        SCLogDebug!("SMB PDU frame {:?}", smb_pdu);
        smb_pdu
    }
    fn add_smb1_tc_hdr_data_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) {
        let _smb1_hdr = Frame::new(flow, stream_slice, input, SMB1_HEADER_SIZE as i64, SMBFrameType::SMB1Hdr as u8);
        SCLogDebug!("SMBv1 HDR frame {:?}", _smb1_hdr);
        if input.len() > SMB1_HEADER_SIZE {
            let _smb1_data = Frame::new(flow, stream_slice, &input[SMB1_HEADER_SIZE..], (nbss_len - SMB1_HEADER_SIZE as i64) as i64,
                    SMBFrameType::SMB1Data as u8);
            SCLogDebug!("SMBv1 DATA frame {:?}", _smb1_data);
        }
    }

    fn add_smb2_tc_pdu_frame(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) -> Option<Frame> {
        let smb_pdu = Frame::new(flow, stream_slice, input, nbss_len, SMBFrameType::SMB2Pdu as u8);
        SCLogDebug!("SMBv2 PDU frame {:?}", smb_pdu);
        smb_pdu
    }
    fn add_smb2_tc_hdr_data_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64, hdr_len: i64) {
        let _smb2_hdr = Frame::new(flow, stream_slice, input, hdr_len, SMBFrameType::SMB2Hdr as u8);
        SCLogDebug!("SMBv2 HDR frame {:?}", _smb2_hdr);
        if input.len() > hdr_len as usize {
            let _smb2_data = Frame::new(flow, stream_slice, &input[hdr_len as usize ..], nbss_len - hdr_len, SMBFrameType::SMB2Data as u8);
            SCLogDebug!("SMBv2 DATA frame {:?}", _smb2_data);
        }
    }

    fn add_smb3_tc_pdu_frame(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) {
        let _smb_pdu = Frame::new(flow, stream_slice, input, nbss_len, SMBFrameType::SMB3Pdu as u8);
        SCLogDebug!("SMBv3 PDU frame {:?}", _smb_pdu);
    }
    fn add_smb3_tc_hdr_data_frames(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &[u8], nbss_len: i64) {
        let _smb3_hdr = Frame::new(flow, stream_slice, input, 52 as i64, SMBFrameType::SMB3Hdr as u8);
        SCLogDebug!("SMBv3 HDR frame {:?}", _smb3_hdr);
        if input.len() > 52 {
            let _smb3_data = Frame::new(flow, stream_slice, &input[52..], (nbss_len - 52) as i64, SMBFrameType::SMB3Data as u8);
            SCLogDebug!("SMBv3 DATA frame {:?}", _smb3_data);
        }
    }

    /// return bytes consumed
    pub fn parse_tcp_data_tc_partial<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice, input: &'b[u8]) -> usize
    {
        SCLogDebug!("incomplete of size {}", input.len());
        if input.len() < 512 {
            // check for malformed data. Wireshark reports as
            // 'NBSS continuation data'. If it's invalid we're
            // lost so we give up.
            if input.len() > 8 {
                match parse_nbss_record_partial(input) {
                    Ok((_, ref hdr)) => {
                        if !hdr.is_smb() {
                            SCLogDebug!("partial NBSS, not SMB and no known msg type {}", hdr.message_type);
                            self.trunc_tc();
                            return 0;
                        }
                    },
                    _ => {},
                }
            }
            return 0;
        }

        if let Ok((output, ref nbss_part_hdr)) = parse_nbss_record_partial(input) {
            SCLogDebug!("parse_nbss_record_partial ok, output len {}", output.len());
            if nbss_part_hdr.message_type == NBSS_MSGTYPE_SESSION_MESSAGE {
                if let Ok((_, ref smb)) = parse_smb_version(nbss_part_hdr.data) {
                    SCLogDebug!("SMB {:?}", smb);
                    if smb.version == 255u8 { // SMB1
                        SCLogDebug!("SMBv1 record");
                        if let Ok((_, ref r)) = parse_smb_record(nbss_part_hdr.data) {
                            SCLogDebug!("SMB1: partial record {}",
                                    r.command);
                            if r.command == SMB1_COMMAND_READ_ANDX {
                                let tree_key = SMBCommonHdr::new(SMBHDR_TYPE_SHARE,
                                        r.ssn_id as u64, r.tree_id as u32, 0);
                                let is_pipe = match self.ssn2tree_map.get(&tree_key) {
                                    Some(n) => n.is_pipe,
                                        None => false,
                                };
                                if is_pipe {
                                    return 0;
                                }

                                // create NBSS frames here so we don't get double frames
                                // when we don't consume the data now.
                                self.add_nbss_tc_frames(flow, stream_slice, input, nbss_part_hdr.length as i64);
                                self.add_smb1_tc_pdu_frame(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64);
                                self.add_smb1_tc_hdr_data_frames(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64);

                                smb1_read_response_record(self, r, SMB1_HEADER_SIZE);
                                let consumed = input.len() - output.len();
                                return consumed;
                            }
                        }
                    } else if smb.version == 254u8 { // SMB2
                        SCLogDebug!("SMBv2 record");
                        if let Ok((_, ref smb_record)) = parse_smb2_response_record(nbss_part_hdr.data) {
                            SCLogDebug!("SMB2: partial record {}",
                                    &smb2_command_string(smb_record.command));
                            if smb_record.command == SMB2_COMMAND_READ {
                                // create NBSS frames here so we don't get double frames
                                // when we don't consume the data now.
                                self.add_nbss_tc_frames(flow, stream_slice, input, nbss_part_hdr.length as i64);
                                self.add_smb2_tc_pdu_frame(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64);
                                self.add_smb2_tc_hdr_data_frames(flow, stream_slice, nbss_part_hdr.data, nbss_part_hdr.length as i64, smb_record.header_len as i64);

                                smb2_read_response_record(self, smb_record);
                                let consumed = input.len() - output.len();
                                return consumed;
                            }
                        }
                    }
                    // no SMB3 here yet, will buffer full records
                }
            }
        }
        return 0;
    }

    /// Parsing function, handling TCP chunks fragmentation
    pub fn parse_tcp_data_tc<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult
    {
        let mut cur_i = stream_slice.as_slice();
        let consumed = self.handle_skip(Direction::ToClient, cur_i.len() as u32);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return AppLayerResult::err();
            }
            cur_i = &cur_i[consumed as usize..];
        }
        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(Direction::ToClient, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return AppLayerResult::err();
            }
            cur_i = &cur_i[consumed as usize..];
        }
        if cur_i.len() == 0 {
            return AppLayerResult::ok();
        }
        // gap
        if self.tc_gap {
            SCLogDebug!("TC trying to catch up after GAP (input {})", cur_i.len());
            while cur_i.len() > 0 { // min record size
                match search_smb_record(cur_i) {
                    Ok((_, pg)) => {
                        SCLogDebug!("smb record found");
                        let smb2_offset = cur_i.len() - pg.len();
                        if smb2_offset < 4 {
                            cur_i = &cur_i[smb2_offset+4..];
                            continue; // see if we have another record in our data
                        }
                        let nbss_offset = smb2_offset - 4;
                        cur_i = &cur_i[nbss_offset..];

                        self.tc_gap = false;
                        break;
                    },
                    _ => {
                        let mut consumed = stream_slice.len();
                        if consumed < 4 {
                            consumed = 0;
                        } else {
                            consumed = consumed - 3;
                        }
                        SCLogDebug!("smb record NOT found");
                        return AppLayerResult::incomplete(consumed as u32, 8);
                    },
                }
            }
        }
        while cur_i.len() > 0 { // min record size
            match parse_nbss_record(cur_i) {
                Ok((rem, ref nbss_hdr)) => {
                    SCLogDebug!("nbss record offset {} len {}", stream_slice.offset_from(cur_i), cur_i.len() - rem.len());
                    self.add_nbss_tc_frames(flow, stream_slice, cur_i, nbss_hdr.length as i64);
                    SCLogDebug!("nbss frames added");

                    if nbss_hdr.message_type == NBSS_MSGTYPE_SESSION_MESSAGE {
                        // we have the full records size worth of data,
                        // let's parse it
                        match parse_smb_version(nbss_hdr.data) {
                            Ok((_, ref smb)) => {
                                SCLogDebug!("SMB {:?}", smb);
                                if smb.version == 0xff_u8 { // SMB1
                                    SCLogDebug!("SMBv1 record");
                                    match parse_smb_record(nbss_hdr.data) {
                                        Ok((_, ref smb_record)) => {
                                            let pdu_frame = self.add_smb1_tc_pdu_frame(flow, stream_slice, nbss_hdr.data, nbss_hdr.length as i64);
                                            self.add_smb1_tc_hdr_data_frames(flow, stream_slice, nbss_hdr.data, nbss_hdr.length as i64);
                                            if smb_record.is_response() {
                                                smb1_response_record(self, smb_record);
                                            } else {
                                                SCLogDebug!("SMB1 request seen from server to client");
                                                if let Some(frame) = pdu_frame {
                                                    frame.add_event(flow, SMBEvent::RequestToClient as u8);
                                                }
                                            }
                                        },
                                        _ => {
                                            self.set_event(SMBEvent::MalformedData);
                                            return AppLayerResult::err();
                                        },
                                    }
                                } else if smb.version == 0xfe_u8 { // SMB2
                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv2 record");
                                        match parse_smb2_response_record(nbss_data) {
                                            Ok((nbss_data_rem, ref smb_record)) => {
                                                let record_len = (nbss_data.len() - nbss_data_rem.len()) as i64;
                                                let pdu_frame = self.add_smb2_tc_pdu_frame(flow, stream_slice, nbss_data, record_len);
                                                self.add_smb2_tc_hdr_data_frames(flow, stream_slice, nbss_data, record_len, smb_record.header_len as i64);
                                                if smb_record.is_response() {
                                                    smb2_response_record(self, smb_record);
                                                } else {
                                                    SCLogDebug!("SMB2 request seen from server to client");
                                                    if let Some(frame) = pdu_frame {
                                                        frame.add_event(flow, SMBEvent::RequestToClient as u8);
                                                    }
                                                }
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                self.set_event(SMBEvent::MalformedData);
                                                return AppLayerResult::err();
                                            },
                                        }
                                    }
                                } else if smb.version == 0xfd_u8 { // SMB3 transform
                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv3 transform record");
                                        match parse_smb3_transform_record(nbss_data) {
                                            Ok((nbss_data_rem, ref _smb3_record)) => {
                                                let record_len = (nbss_data.len() - nbss_data_rem.len()) as i64;
                                                self.add_smb3_tc_pdu_frame(flow, stream_slice, nbss_data, record_len);
                                                self.add_smb3_tc_hdr_data_frames(flow, stream_slice, nbss_data, record_len);
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                self.set_event(SMBEvent::MalformedData);
                                                return AppLayerResult::err();
                                            },
                                        }
                                    }
                                }
                            },
                            Err(Err::Incomplete(_)) => {
                                // not enough data to contain basic SMB hdr
                                // TODO event: empty NBSS_MSGTYPE_SESSION_MESSAGE
                            },
                            Err(_) => {
                                self.set_event(SMBEvent::MalformedData);
                                return AppLayerResult::err();
                            },
                        }
                    } else {
                        SCLogDebug!("NBSS message {:X}", nbss_hdr.message_type);
                    }
                    cur_i = rem;
                },
                Err(Err::Incomplete(needed)) => {
                    SCLogDebug!("INCOMPLETE have {} needed {:?}", cur_i.len(), needed);
                    if let Needed::Size(n) = needed {
                        let n = usize::from(n) + cur_i.len();
                        // 512 is the minimum for parse_tcp_data_tc_partial
                        if n >= 512 && cur_i.len() < 512 {
                            let total_consumed = stream_slice.offset_from(cur_i);
                            return AppLayerResult::incomplete(total_consumed, 512);
                        }
                        let consumed = self.parse_tcp_data_tc_partial(flow, stream_slice, cur_i);
                        if consumed == 0 {
                            // if we consumed none we will buffer the entire record
                            let total_consumed = stream_slice.offset_from(cur_i);
                            SCLogDebug!("setting consumed {} need {} needed {:?} total input {}",
                                    total_consumed, n, needed, stream_slice.len());
                            let need = n;
                            return AppLayerResult::incomplete(total_consumed as u32, need as u32);
                        }
                        // tracking a read record, which we don't need to
                        // queue up at the stream level, but can feed to us
                        // in small chunks
                        return AppLayerResult::ok();
                    } else {
                        self.set_event(SMBEvent::InternalError);
                        return AppLayerResult::err();
                    }
                },
                Err(_) => {
                    self.set_event(SMBEvent::MalformedData);
                    return AppLayerResult::err();
                },
            }
        };
        self.post_gap_housekeeping(Direction::ToClient);
        if self.check_post_gap_file_txs && !self.post_gap_files_checked {
            self.post_gap_housekeeping_for_files();
            self.post_gap_files_checked = true;
        }
        self._debug_tx_stats();
        AppLayerResult::ok()
    }

    /// handle a gap in the TOSERVER direction
    /// returns: 0 ok, 1 unrecoverable error
    pub fn parse_tcp_data_ts_gap(&mut self, gap_size: u32) -> AppLayerResult {
        let consumed = self.handle_skip(Direction::ToServer, gap_size);
        if consumed < gap_size {
            let new_gap_size = gap_size - consumed;
            let gap = vec![0; new_gap_size as usize];

            let consumed2 = self.filetracker_update(Direction::ToServer, &gap, new_gap_size);
            if consumed2 > new_gap_size {
                SCLogDebug!("consumed more than GAP size: {} > {}", consumed2, new_gap_size);
                self.set_event(SMBEvent::InternalError);
                return AppLayerResult::err();
            }
        }
        SCLogDebug!("GAP of size {} in toserver direction", gap_size);
        self.ts_ssn_gap = true;
        self.ts_gap = true;
        return AppLayerResult::ok();
    }

    /// handle a gap in the TOCLIENT direction
    /// returns: 0 ok, 1 unrecoverable error
    pub fn parse_tcp_data_tc_gap(&mut self, gap_size: u32) -> AppLayerResult {
        let consumed = self.handle_skip(Direction::ToClient, gap_size);
        if consumed < gap_size {
            let new_gap_size = gap_size - consumed;
            let gap = vec![0; new_gap_size as usize];

            let consumed2 = self.filetracker_update(Direction::ToClient, &gap, new_gap_size);
            if consumed2 > new_gap_size {
                SCLogDebug!("consumed more than GAP size: {} > {}", consumed2, new_gap_size);
                self.set_event(SMBEvent::InternalError);
                return AppLayerResult::err();
            }
        }
        SCLogDebug!("GAP of size {} in toclient direction", gap_size);
        self.tc_ssn_gap = true;
        self.tc_gap = true;
        return AppLayerResult::ok();
    }

    pub fn trunc_ts(&mut self) {
        SCLogDebug!("TRUNC TS");
        self.ts_trunc = true;

        for tx in &mut self.transactions {
            if !tx.request_done {
                SCLogDebug!("TRUNCING TX {} in TOSERVER direction", tx.id);
                tx.request_done = true;
            }
       }
    }
    pub fn trunc_tc(&mut self) {
        SCLogDebug!("TRUNC TC");
        self.tc_trunc = true;

        for tx in &mut self.transactions {
            if !tx.response_done {
                SCLogDebug!("TRUNCING TX {} in TOCLIENT direction", tx.id);
                tx.response_done = true;
            }
        }
    }
}

/// Returns *mut SMBState
#[no_mangle]
pub extern "C" fn rs_smb_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = SMBState::new();
    let boxed = Box::new(state);
    SCLogDebug!("allocating state");
    return Box::into_raw(boxed) as *mut _;
}

/// Params:
/// - state: *mut SMBState as void pointer
#[no_mangle]
pub extern "C" fn rs_smb_state_free(state: *mut std::os::raw::c_void) {
    SCLogDebug!("freeing state");
    let mut smb_state = unsafe { Box::from_raw(state as *mut SMBState) };
    smb_state.free();
}

/// C binding parse a SMB request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn rs_smb_parse_request_tcp(flow: *const Flow,
                                       state: *mut ffi::c_void,
                                       _pstate: *mut std::os::raw::c_void,
                                       stream_slice: StreamSlice,
                                       _data: *const std::os::raw::c_void,
                                       )
                                       -> AppLayerResult
{
    let mut state = cast_pointer!(state, SMBState);
    let flow = cast_pointer!(flow, Flow);

    if stream_slice.is_gap() {
        return rs_smb_parse_request_tcp_gap(state, stream_slice.gap_size());
    }

    SCLogDebug!("parsing {} bytes of request data", stream_slice.len());

    /* START with MISTREAM set: record might be starting the middle. */
    if stream_slice.flags() & (STREAM_START|STREAM_MIDSTREAM) == (STREAM_START|STREAM_MIDSTREAM) {
        state.ts_gap = true;
    }

    state.update_ts(flow.get_last_time().as_secs());
    state.parse_tcp_data_ts(flow, &stream_slice)
}

#[no_mangle]
pub extern "C" fn rs_smb_parse_request_tcp_gap(
                                        state: &mut SMBState,
                                        input_len: u32)
                                        -> AppLayerResult
{
    state.parse_tcp_data_ts_gap(input_len as u32)
}


#[no_mangle]
pub unsafe extern "C" fn rs_smb_parse_response_tcp(flow: *const Flow,
                                        state: *mut ffi::c_void,
                                        _pstate: *mut std::os::raw::c_void,
                                        stream_slice: StreamSlice,
                                        _data: *const ffi::c_void,
                                        )
                                        -> AppLayerResult
{
    let mut state = cast_pointer!(state, SMBState);
    let flow = cast_pointer!(flow, Flow);

    if stream_slice.is_gap() {
        return rs_smb_parse_response_tcp_gap(state, stream_slice.gap_size());
    }

    /* START with MISTREAM set: record might be starting the middle. */
    if stream_slice.flags() & (STREAM_START|STREAM_MIDSTREAM) == (STREAM_START|STREAM_MIDSTREAM) {
        state.tc_gap = true;
    }

    state.update_ts(flow.get_last_time().as_secs());
    state.parse_tcp_data_tc(flow, &stream_slice)
}

#[no_mangle]
pub extern "C" fn rs_smb_parse_response_tcp_gap(
                                        state: &mut SMBState,
                                        input_len: u32)
                                        -> AppLayerResult
{
    state.parse_tcp_data_tc_gap(input_len as u32)
}

fn smb_probe_tcp_midstream(direction: Direction, slice: &[u8], rdir: *mut u8, begins: bool) -> i8
{
    let r = if begins {
        // if pattern was found in the beginning, just check first byte
        if slice[0] == NBSS_MSGTYPE_SESSION_MESSAGE {
            Ok((&slice[..4], &slice[4..]))
        } else {
            Err(Err::Error(make_error(slice, ErrorKind::Eof)))
        }
    } else {
        search_smb_record(slice)
    };
    match r {
        Ok((_, data)) => {
            SCLogDebug!("smb found");
            match parse_smb_version(data) {
                Ok((_, ref smb)) => {
                    SCLogDebug!("SMB {:?}", smb);
                    if smb.version == 0xff_u8 { // SMB1
                        SCLogDebug!("SMBv1 record");
                        match parse_smb_record(data) {
                            Ok((_, ref smb_record)) => {
                                if smb_record.flags & 0x80 != 0 {
                                    SCLogDebug!("RESPONSE {:02x}", smb_record.flags);
                                    if direction == Direction::ToServer {
                                        unsafe { *rdir = Direction::ToClient as u8; }
                                    }
                                } else {
                                    SCLogDebug!("REQUEST {:02x}", smb_record.flags);
                                    if direction == Direction::ToClient {
                                        unsafe { *rdir = Direction::ToServer as u8; }
                                    }
                                }
                                return 1;
                            },
                            _ => { },
                        }
                    } else if smb.version == 0xfe_u8 { // SMB2
                        SCLogDebug!("SMB2 record");
                        match parse_smb2_record_direction(data) {
                            Ok((_, ref smb_record)) => {
                                if direction == Direction::ToServer {
                                    SCLogDebug!("direction Direction::ToServer smb_record {:?}", smb_record);
                                    if !smb_record.request {
                                        unsafe { *rdir = Direction::ToClient as u8; }
                                    }
                                } else {
                                    SCLogDebug!("direction Direction::ToClient smb_record {:?}", smb_record);
                                    if smb_record.request {
                                        unsafe { *rdir = Direction::ToServer as u8; }
                                    }
                                }
                            },
                            _ => {},
                        }
                    }
                    else if smb.version == 0xfd_u8 { // SMB3 transform
                        SCLogDebug!("SMB3 record");
                    }
                    return 1;
                },
                    _ => {
                        SCLogDebug!("smb not found in {:?}", slice);
                    },
            }
        },
        _ => {
            SCLogDebug!("no dice");
        },
    }
    return 0;
}

fn smb_probe_tcp(flags: u8, slice: &[u8], rdir: *mut u8, begins: bool) -> AppProto
{
    if flags & STREAM_MIDSTREAM == STREAM_MIDSTREAM {
        if smb_probe_tcp_midstream(flags.into(), slice, rdir, begins) == 1 {
            unsafe { return ALPROTO_SMB; }
        }
    }
    match parse_nbss_record_partial(slice) {
        Ok((_, ref hdr)) => {
            if hdr.is_smb() {
                SCLogDebug!("smb found");
                unsafe { return ALPROTO_SMB; }
            } else if hdr.needs_more(){
                return 0;
            } else if hdr.is_valid() &&
                hdr.message_type != NBSS_MSGTYPE_SESSION_MESSAGE {
                //we accept a first small netbios message before real SMB
                let hl = hdr.length as usize;
                if hdr.data.len() >= hl + 8 {
                    // 8 is 4 bytes NBSS + 4 bytes SMB0xFX magic
                    match parse_nbss_record_partial(&hdr.data[hl..]) {
                        Ok((_, ref hdr2)) => {
                            if hdr2.is_smb() {
                                SCLogDebug!("smb found");
                                unsafe { return ALPROTO_SMB; }
                            }
                        }
                        _ => {}
                    }
                } else if hdr.length < 256 {
                    // we want more data, 256 is some random value
                    return 0;
                }
                // default is failure
            }
        },
        _ => { },
    }
    SCLogDebug!("no smb");
    unsafe { return ALPROTO_FAILED; }
}

// probing confirmation parser
// return 1 if found, 0 is not found
#[no_mangle]
pub unsafe extern "C" fn rs_smb_probe_begins_tcp(_f: *const Flow,
                                   flags: u8, input: *const u8, len: u32, rdir: *mut u8)
    -> AppProto
{
    if len < MIN_REC_SIZE as u32 {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, len as usize);
    return smb_probe_tcp(flags, slice, rdir, true);
}

// probing parser
// return 1 if found, 0 is not found
#[no_mangle]
pub unsafe extern "C" fn rs_smb_probe_tcp(_f: *const Flow,
                                   flags: u8, input: *const u8, len: u32, rdir: *mut u8)
    -> AppProto
{
    if len < MIN_REC_SIZE as u32 {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, len as usize);
    return smb_probe_tcp(flags, slice, rdir, false);
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_state_get_tx_count(state: *mut ffi::c_void)
                                            -> u64
{
    let state = cast_pointer!(state, SMBState);
    SCLogDebug!("rs_smb_state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_state_get_tx(state: *mut ffi::c_void,
                                      tx_id: u64)
                                      -> *mut ffi::c_void
{
    let state = cast_pointer!(state, SMBState);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_state_tx_free(state: *mut ffi::c_void,
                                       tx_id: u64)
{
    let state = cast_pointer!(state, SMBState);
    SCLogDebug!("freeing tx {}", tx_id as u64);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_tx_get_alstate_progress(tx: *mut ffi::c_void,
                                                  direction: u8)
                                                  -> i32
{
    let tx = cast_pointer!(tx, SMBTransaction);

    if direction == Direction::ToServer as u8 && tx.request_done {
        SCLogDebug!("tx {} TOSERVER progress 1 => {:?}", tx.id, tx);
    } else if direction == Direction::ToClient as u8 && tx.response_done {
        SCLogDebug!("tx {} TOCLIENT progress 1 => {:?}", tx.id, tx);

    } else {
        SCLogDebug!("tx {} direction {} progress 0 => {:?}", tx.id, direction, tx);
        return 0;
    }
    return 1;

}


export_state_data_get!(rs_smb_get_state_data, SMBState);

#[no_mangle]
pub unsafe extern "C" fn rs_smb_get_tx_data(
    tx: *mut std::os::raw::c_void)
    -> *mut AppLayerTxData
{
    let tx = cast_pointer!(tx, SMBTransaction);
    return &mut tx.tx_data;
}


#[no_mangle]
pub unsafe extern "C" fn rs_smb_state_truncate(
        state: *mut std::ffi::c_void,
        direction: u8)
{
    let state = cast_pointer!(state, SMBState);
    match direction.into() {
        Direction::ToServer => {
            state.trunc_ts();
        }
        Direction::ToClient => {
            state.trunc_tc();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_state_get_event_info_by_id(
    event_id: std::os::raw::c_int,
    event_name: *mut *const std::os::raw::c_char,
    event_type: *mut AppLayerEventType,
) -> i8 {
    SMBEvent::get_event_info_by_id(event_id, event_name, event_type)
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_state_get_event_info(
    event_name: *const std::os::raw::c_char,
    event_id: *mut std::os::raw::c_int,
    event_type: *mut AppLayerEventType,
) -> std::os::raw::c_int {
    SMBEvent::get_event_info(event_name, event_id, event_type)
}

pub unsafe extern "C" fn smb3_probe_tcp(f: *const Flow, dir: u8, input: *const u8, len: u32, rdir: *mut u8) -> u16 {
    let retval = rs_smb_probe_tcp(f, dir, input, len, rdir);
    let f = cast_pointer!(f, Flow);
    if retval != ALPROTO_SMB {
        return retval;
    }
    let (sp, dp) = f.get_ports();
    let flags = f.get_flags();
    let fsp = if (flags & FLOW_DIR_REVERSED) != 0 { dp } else { sp };
    let fdp = if (flags & FLOW_DIR_REVERSED) != 0 { sp } else { dp };
    if fsp == 445 && fdp != 445 {
        match dir.into() {
            Direction::ToServer => {
                *rdir = Direction::ToClient as u8;
            }
            Direction::ToClient => {
                *rdir = Direction::ToServer as u8;
            }
        }
    }
    return ALPROTO_SMB;
}

fn register_pattern_probe() -> i8 {
    let mut r = 0;
    unsafe {
        // SMB1
        r |= AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP as u8, ALPROTO_SMB,
                                                     b"|ff|SMB\0".as_ptr() as *const std::os::raw::c_char, 8, 4,
                                                     Direction::ToServer as u8, rs_smb_probe_begins_tcp, MIN_REC_SIZE, MIN_REC_SIZE);
        r |= AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP as u8, ALPROTO_SMB,
                                                     b"|ff|SMB\0".as_ptr() as *const std::os::raw::c_char, 8, 4,
                                                     Direction::ToClient as u8, rs_smb_probe_begins_tcp, MIN_REC_SIZE, MIN_REC_SIZE);
        // SMB2/3
        r |= AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP as u8, ALPROTO_SMB,
                                                     b"|fe|SMB\0".as_ptr() as *const std::os::raw::c_char, 8, 4,
                                                     Direction::ToServer as u8, rs_smb_probe_begins_tcp, MIN_REC_SIZE, MIN_REC_SIZE);
        r |= AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP as u8, ALPROTO_SMB,
                                                     b"|fe|SMB\0".as_ptr() as *const std::os::raw::c_char, 8, 4,
                                                     Direction::ToClient as u8, rs_smb_probe_begins_tcp, MIN_REC_SIZE, MIN_REC_SIZE);
        // SMB3 encrypted records
        r |= AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP as u8, ALPROTO_SMB,
                                                     b"|fd|SMB\0".as_ptr() as *const std::os::raw::c_char, 8, 4,
                                                     Direction::ToServer as u8, smb3_probe_tcp, MIN_REC_SIZE, MIN_REC_SIZE);
        r |= AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP as u8, ALPROTO_SMB,
                                                     b"|fd|SMB\0".as_ptr() as *const std::os::raw::c_char, 8, 4,
                                                     Direction::ToClient as u8, smb3_probe_tcp, MIN_REC_SIZE, MIN_REC_SIZE);
    }

    if r == 0 {
        return 0;
    } else {
        return -1;
    }
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"smb\0";

#[no_mangle]
pub unsafe extern "C" fn rs_smb_register_parser() {
    let default_port = CString::new("445").unwrap();
    let mut stream_depth = SMB_CONFIG_DEFAULT_STREAM_DEPTH;
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_smb_state_new,
        state_free: rs_smb_state_free,
        tx_free: rs_smb_state_tx_free,
        parse_ts: rs_smb_parse_request_tcp,
        parse_tc: rs_smb_parse_response_tcp,
        get_tx_count: rs_smb_state_get_tx_count,
        get_tx: rs_smb_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_smb_tx_get_alstate_progress,
        get_eventinfo: Some(rs_smb_state_get_event_info),
        get_eventinfo_byid : Some(rs_smb_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: Some(rs_smb_gettxfiles),
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<SMBState, SMBTransaction>),
        get_tx_data: rs_smb_get_tx_data,
        get_state_data: rs_smb_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: Some(rs_smb_state_truncate),
        get_frame_id_by_name: Some(SMBFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(SMBFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SMB = alproto;
        if register_pattern_probe() < 0 {
            return;
        }

        let have_cfg = AppLayerProtoDetectPPParseConfPorts(ip_proto_str.as_ptr(),
                    IPPROTO_TCP as u8, parser.name, ALPROTO_SMB, 0,
                    MIN_REC_SIZE, rs_smb_probe_tcp, rs_smb_probe_tcp);

        if have_cfg == 0 {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP as u8, default_port.as_ptr(), ALPROTO_SMB,
                                          0, MIN_REC_SIZE, Direction::ToServer as u8, rs_smb_probe_tcp, rs_smb_probe_tcp);
        }

        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust SMB parser registered.");
        let retval = conf_get("app-layer.protocols.smb.stream-depth");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => { stream_depth = retval as u32; }
                Err(_) => { SCLogError!("Invalid depth value"); }
            }
        }
        AppLayerParserSetStreamDepth(IPPROTO_TCP as u8, ALPROTO_SMB, stream_depth);
        let retval = conf_get("app-layer.protocols.smb.max-read-size");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => { SMB_CFG_MAX_READ_SIZE = retval as u32; }
                Err(_) => { SCLogError!("Invalid max-read-size value"); }
            }
        }
        let retval = conf_get("app-layer.protocols.smb.max-write-size");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => { SMB_CFG_MAX_WRITE_SIZE = retval as u32; }
                Err(_) => { SCLogError!("Invalid max-write-size value"); }
            }
        }
        let retval = conf_get("app-layer.protocols.smb.max-write-queue-size");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => { SMB_CFG_MAX_WRITE_QUEUE_SIZE = retval as u32; }
                Err(_) => { SCLogError!("Invalid max-write-queue-size value"); }
            }
        }
        let retval = conf_get("app-layer.protocols.smb.max-write-queue-cnt");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => { SMB_CFG_MAX_WRITE_QUEUE_CNT = retval as u32; }
                Err(_) => { SCLogError!("Invalid max-write-queue-cnt value"); }
            }
        }
        let retval = conf_get("app-layer.protocols.smb.max-read-queue-size");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => { SMB_CFG_MAX_READ_QUEUE_SIZE = retval as u32; }
                Err(_) => { SCLogError!("Invalid max-read-queue-size value"); }
            }
        }
        let retval = conf_get("app-layer.protocols.smb.max-read-queue-cnt");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => { SMB_CFG_MAX_READ_QUEUE_CNT = retval as u32; }
                Err(_) => { SCLogError!("Invalid max-read-queue-cnt value"); }
            }
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for SMB.");
    }
}
