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

/* TODO
 * - check all parsers for calls on non-SUCCESS status
 */

/*  GAP processing:
 *  - if post-gap we've seen a succesful tx req/res: we consider "re-sync'd"
 */

// written by Victor Julien

use std;
use std::mem::transmute;
use std::str;
use std::ffi::CStr;

use std::collections::HashMap;

use nom;

use core::*;
use log::*;
use applayer;
use applayer::LoggerFlags;

use smb::nbss_records::*;
use smb::smb1_records::*;
use smb::smb2_records::*;

use smb::smb1::*;
use smb::smb2::*;
use smb::smb3::*;
use smb::dcerpc::*;
use smb::session::*;
use smb::events::*;
use smb::files::*;
use smb::smb2_ioctl::*;

pub static mut SURICATA_SMB_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

#[no_mangle]
pub extern "C" fn rs_smb_init(context: &'static mut SuricataFileContext)
{
    unsafe {
        SURICATA_SMB_FILE_CONFIG = Some(context);
    }
}

pub const SMB_NTSTATUS_SUCCESS:                    u32 = 0;
pub const SMB_NTSTATUS_PENDING:                    u32 = 0x00000103;
pub const SMB_NTSTATUS_BUFFER_OVERFLOW:            u32 = 0x80000005;
pub const SMB_NTSTATUS_NO_MORE_FILES:              u32 = 0x80000006;
pub const SMB_NTSTATUS_NO_MORE_ENTRIES:            u32 = 0x8000001a;
pub const SMB_NTSTATUS_INVALID_HANDLE:             u32 = 0xc0000008;
pub const SMB_NTSTATUS_INVALID_PARAMETER:          u32 = 0xc000000d;
pub const SMB_NTSTATUS_NO_SUCH_DEVICE:             u32 = 0xc000000e;
pub const SMB_NTSTATUS_NO_SUCH_FILE:               u32 = 0xc000000f;
pub const SMB_NTSTATUS_INVALID_DEVICE_REQUEST:     u32 = 0xc0000010;
pub const SMB_NTSTATUS_END_OF_FILE:                u32 = 0xc0000011;
pub const SMB_NTSTATUS_MORE_PROCESSING_REQUIRED:   u32 = 0xc0000016;
pub const SMB_NTSTATUS_ACCESS_DENIED:              u32 = 0xc0000022;
pub const SMB_NTSTATUS_OBJECT_NAME_INVALID:        u32 = 0xc0000033;
pub const SMB_NTSTATUS_OBJECT_NAME_NOT_FOUND:      u32 = 0xc0000034;
pub const SMB_NTSTATUS_OBJECT_NAME_COLLISION:      u32 = 0xc0000035;
pub const SMB_NTSTATUS_OBJECT_PATH_NOT_FOUND:      u32 = 0xc000003a;
pub const SMB_NTSTATUS_SHARING_VIOLATION:          u32 = 0xc0000043;
pub const SMB_NTSTATUS_LOCK_CONFLICT:              u32 = 0xc0000054;
pub const SMB_NTSTATUS_LOCK_NOT_GRANTED:           u32 = 0xc0000055;
pub const SMB_NTSTATUS_PRIVILEGE_NOT_HELD:         u32 = 0xc0000061;
pub const SMB_NTSTATUS_LOGON_FAILURE:              u32 = 0xc000006d;
pub const SMB_NTSTATUS_PIPE_DISCONNECTED:          u32 = 0xc00000b0;
pub const SMB_NTSTATUS_FILE_IS_A_DIRECTORY:        u32 = 0xc00000ba;
pub const SMB_NTSTATUS_NOT_SUPPORTED:              u32 = 0xc00000bb;
pub const SMB_NTSTATUS_BAD_NETWORK_NAME:           u32 = 0xc00000cc;
pub const SMB_NTSTATUS_REQUEST_NOT_ACCEPTED:       u32 = 0xc00000d0;
pub const SMB_NTSTATUS_OPLOCK_NOT_GRANTED:         u32 = 0xc00000e2;
pub const SMB_NTSTATUS_CANCELLED:                  u32 = 0xc0000120;
pub const SMB_NTSTATUS_FILE_CLOSED:                u32 = 0xc0000128;
pub const SMB_NTSTATUS_FS_DRIVER_REQUIRED:         u32 = 0xc000019c;
pub const SMB_NTSTATUS_INSUFF_SERVER_RESOURCES:    u32 = 0xc0000205;
pub const SMB_NTSTATUS_NOT_FOUND:                  u32 = 0xc0000225;
pub const SMB_NTSTATUS_PIPE_BROKEN:                u32 = 0xc000014b;
pub const SMB_NTSTATUS_TRUSTED_RELATIONSHIP_FAILURE:    u32 = 0xc000018d;
pub const SMB_NTSTATUS_NOT_A_REPARSE_POINT:        u32 = 0xc0000275;
pub const SMB_NTSTATUS_NETWORK_SESSION_EXPIRED:    u32 = 0xc000035c;

pub fn smb_ntstatus_string(c: u32) -> String {
    match c {
        SMB_NTSTATUS_SUCCESS                   => "STATUS_SUCCESS",
        SMB_NTSTATUS_BUFFER_OVERFLOW           => "STATUS_BUFFER_OVERFLOW",
        SMB_NTSTATUS_PENDING                   => "STATUS_PENDING",
        SMB_NTSTATUS_NO_MORE_FILES             => "STATUS_NO_MORE_FILES",
        SMB_NTSTATUS_NO_MORE_ENTRIES           => "STATUS_NO_MORE_ENTRIES",
        SMB_NTSTATUS_INVALID_HANDLE            => "STATUS_INVALID_HANDLE",
        SMB_NTSTATUS_INVALID_PARAMETER         => "STATUS_INVALID_PARAMETER",
        SMB_NTSTATUS_NO_SUCH_DEVICE            => "STATUS_NO_SUCH_DEVICE",
        SMB_NTSTATUS_NO_SUCH_FILE              => "STATUS_NO_SUCH_FILE",
        SMB_NTSTATUS_INVALID_DEVICE_REQUEST    => "STATUS_INVALID_DEVICE_REQUEST",
        SMB_NTSTATUS_END_OF_FILE               => "STATUS_END_OF_FILE",
        SMB_NTSTATUS_MORE_PROCESSING_REQUIRED  => "STATUS_MORE_PROCESSING_REQUIRED",
        SMB_NTSTATUS_ACCESS_DENIED             => "STATUS_ACCESS_DENIED",
        SMB_NTSTATUS_OBJECT_NAME_INVALID       => "STATUS_OBJECT_NAME_INVALID",
        SMB_NTSTATUS_OBJECT_NAME_NOT_FOUND     => "STATUS_OBJECT_NAME_NOT_FOUND",
        SMB_NTSTATUS_OBJECT_NAME_COLLISION     => "STATUS_OBJECT_NAME_COLLISION",
        SMB_NTSTATUS_OBJECT_PATH_NOT_FOUND     => "STATUS_OBJECT_PATH_NOT_FOUND",
        SMB_NTSTATUS_SHARING_VIOLATION         => "STATUS_SHARING_VIOLATION",
        SMB_NTSTATUS_LOCK_CONFLICT             => "STATUS_LOCK_CONFLICT",
        SMB_NTSTATUS_LOCK_NOT_GRANTED          => "STATUS_LOCK_NOT_GRANTED",
        SMB_NTSTATUS_PRIVILEGE_NOT_HELD        => "STATUS_PRIVILEGE_NOT_HELD",
        SMB_NTSTATUS_LOGON_FAILURE             => "STATUS_LOGON_FAILURE",
        SMB_NTSTATUS_PIPE_DISCONNECTED         => "STATUS_PIPE_DISCONNECTED",
        SMB_NTSTATUS_FILE_IS_A_DIRECTORY       => "STATUS_FILE_IS_A_DIRECTORY",
        SMB_NTSTATUS_NOT_SUPPORTED             => "STATUS_NOT_SUPPORTED",
        SMB_NTSTATUS_BAD_NETWORK_NAME          => "STATUS_BAD_NETWORK_NAME",
        SMB_NTSTATUS_REQUEST_NOT_ACCEPTED      => "STATUS_REQUEST_NOT_ACCEPTED",
        SMB_NTSTATUS_OPLOCK_NOT_GRANTED        => "STATUS_OPLOCK_NOT_GRANTED",
        SMB_NTSTATUS_CANCELLED                 => "STATUS_CANCELLED",
        SMB_NTSTATUS_FILE_CLOSED               => "STATUS_FILE_CLOSED",
        SMB_NTSTATUS_FS_DRIVER_REQUIRED        => "STATUS_FS_DRIVER_REQUIRED",
        SMB_NTSTATUS_INSUFF_SERVER_RESOURCES   => "STATUS_INSUFF_SERVER_RESOURCES",
        SMB_NTSTATUS_NOT_FOUND                 => "STATUS_NOT_FOUND",
        SMB_NTSTATUS_PIPE_BROKEN               => "STATUS_PIPE_BROKEN",
        SMB_NTSTATUS_TRUSTED_RELATIONSHIP_FAILURE   => "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
        SMB_NTSTATUS_NOT_A_REPARSE_POINT       => "STATUS_NOT_A_REPARSE_POINT",
        SMB_NTSTATUS_NETWORK_SESSION_EXPIRED   => "STATUS_NETWORK_SESSION_EXPIRED",
        _ => { return (c).to_string(); },
    }.to_string()
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

#[derive(Eq, PartialEq, Debug, Clone)]
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
    pub fn new() -> SMBVerCmdStat {
        return SMBVerCmdStat {
            smb_ver: 0,
            smb1_cmd: 0,
            smb2_cmd: 0,
            status_set: false,
            status_is_dos_error: false,
            status_error_class: 0,
            status: 0,
        }
    }
    pub fn new1(cmd: u8) -> SMBVerCmdStat {
        return SMBVerCmdStat {
            smb_ver: 1,
            smb1_cmd: cmd,
            smb2_cmd: 0,
            status_set: false,
            status_is_dos_error: false,
            status_error_class: 0,
            status: 0,
        }
    }
    pub fn new1_with_ntstatus(cmd: u8, status: u32) -> SMBVerCmdStat {
        return SMBVerCmdStat {
            smb_ver: 1,
            smb1_cmd: cmd,
            smb2_cmd: 0,
            status_set: true,
            status_is_dos_error: false,
            status_error_class: 0,
            status: status,
        }
    }
    pub fn new2(cmd: u16) -> SMBVerCmdStat {
        return SMBVerCmdStat {
            smb_ver: 2,
            smb1_cmd: 0,
            smb2_cmd: cmd,
            status_set: false,
            status_is_dos_error: false,
            status_error_class: 0,
            status: 0,
        }
    }

    pub fn new2_with_ntstatus(cmd: u16, status: u32) -> SMBVerCmdStat {
        return SMBVerCmdStat {
            smb_ver: 2,
            smb1_cmd: 0,
            smb2_cmd: cmd,
            status_set: true,
            status_is_dos_error: false,
            status_error_class: 0,
            status: status,
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
    pub fn new(raw: u64) -> SMBFiletime {
        SMBFiletime {
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
        -> SMBTransactionSetFilePathInfo
    {
        return SMBTransactionSetFilePathInfo {
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
        -> (&mut SMBTransaction)
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
        -> (&mut SMBTransaction)
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
    pub fn new(fuid: Vec<u8>, oldname: Vec<u8>, newname: Vec<u8>) -> SMBTransactionRename {
        return SMBTransactionRename {
            fuid: fuid, oldname: oldname, newname: newname,
        }
    }
}

impl SMBState {
    pub fn new_rename_tx(&mut self, fuid: Vec<u8>, oldname: Vec<u8>, newname: Vec<u8>)
        -> (&mut SMBTransaction)
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

#[derive(Debug)]
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
    pub fn new(filename: Vec<u8>, disp: u32, del: bool, dir: bool) -> SMBTransactionCreate {
        return SMBTransactionCreate {
            disposition: disp,
            delete_on_close: del,
            directory: dir,
            filename: filename,
            guid: Vec::new(),
            create_ts: 0,
            last_access_ts: 0,
            last_write_ts: 0,
            last_change_ts: 0,
            size: 0,
        }
    }
}

#[derive(Debug)]
pub struct SMBTransactionNegotiate {
    pub smb_ver: u8,
    pub dialects: Vec<Vec<u8>>,
    pub dialects2: Vec<Vec<u8>>,

    // SMB1 doesn't have the client GUID
    pub client_guid: Option<Vec<u8>>,
    pub server_guid: Vec<u8>,
}

impl SMBTransactionNegotiate {
    pub fn new(smb_ver: u8) -> SMBTransactionNegotiate {
        return SMBTransactionNegotiate {
            smb_ver: smb_ver,
            dialects: Vec::new(),
            dialects2: Vec::new(),
            client_guid: None,
            server_guid: Vec::with_capacity(16),
        }
    }
}

#[derive(Debug)]
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
    pub fn new(share_name: Vec<u8>) -> SMBTransactionTreeConnect {
        return SMBTransactionTreeConnect {
            is_pipe:false,
            share_type: 0,
            tree_id:0,
            share_name:share_name,
            req_service: None,
            res_service: None,
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

    /// detection engine flags for use by detection engine
    detect_flags_ts: u64,
    detect_flags_tc: u64,
    pub logged: LoggerFlags,
    pub de_state: Option<*mut DetectEngineState>,
    pub events: *mut AppLayerDecoderEvents,
}

impl SMBTransaction {
    pub fn new() -> SMBTransaction {
        return SMBTransaction{
            id: 0,
            vercmd: SMBVerCmdStat::new(),
            hdr: SMBCommonHdr::init(),
            request_done: false,
            response_done: false,
            type_data: None,
            detect_flags_ts: 0,
            detect_flags_tc: 0,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
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
    pub fn new(guid: Vec<u8>, offset: u64) -> SMBFileGUIDOffset {
        SMBFileGUIDOffset {
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

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct SMBCommonHdr {
    pub ssn_id: u64,
    pub tree_id: u32,
    pub rec_type: u32,
    pub msg_id: u64,
}

impl SMBCommonHdr {
    pub fn init() -> SMBCommonHdr {
        SMBCommonHdr {
            rec_type : 0,
            ssn_id : 0,
            tree_id : 0,
            msg_id : 0,
        }
    }
    pub fn new(rec_type: u32, ssn_id: u64, tree_id: u32, msg_id: u64) -> SMBCommonHdr {
        SMBCommonHdr {
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
        (self.rec_type == hdr.rec_type && self.ssn_id == hdr.ssn_id &&
         self.msg_id == hdr.msg_id)
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct SMBHashKeyHdrGuid {
    hdr: SMBCommonHdr,
    guid: Vec<u8>,
}

impl SMBHashKeyHdrGuid {
    pub fn new(hdr: SMBCommonHdr, guid: Vec<u8>) -> SMBHashKeyHdrGuid {
        SMBHashKeyHdrGuid {
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
    pub fn new(name: Vec<u8>, is_pipe: bool) -> SMBTree {
        SMBTree {
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

pub struct SMBState<> {
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

    /// TCP segments defragmentation buffer
    pub tcp_buffer_ts: Vec<u8>,
    pub tcp_buffer_tc: Vec<u8>,

    pub files: SMBFiles,

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
}

impl SMBState {
    /// Allocation function for a new TLS parser instance
    pub fn new() -> SMBState {
        SMBState {
            ssn2vec_map:HashMap::new(),
            guid2name_map:HashMap::new(),
            ssn2vecoffset_map:HashMap::new(),
            ssn2tree_map:HashMap::new(),
            ssnguid2vec_map:HashMap::new(),
            tcp_buffer_ts:Vec::new(),
            tcp_buffer_tc:Vec::new(),
            files: SMBFiles::new(),
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
            transactions: Vec::new(),
            tx_id:0,
            dialect:0,
            dialect_vec: None,
            dcerpc_ifaces: None,
        }
    }

    pub fn free(&mut self) {
        //self._debug_state_stats();
        self._debug_tx_stats();
        self.files.free();
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

    // for use with the C API call StateGetTxIterator
    pub fn get_tx_iterator(&mut self, min_tx_id: u64, state: &mut u64) ->
        Option<(&SMBTransaction, u64, bool)>
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
            //SCLogDebug!("returning tx_id {} has_next? {} (len {} index {}), tx {:?}",
            //        tx.id - 1, (len - index) > 1, len, index, tx);
            return Some((tx, tx.id - 1, (len - index) > 1));
        }
        return None;
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
                return Some(tx);
            }
        }
        SCLogDebug!("Failed to find SMB TX with ID {}", tx_id);
        return None;
    }

    /* generic TX has no type_data and is only used to
     * track a single cmd request/reply pair. */

    pub fn new_generic_tx(&mut self, smb_ver: u8, smb_cmd: u16, key: SMBCommonHdr)
        -> (&mut SMBTransaction)
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
        -> (&mut SMBTransaction)
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
        -> (&mut SMBTransaction)
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
                    tx.hdr.compare(&hdr)
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
        (&name, is_dcerpc)
    }

    /* if we have marked the ssn as 'gapped' we check to see if
     * we've caught up. The check is to see if we have the last
     * tx in our list is done. This means we've seen both sides
     * and we're back in sync. Mark older txs as 'done' */
    fn check_gap_resync(&mut self, prior_max_id: u64)
    {
        SCLogDebug!("check_gap_resync2: post-GAP resync check ({}/{})", self.ts_ssn_gap, self.tc_ssn_gap);
        if !self.ts_ssn_gap && !self.tc_ssn_gap {
            return;
        }

        let (last_done, id) = match self.transactions.last() {
            Some(tx) => {
                (tx.request_done && tx.response_done, tx.id)
            },
            None => (false, 0),
        };
        if last_done && id > 0 {
            SCLogDebug!("check_gap_resync2: TX {} is done post-GAP, mark all older ones complete", id);
            self.ts_ssn_gap = false;
            self.tc_ssn_gap = false;
            self.close_non_file_txs(prior_max_id);
        }
    }

    /* close all txs execpt file xfers. */
    fn close_non_file_txs(&mut self, max_id: u64) {
        SCLogDebug!("close_non_file_txs: checking for non-file txs to wrap up");
        for tx in &mut self.transactions {
            if tx.id >= max_id {
                SCLogDebug!("close_non_file_txs: done");
                break;
            }
            if let Some(SMBTransactionTypeData::FILE(_)) = tx.type_data {
                // leaving FILE txs open as they can deal with gaps.
            } else {
                SCLogDebug!("ose_non_file_txs: tx {} marked as done", tx.id);
                tx.request_done = true;
                tx.response_done = true;
            }
        }
    }

    pub fn set_file_left(&mut self, direction: u8, rec_size: u32, data_size: u32, fuid: Vec<u8>)
    {
        let left = rec_size.saturating_sub(data_size);
        if direction == STREAM_TOSERVER {
            self.file_ts_left = left;
            self.file_ts_guid = fuid;
        } else {
            self.file_tc_left = left;
            self.file_tc_guid = fuid;
        }
    }

    pub fn set_skip(&mut self, direction: u8, rec_size: u32, data_size: u32)
    {
        let skip = rec_size.saturating_sub(data_size);
        if direction == STREAM_TOSERVER {
            self.skip_ts = skip;
        } else {
            self.skip_tc = skip;
        }
    }

    // return how much data we consumed
    fn handle_skip(&mut self, direction: u8, input_size: u32) -> u32 {
        let mut skip_left = if direction == STREAM_TOSERVER {
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

        if direction == STREAM_TOSERVER {
            self.skip_ts = skip_left;
        } else {
            self.skip_tc = skip_left;
        }
        return consumed;
    }

    /// return bytes consumed
    pub fn parse_tcp_data_ts_partial<'b>(&mut self, input: &'b[u8]) -> usize
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
                    match parse_smb_version(&nbss_part_hdr.data) {
                        Ok((_, ref smb)) => {
                            SCLogDebug!("SMB {:?}", smb);
                            if smb.version == 0xff_u8 { // SMB1
                                SCLogDebug!("SMBv1 record");
                                match parse_smb_record(&nbss_part_hdr.data) {
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
                                            smb1_write_request_record(self, r);
                                            let consumed = input.len() - output.len();
                                            return consumed;
                                        }
                                    },
                                    _ => { },

                                }
                            } else if smb.version == 0xfe_u8 { // SMB2
                                SCLogDebug!("SMBv2 record");
                                match parse_smb2_request_record(&nbss_part_hdr.data) {
                                    Ok((_, ref smb_record)) => {
                                        SCLogDebug!("SMB2: partial record {}",
                                                &smb2_command_string(smb_record.command));
                                        if smb_record.command == SMB2_COMMAND_WRITE {
                                            smb2_write_request_record(self, smb_record);
                                            let consumed = input.len() - output.len();
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
    pub fn parse_tcp_data_ts<'b>(&mut self, i: &'b[u8]) -> u32
    {
        let max_tx_id = self.tx_id;

        let mut v : Vec<u8>;
        //println!("parse_tcp_data_ts ({})",i.len());
        //println!("{:?}",i);
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer_ts.len() {
            0 => i,
            _ => {
                v = self.tcp_buffer_ts.split_off(0);
                if self.tcp_buffer_ts.len() + i.len() > 100000 {
                    self.set_event(SMBEvent::RecordOverflow);
                    return 1;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        //println!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        if cur_i.len() > 1000000 {
            self.set_event(SMBEvent::RecordOverflow);
            return 1;
        }
        let consumed = self.handle_skip(STREAM_TOSERVER, cur_i.len() as u32);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return 1;
            }
            cur_i = &cur_i[consumed as usize..];
        }
        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(STREAM_TOSERVER, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return 1;
            }
            cur_i = &cur_i[consumed as usize..];
        }
        // gap
        if self.ts_gap {
            SCLogDebug!("TS trying to catch up after GAP (input {})", cur_i.len());
            match search_smb_record(cur_i) {
                Ok((_, pg)) => {
                    SCLogDebug!("smb record found");
                    let smb2_offset = cur_i.len() - pg.len();
                    if smb2_offset < 4 {
                        return 0;
                    }
                    let nbss_offset = smb2_offset - 4;
                    cur_i = &cur_i[nbss_offset..];

                    self.ts_gap = false;
                },
                _ => {
                    SCLogDebug!("smb record NOT found");
                    self.tcp_buffer_ts.extend_from_slice(cur_i);
                    return 0;
                },
            }
        }
        while cur_i.len() > 0 { // min record size
            match parse_nbss_record(cur_i) {
                Ok((rem, ref nbss_hdr)) => {
                    if nbss_hdr.message_type == NBSS_MSGTYPE_SESSION_MESSAGE {
                        // we have the full records size worth of data,
                        // let's parse it
                        match parse_smb_version(&nbss_hdr.data) {
                            Ok((_, ref smb)) => {
                                SCLogDebug!("SMB {:?}", smb);
                                if smb.version == 0xff_u8 { // SMB1
                                    SCLogDebug!("SMBv1 record");
                                    match parse_smb_record(&nbss_hdr.data) {
                                        Ok((_, ref smb_record)) => {
                                            smb1_request_record(self, smb_record);
                                        },
                                        _ => {
                                            self.set_event(SMBEvent::MalformedData);
                                            return 1;
                                        },
                                    }
                                } else if smb.version == 0xfe_u8 { // SMB2
                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv2 record");
                                        match parse_smb2_request_record(&nbss_data) {
                                            Ok((nbss_data_rem, ref smb_record)) => {
                                                SCLogDebug!("nbss_data_rem {}", nbss_data_rem.len());

                                                smb2_request_record(self, smb_record);
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                self.set_event(SMBEvent::MalformedData);
                                                return 1;
                                            },
                                        }
                                    }
                                } else if smb.version == 0xfd_u8 { // SMB3 transform
                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv3 transform record");
                                        match parse_smb3_transform_record(&nbss_data) {
                                            Ok((nbss_data_rem, ref _smb3_record)) => {
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                self.set_event(SMBEvent::MalformedData);
                                                return 1;
                                            },
                                        }
                                    }
                                }
                            },
                            _ => {
                                self.set_event(SMBEvent::MalformedData);
                                return 1;
                            },
                        }
                    } else {
                        SCLogDebug!("NBSS message {:X}", nbss_hdr.message_type);
                    }
                    cur_i = rem;
                },
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = self.parse_tcp_data_ts_partial(cur_i);
                    cur_i = &cur_i[consumed ..];

                    self.tcp_buffer_ts.extend_from_slice(cur_i);
                    break;
                },
                Err(_) => {
                    self.set_event(SMBEvent::MalformedData);
                    return 1;
                },
            }
        };

        self.check_gap_resync(max_tx_id);
        0
    }

    /// return bytes consumed
    pub fn parse_tcp_data_tc_partial<'b>(&mut self, input: &'b[u8]) -> usize
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

        match parse_nbss_record_partial(input) {
            Ok((output, ref nbss_part_hdr)) => {
                SCLogDebug!("parse_nbss_record_partial ok, output len {}", output.len());
                if nbss_part_hdr.message_type == NBSS_MSGTYPE_SESSION_MESSAGE {
                    match parse_smb_version(&nbss_part_hdr.data) {
                        Ok((_, ref smb)) => {
                            SCLogDebug!("SMB {:?}", smb);
                            if smb.version == 255u8 { // SMB1
                                SCLogDebug!("SMBv1 record");
                                match parse_smb_record(&nbss_part_hdr.data) {
                                    Ok((_, ref r)) => {
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
                                            smb1_read_response_record(self, r);
                                            let consumed = input.len() - output.len();
                                            return consumed;
                                        }
                                    },
                                    _ => { },
                                }
                            } else if smb.version == 254u8 { // SMB2
                                SCLogDebug!("SMBv2 record");
                                match parse_smb2_response_record(&nbss_part_hdr.data) {
                                    Ok((_, ref smb_record)) => {
                                        SCLogDebug!("SMB2: partial record {}",
                                                &smb2_command_string(smb_record.command));
                                        if smb_record.command == SMB2_COMMAND_READ {
                                            smb2_read_response_record(self, smb_record);
                                            let consumed = input.len() - output.len();
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
    pub fn parse_tcp_data_tc<'b>(&mut self, i: &'b[u8]) -> u32
    {
        let max_tx_id = self.tx_id;

        let mut v : Vec<u8>;
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer_tc.len() {
            0 => i,
            _ => {
                v = self.tcp_buffer_tc.split_off(0);
                if self.tcp_buffer_tc.len() + i.len() > 100000 {
                    self.set_event(SMBEvent::RecordOverflow);
                    return 1;
                };
                v.extend_from_slice(i);
                v.as_slice()
            },
        };
        let mut cur_i = tcp_buffer;
        SCLogDebug!("cur_i.len {}", cur_i.len());
        if cur_i.len() > 100000 {
            self.set_event(SMBEvent::RecordOverflow);
            return 1;
        }
        let consumed = self.handle_skip(STREAM_TOCLIENT, cur_i.len() as u32);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return 1;
            }
            cur_i = &cur_i[consumed as usize..];
        }
        // take care of in progress file chunk transfers
        // and skip buffer beyond it
        let consumed = self.filetracker_update(STREAM_TOCLIENT, cur_i, 0);
        if consumed > 0 {
            if consumed > cur_i.len() as u32 {
                self.set_event(SMBEvent::InternalError);
                return 1;
            }
            cur_i = &cur_i[consumed as usize..];
        }
        // gap
        if self.tc_gap {
            SCLogDebug!("TC trying to catch up after GAP (input {})", cur_i.len());
            match search_smb_record(cur_i) {
                Ok((_, pg)) => {
                    SCLogDebug!("smb record found");
                    let smb2_offset = cur_i.len() - pg.len();
                    if smb2_offset < 4 {
                        return 0;
                    }
                    let nbss_offset = smb2_offset - 4;
                    cur_i = &cur_i[nbss_offset..];

                    self.tc_gap = false;
                },
                _ => {
                    SCLogDebug!("smb record NOT found");
                    self.tcp_buffer_tc.extend_from_slice(cur_i);
                    return 0;
                },
            }
        }
        while cur_i.len() > 0 { // min record size
            match parse_nbss_record(cur_i) {
                Ok((rem, ref nbss_hdr)) => {
                    if nbss_hdr.message_type == NBSS_MSGTYPE_SESSION_MESSAGE {
                        // we have the full records size worth of data,
                        // let's parse it
                        match parse_smb_version(&nbss_hdr.data) {
                            Ok((_, ref smb)) => {
                                SCLogDebug!("SMB {:?}", smb);
                                if smb.version == 0xff_u8 { // SMB1
                                    SCLogDebug!("SMBv1 record");
                                    match parse_smb_record(&nbss_hdr.data) {
                                        Ok((_, ref smb_record)) => {
                                            smb1_response_record(self, smb_record);
                                        },
                                        _ => {
                                            self.set_event(SMBEvent::MalformedData);
                                            return 1;
                                        },
                                    }
                                } else if smb.version == 0xfe_u8 { // SMB2
                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv2 record");
                                        match parse_smb2_response_record(&nbss_data) {
                                            Ok((nbss_data_rem, ref smb_record)) => {
                                                smb2_response_record(self, smb_record);
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                self.set_event(SMBEvent::MalformedData);
                                                return 1;
                                            },
                                        }
                                    }
                                } else if smb.version == 0xfd_u8 { // SMB3 transform
                                    let mut nbss_data = nbss_hdr.data;
                                    while nbss_data.len() > 0 {
                                        SCLogDebug!("SMBv3 transform record");
                                        match parse_smb3_transform_record(&nbss_data) {
                                            Ok((nbss_data_rem, ref _smb3_record)) => {
                                                nbss_data = nbss_data_rem;
                                            },
                                            _ => {
                                                self.set_event(SMBEvent::MalformedData);
                                                return 1;
                                            },
                                        }
                                    }
                                }
                            },
                            Err(nom::Err::Incomplete(_)) => {
                                // not enough data to contain basic SMB hdr
                                // TODO event: empty NBSS_MSGTYPE_SESSION_MESSAGE
                            },
                            Err(_) => {
                                self.set_event(SMBEvent::MalformedData);
                                return 1;
                            },
                        }
                    } else {
                        SCLogDebug!("NBSS message {:X}", nbss_hdr.message_type);
                    }
                    cur_i = rem;
                },
                Err(nom::Err::Incomplete(needed)) => {
                    SCLogDebug!("INCOMPLETE have {} needed {:?}", cur_i.len(), needed);
                    let consumed = self.parse_tcp_data_tc_partial(cur_i);
                    cur_i = &cur_i[consumed ..];

                    SCLogDebug!("INCOMPLETE have {}", cur_i.len());
                    self.tcp_buffer_tc.extend_from_slice(cur_i);
                    break;
                },
                Err(_) => {
                    self.set_event(SMBEvent::MalformedData);
                    return 1;
                },
            }
        };
        self.check_gap_resync(max_tx_id);
        self._debug_tx_stats();
        0
    }

    /// handle a gap in the TOSERVER direction
    /// returns: 0 ok, 1 unrecoverable error
    pub fn parse_tcp_data_ts_gap(&mut self, gap_size: u32) -> u32 {
        if self.tcp_buffer_ts.len() > 0 {
            self.tcp_buffer_ts.clear();
        }
        let consumed = self.handle_skip(STREAM_TOSERVER, gap_size);
        if consumed < gap_size {
            let new_gap_size = gap_size - consumed;
            let gap = vec![0; new_gap_size as usize];

            let consumed2 = self.filetracker_update(STREAM_TOSERVER, &gap, new_gap_size);
            if consumed2 > new_gap_size {
                SCLogDebug!("consumed more than GAP size: {} > {}", consumed2, new_gap_size);
                self.set_event(SMBEvent::InternalError);
                return 1;
            }
        }
        SCLogDebug!("GAP of size {} in toserver direction", gap_size);
        self.ts_ssn_gap = true;
        self.ts_gap = true;
        return 0
    }

    /// handle a gap in the TOCLIENT direction
    /// returns: 0 ok, 1 unrecoverable error
    pub fn parse_tcp_data_tc_gap(&mut self, gap_size: u32) -> u32 {
        if self.tcp_buffer_tc.len() > 0 {
            self.tcp_buffer_tc.clear();
        }
        let consumed = self.handle_skip(STREAM_TOCLIENT, gap_size);
        if consumed < gap_size {
            let new_gap_size = gap_size - consumed;
            let gap = vec![0; new_gap_size as usize];

            let consumed2 = self.filetracker_update(STREAM_TOCLIENT, &gap, new_gap_size);
            if consumed2 > new_gap_size {
                SCLogDebug!("consumed more than GAP size: {} > {}", consumed2, new_gap_size);
                self.set_event(SMBEvent::InternalError);
                return 1;
            }
        }
        SCLogDebug!("GAP of size {} in toclient direction", gap_size);
        self.tc_ssn_gap = true;
        self.tc_gap = true;
        return 0
    }

    pub fn trunc_ts(&mut self) {
        SCLogDebug!("TRUNC TS");
        self.ts_trunc = true;
        self.tcp_buffer_ts.clear();

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
        self.tcp_buffer_tc.clear();

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
pub extern "C" fn rs_smb_state_new() -> *mut std::os::raw::c_void {
    let state = SMBState::new();
    let boxed = Box::new(state);
    SCLogDebug!("allocating state");
    return unsafe{transmute(boxed)};
}

/// Params:
/// - state: *mut SMBState as void pointer
#[no_mangle]
pub extern "C" fn rs_smb_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    SCLogDebug!("freeing state");
    let mut smb_state: Box<SMBState> = unsafe{transmute(state)};
    smb_state.free();
}

/// C binding parse a SMB request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_smb_parse_request_tcp(_flow: *mut Flow,
                                       state: &mut SMBState,
                                       _pstate: *mut std::os::raw::c_void,
                                       input: *mut u8,
                                       input_len: u32,
                                       _data: *mut std::os::raw::c_void,
                                       flags: u8)
                                       -> i8
{
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    SCLogDebug!("parsing {} bytes of request data", input_len);

    /* START with MISTREAM set: record might be starting the middle. */
    if flags & (STREAM_START|STREAM_MIDSTREAM) == (STREAM_START|STREAM_MIDSTREAM) {
        state.ts_gap = true;
    }

    if state.parse_tcp_data_ts(buf) == 0 {
        return 1;
    } else {
        return -1;
    }
}

#[no_mangle]
pub extern "C" fn rs_smb_parse_request_tcp_gap(
                                        state: &mut SMBState,
                                        input_len: u32)
                                        -> i8
{
    if state.parse_tcp_data_ts_gap(input_len as u32) == 0 {
        return 1;
    }
    return -1;
}


#[no_mangle]
pub extern "C" fn rs_smb_parse_response_tcp(_flow: *mut Flow,
                                        state: &mut SMBState,
                                        _pstate: *mut std::os::raw::c_void,
                                        input: *mut u8,
                                        input_len: u32,
                                        _data: *mut std::os::raw::c_void,
                                        flags: u8)
                                        -> i8
{
    SCLogDebug!("parsing {} bytes of response data", input_len);
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};

    /* START with MISTREAM set: record might be starting the middle. */
    if flags & (STREAM_START|STREAM_MIDSTREAM) == (STREAM_START|STREAM_MIDSTREAM) {
        state.tc_gap = true;
    }

    if state.parse_tcp_data_tc(buf) == 0 {
        return 1;
    } else {
        return -1;
    }
}

#[no_mangle]
pub extern "C" fn rs_smb_parse_response_tcp_gap(
                                        state: &mut SMBState,
                                        input_len: u32)
                                        -> i8
{
    if state.parse_tcp_data_tc_gap(input_len as u32) == 0 {
        return 1;
    }
    return -1;
}

// probing parser
// return 1 if found, 0 is not found
#[no_mangle]
pub extern "C" fn rs_smb_probe_tcp(direction: u8,
        input: *const u8, len: u32,
        rdir: *mut u8)
    -> i8
{
    let slice = build_slice!(input, len as usize);
    match search_smb_record(slice) {
        Ok((_, ref data)) => {
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
                                    if direction & STREAM_TOSERVER != 0 {
                                        unsafe { *rdir = STREAM_TOCLIENT; }
                                    }
                                } else {
                                    SCLogDebug!("REQUEST {:02x}", smb_record.flags);
                                    if direction & STREAM_TOCLIENT != 0 {
                                        unsafe { *rdir = STREAM_TOSERVER; }
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
                                if direction & STREAM_TOSERVER != 0 {
                                    SCLogDebug!("direction STREAM_TOSERVER smb_record {:?}", smb_record);
                                    if !smb_record.request {
                                        unsafe { *rdir = STREAM_TOCLIENT; }
                                    }
                                } else {
                                    SCLogDebug!("direction STREAM_TOCLIENT smb_record {:?}", smb_record);
                                    if smb_record.request {
                                        unsafe { *rdir = STREAM_TOSERVER; }
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
    match parse_nbss_record_partial(slice) {
        Ok((_, ref hdr)) => {
            if hdr.is_smb() {
                SCLogDebug!("smb found");
                return 1;
            } else if hdr.is_valid() {
                SCLogDebug!("nbss found, assume smb");
                return 1;
            }
        },
        _ => { },
    }
    SCLogDebug!("no smb");
    return -1
}

#[no_mangle]
pub extern "C" fn rs_smb_state_get_tx_count(state: &mut SMBState)
                                            -> u64
{
    SCLogDebug!("rs_smb_state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_smb_state_get_tx(state: &mut SMBState,
                                      tx_id: u64)
                                      -> *mut SMBTransaction
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
pub extern "C" fn rs_smb_state_get_tx_iterator(
                                      state: &mut SMBState,
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
pub extern "C" fn rs_smb_state_tx_free(state: &mut SMBState,
                                       tx_id: u64)
{
    SCLogDebug!("freeing tx {}", tx_id as u64);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_smb_state_progress_completion_status(
    _direction: u8)
    -> std::os::raw::c_int
{
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_get_alstate_progress(tx: &mut SMBTransaction,
                                                  direction: u8)
                                                  -> u8
{
    if direction == STREAM_TOSERVER && tx.request_done {
        SCLogDebug!("tx {} TOSERVER progress 1 => {:?}", tx.id, tx);
        return 1;
    } else if direction == STREAM_TOCLIENT && tx.response_done {
        SCLogDebug!("tx {} TOCLIENT progress 1 => {:?}", tx.id, tx);
        return 1;
    } else {
        SCLogDebug!("tx {} direction {} progress 0", tx.id, direction);
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_set_logged(_state: &mut SMBState,
                                       tx: &mut SMBTransaction,
                                       bits: u32)
{
    tx.logged.set(bits);
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_get_logged(_state: &mut SMBState,
                                       tx: &mut SMBTransaction)
                                       -> u32
{
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_set_detect_flags(
                                       tx: &mut SMBTransaction,
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
pub extern "C" fn rs_smb_tx_get_detect_flags(
                                       tx: &mut SMBTransaction,
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
pub extern "C" fn rs_smb_state_set_tx_detect_state(
    tx: &mut SMBTransaction,
    de_state: &mut DetectEngineState)
{
    tx.de_state = Some(de_state);
}

#[no_mangle]
pub extern "C" fn rs_smb_state_get_tx_detect_state(
    tx: &mut SMBTransaction)
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
pub extern "C" fn rs_smb_state_truncate(
        state: &mut SMBState,
        direction: u8)
{
    if (direction & STREAM_TOSERVER) != 0 {
        state.trunc_ts();
    } else {
        state.trunc_tc();
    }
}

#[no_mangle]
pub extern "C" fn rs_smb_state_get_events(tx: *mut std::os::raw::c_void)
                                          -> *mut AppLayerDecoderEvents
{
    let tx = cast_pointer!(tx, SMBTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_smb_state_get_event_info_by_id(event_id: std::os::raw::c_int,
                                              event_name: *mut *const std::os::raw::c_char,
                                              event_type: *mut AppLayerEventType)
                                              -> i8
{
    if let Some(e) = SMBEvent::from_i32(event_id as i32) {
        let estr = match e {
            SMBEvent::InternalError => { "internal_error\0" },
            SMBEvent::MalformedData => { "malformed_data\0" },
            SMBEvent::RecordOverflow => { "record_overflow\0" },
            SMBEvent::MalformedNtlmsspRequest => { "malformed_ntlmssp_request\0" },
            SMBEvent::MalformedNtlmsspResponse => { "malformed_ntlmssp_response\0" },
            SMBEvent::DuplicateNegotiate => { "duplicate_negotiate\0" },
            SMBEvent::NegotiateMalformedDialects => { "netogiate_malformed_dialects\0" },
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
pub extern "C" fn rs_smb_state_get_event_info(event_name: *const std::os::raw::c_char,
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
            smb_str_to_event(s)
        },
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe {
        *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    if event == -1 {
        return -1;
    }
    0
}
