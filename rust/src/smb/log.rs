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

use crate::conf::ConfNode;
use crate::dcerpc::dcerpc::*;
use crate::dcerpc::load_interfaces::DCERPC_INTERFACE_MAP;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::smb::funcs::*;
use crate::smb::smb::*;
use crate::smb::smb1::*;
use crate::smb::smb2::*;
use crate::smb::smb_status::*;
use std::error::Error;
use std::fmt;
use std::str;
use std::string::String;
use suricata_sys::sys::SCConfNode;
use uuid;

const SMB_LOG_MAX_STRING: usize = 8 * 1024;
const SMB_LOG_MAX_ARRAY: usize = 64;
const SMB_LOG_MAX_BYTES: usize = 128 * 1024;

struct SmbLogBudget {
    remaining: usize,
    truncated: bool,
}

impl SmbLogBudget {
    fn new() -> Self {
        Self {
            remaining: SMB_LOG_MAX_BYTES,
            truncated: false,
        }
    }

    fn set(&mut self, js: &mut JsonBuilder, key: &str, val: &str) -> Result<(), JsonError> {
        let cost = val.len().min(SMB_LOG_MAX_STRING) + 24;
        if cost > self.remaining {
            self.truncated = true;
            return Ok(());
        }
        self.remaining -= cost;
        if val.len() > SMB_LOG_MAX_STRING {
            self.truncated = true;
            js.set_string_limited(key, val, SMB_LOG_MAX_STRING)?;
        } else {
            js.set_string(key, val)?;
        }
        Ok(())
    }

    fn append(&mut self, js: &mut JsonBuilder, val: &str) -> Result<(), JsonError> {
        let cost = val.len().min(SMB_LOG_MAX_STRING) + 8;
        if cost > self.remaining {
            self.truncated = true;
            return Ok(());
        }
        self.remaining -= cost;
        if val.len() > SMB_LOG_MAX_STRING {
            self.truncated = true;
        }
        js.append_string_limited(val, SMB_LOG_MAX_STRING)?;
        Ok(())
    }
}

#[cfg(not(feature = "debug"))]
fn debug_add_progress(_js: &mut JsonBuilder, _tx: &SMBTransaction) -> Result<(), JsonError> {
    Ok(())
}

#[cfg(feature = "debug")]
fn debug_add_progress(jsb: &mut JsonBuilder, tx: &SMBTransaction) -> Result<(), JsonError> {
    jsb.set_bool("request_done", tx.request_done)?;
    jsb.set_bool("response_done", tx.response_done)?;
    Ok(())
}

/// take in a file GUID (16 bytes) or FID (2 bytes). Also deal
/// with our frankenFID (2 bytes + 4 user_id)
fn fuid_to_string(fuid: &[u8]) -> String {
    let fuid_len = fuid.len();
    if fuid_len == 16 {
        guid_to_string(fuid)
    } else if fuid_len == 2 {
        format!("{:02x}{:02x}", fuid[1], fuid[0])
    } else if fuid_len == 6 {
        let pure_fid = &fuid[0..2];
        format!("{:02x}{:02x}", pure_fid[1], pure_fid[0])
    } else {
        "".to_string()
    }
}

fn guid_to_string(guid: &[u8]) -> String {
    if guid.len() == 16 {
        let output = format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                guid[3],  guid[2],  guid[1],  guid[0],
                guid[5],  guid[4],  guid[7],  guid[6],
                guid[9],  guid[8],  guid[11], guid[10],
                guid[15], guid[14], guid[13], guid[12]);
        output
    } else {
        "".to_string()
    }
}

// Wrapping error for either jsonbuilder error or our own custom error if
// tx is not to be logged due to config
#[derive(Debug)]
enum SmbLogError {
    SkippedByConf,
    Json(JsonError),
}

impl Error for SmbLogError {}

impl fmt::Display for SmbLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmbLogError::SkippedByConf => {
                write!(f, "skipped by configuration")
            }
            SmbLogError::Json(j) => j.fmt(f),
        }
    }
}

impl From<JsonError> for SmbLogError {
    fn from(err: JsonError) -> SmbLogError {
        SmbLogError::Json(err)
    }
}

fn smb_common_header(
    jsb: &mut JsonBuilder, state: &SMBState, tx: &SMBTransaction, flags: u64,
) -> Result<(), SmbLogError> {
    let mut budget = SmbLogBudget::new();
    jsb.set_uint("id", tx.id)?;

    if state.dialect != 0 {
        let dialect = &smb2_dialect_string(state.dialect);
        budget.set(jsb, "dialect", dialect)?;
    } else {
        let dialect = match state.dialect_vec {
            Some(ref d) => str::from_utf8(d).unwrap_or("invalid"),
            None => "unknown",
        };
        budget.set(jsb, "dialect", dialect)?;
    }

    match tx.vercmd.get_version() {
        1 => {
            let (ok, cmd) = tx.vercmd.get_smb1_cmd();
            if ok {
                jsb.set_string("command", &smb1_command_string(cmd))?;
            }
        }
        2 => {
            let (ok, cmd) = tx.vercmd.get_smb2_cmd();
            if ok {
                jsb.set_string("command", &smb2_command_string(cmd))?;
            }
        }
        _ => {}
    }

    match tx.vercmd.get_ntstatus() {
        (true, ntstatus) => {
            let status = smb_ntstatus_string(ntstatus);
            match status {
                Some(x) => jsb.set_string("status", x)?,
                None => {
                    let status_str = format!("{}", ntstatus);
                    jsb.set_string("status", &status_str)?
                }
            };
            let status_hex = format!("0x{:x}", ntstatus);
            jsb.set_string("status_code", &status_hex)?;
        }
        (false, _) => {
            #[allow(clippy::single_match)]
            match tx.vercmd.get_dos_error() {
                (true, errclass, errcode) => {
                    match errclass {
                        1 => {
                            // DOSERR
                            let status = smb_dos_error_string(errcode);
                            jsb.set_string("status", &status)?;
                        }
                        2 => {
                            // SRVERR
                            let status = smb_srv_error_string(errcode);
                            jsb.set_string("status", &status)?;
                        }
                        _ => {
                            let s = format!("UNKNOWN_{:02x}_{:04x}", errclass, errcode);
                            jsb.set_string("status", &s)?;
                        }
                    }
                    let status_hex = format!("0x{:04x}", errcode);
                    jsb.set_string("status_code", &status_hex)?;
                }
                (_, _, _) => {}
            }
        }
    }

    jsb.set_uint("session_id", tx.hdr.ssn_id)?;
    jsb.set_uint("tree_id", tx.hdr.tree_id as u64)?;

    debug_add_progress(jsb, tx)?;

    match tx.type_data {
        Some(SMBTransactionTypeData::SESSIONSETUP(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_SESSIONSETUP) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            if let Some(ref ntlmssp) = x.ntlmssp {
                jsb.open_object("ntlmssp")?;
                let domain = String::from_utf8_lossy(&ntlmssp.domain);
                budget.set(jsb, "domain", &domain)?;

                let user = String::from_utf8_lossy(&ntlmssp.user);
                budget.set(jsb, "user", &user)?;

                let host = String::from_utf8_lossy(&ntlmssp.host);
                budget.set(jsb, "host", &host)?;

                if let Some(ref v) = ntlmssp.version {
                    jsb.set_string("version", v.to_string().as_str())?;
                }

                jsb.close()?;
            }

            if let Some(ref ticket) = x.krb_ticket {
                jsb.open_object("kerberos")?;
                budget.set(jsb, "realm", &ticket.realm.0)?;
                jsb.open_array("snames")?;
                let truncated = ticket.sname.name_string.len() > SMB_LOG_MAX_ARRAY;
                for sname in ticket.sname.name_string.iter().take(SMB_LOG_MAX_ARRAY) {
                    budget.append(jsb, sname)?;
                }
                jsb.close()?;
                if truncated {
                    jsb.set_bool("snames_truncated", true)?;
                    budget.truncated = true;
                }
                jsb.close()?;
            }

            if let Some(ref r) = x.request_host {
                jsb.open_object("request")?;
                let os = String::from_utf8_lossy(&r.native_os);
                budget.set(jsb, "native_os", &os)?;
                let lm = String::from_utf8_lossy(&r.native_lm);
                budget.set(jsb, "native_lm", &lm)?;
                jsb.close()?;
            }
            if let Some(ref r) = x.response_host {
                jsb.open_object("response")?;
                let os = String::from_utf8_lossy(&r.native_os);
                budget.set(jsb, "native_os", &os)?;
                let lm = String::from_utf8_lossy(&r.native_lm);
                budget.set(jsb, "native_lm", &lm)?;
                jsb.close()?;
            }
        }
        Some(SMBTransactionTypeData::CREATE(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_CREATE) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            let mut name_raw = x.filename.to_vec();
            name_raw.retain(|&i| i != 0x00);
            if !name_raw.is_empty() {
                let name = String::from_utf8_lossy(&name_raw);
                if x.directory {
                    budget.set(jsb, "directory", &name)?;
                } else {
                    budget.set(jsb, "filename", &name)?;
                }
            } else {
                // name suggestion from Bro
                jsb.set_string("filename", "<share_root>")?;
            }
            match x.disposition {
                0 => {
                    jsb.set_string("disposition", "FILE_SUPERSEDE")?;
                }
                1 => {
                    jsb.set_string("disposition", "FILE_OPEN")?;
                }
                2 => {
                    jsb.set_string("disposition", "FILE_CREATE")?;
                }
                3 => {
                    jsb.set_string("disposition", "FILE_OPEN_IF")?;
                }
                4 => {
                    jsb.set_string("disposition", "FILE_OVERWRITE")?;
                }
                5 => {
                    jsb.set_string("disposition", "FILE_OVERWRITE_IF")?;
                }
                _ => {
                    jsb.set_string("disposition", "UNKNOWN")?;
                }
            }
            if x.delete_on_close {
                jsb.set_string("access", "delete on close")?;
            } else {
                jsb.set_string("access", "normal")?;
            }

            // field names inspired by Bro
            jsb.set_uint("created", x.create_ts as u64)?;
            jsb.set_uint("accessed", x.last_access_ts as u64)?;
            jsb.set_uint("modified", x.last_write_ts as u64)?;
            jsb.set_uint("changed", x.last_change_ts as u64)?;
            jsb.set_uint("size", x.size)?;

            let gs = fuid_to_string(&x.guid);
            jsb.set_string("fuid", &gs)?;
        }
        Some(SMBTransactionTypeData::NEGOTIATE(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_NEGOTIATE) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            if x.smb_ver == 1 {
                jsb.open_array("client_dialects")?;
                let truncated = x.dialects.len() > SMB_LOG_MAX_ARRAY;
                for d in x.dialects.iter().take(SMB_LOG_MAX_ARRAY) {
                    let dialect = String::from_utf8_lossy(d);
                    budget.append(jsb, &dialect)?;
                }
                jsb.close()?;
                if truncated {
                    jsb.set_bool("client_dialects_truncated", true)?;
                    budget.truncated = true;
                }
            } else if x.smb_ver == 2 {
                jsb.open_array("client_dialects")?;
                let truncated = x.dialects2.len() > SMB_LOG_MAX_ARRAY;
                for d in x.dialects2.iter().take(SMB_LOG_MAX_ARRAY) {
                    let dialect = String::from_utf8_lossy(d);
                    budget.append(jsb, &dialect)?;
                }
                jsb.close()?;
                if truncated {
                    jsb.set_bool("client_dialects_truncated", true)?;
                    budget.truncated = true;
                }
            }

            if let Some(ref g) = x.client_guid {
                jsb.set_string("client_guid", &guid_to_string(g))?;
            }

            jsb.set_string("server_guid", &guid_to_string(&x.server_guid))?;

            if state.max_read_size > 0 {
                jsb.set_uint("max_read_size", state.max_read_size)?;
            }
            if state.max_write_size > 0 {
                jsb.set_uint("max_write_size", state.max_write_size)?;
            }
        }
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_TREECONNECT) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            let share_name = String::from_utf8_lossy(&x.share_name);
            if x.is_pipe {
                budget.set(jsb, "named_pipe", &share_name)?;
            } else {
                budget.set(jsb, "share", &share_name)?;
            }

            // handle services
            if tx.vercmd.get_version() == 1 {
                jsb.open_object("service")?;

                if let Some(ref s) = x.req_service {
                    let serv = String::from_utf8_lossy(s);
                    budget.set(jsb, "request", &serv)?;
                }
                if let Some(ref s) = x.res_service {
                    let serv = String::from_utf8_lossy(s);
                    budget.set(jsb, "response", &serv)?;
                }
                jsb.close()?;

            // share type only for SMB2
            } else {
                match x.share_type {
                    1 => {
                        jsb.set_string("share_type", "FILE")?;
                    }
                    2 => {
                        jsb.set_string("share_type", "PIPE")?;
                    }
                    3 => {
                        jsb.set_string("share_type", "PRINT")?;
                    }
                    _ => {
                        jsb.set_string("share_type", "UNKNOWN")?;
                    }
                }
            }
        }
        Some(SMBTransactionTypeData::FILE(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_FILE) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            let file_name = String::from_utf8_lossy(&x.file_name);
            budget.set(jsb, "filename", &file_name)?;
            let share_name = String::from_utf8_lossy(&x.share_name);
            budget.set(jsb, "share", &share_name)?;
            let gs = fuid_to_string(&x.fuid);
            jsb.set_string("fuid", &gs)?;
        }
        Some(SMBTransactionTypeData::RENAME(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_RENAME) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            if tx.vercmd.get_version() == 2 {
                jsb.open_object("set_info")?;
                jsb.set_string("class", "FILE_INFO")?;
                jsb.set_string("info_level", "SMB2_FILE_RENAME_INFO")?;
                jsb.close()?;
            }

            jsb.open_object("rename")?;
            let file_name = String::from_utf8_lossy(&x.oldname);
            budget.set(jsb, "from", &file_name)?;
            let file_name = String::from_utf8_lossy(&x.newname);
            budget.set(jsb, "to", &file_name)?;
            jsb.close()?;
            let gs = fuid_to_string(&x.fuid);
            jsb.set_string("fuid", &gs)?;
        }
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_DCERPC) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            jsb.open_object("dcerpc")?;
            if x.req_set {
                budget.set(jsb, "request", &dcerpc_type_string(x.req_cmd))?;
            } else {
                jsb.set_string("request", "REQUEST_LOST")?;
            }
            if x.res_set {
                budget.set(jsb, "response", &dcerpc_type_string(x.res_cmd))?;
            } else {
                jsb.set_string("response", "UNREPLIED")?;
            }
            if x.req_set {
                match x.req_cmd {
                    DCERPC_TYPE_REQUEST => {
                        jsb.set_uint("opnum", x.opnum as u64)?;
                        jsb.open_object("req")?;
                        jsb.set_uint("frag_cnt", x.frag_cnt_ts as u64)?;
                        jsb.set_uint("stub_data_size", x.stub_data_ts.len() as u64)?;
                        jsb.close()?;
                        if let Some(ref ifaces) = state.dcerpc_ifaces {
                            // First filter the interfaces to those
                            // with the context_id we want to log to
                            // avoid creating an empty "interfaces"
                            // array.
                            let mut ifaces = ifaces
                                .iter()
                                .filter(|i| i.context_id == x.context_id)
                                .peekable();
                            if ifaces.peek().is_some() {
                                jsb.open_array("interfaces")?;
                                for i in ifaces {
                                    jsb.start_object()?;
                                    let ifuuid = uuid::Uuid::from_slice(&i.uuid);
                                    let ifstr = ifuuid
                                        .as_ref()
                                        .map(|ifuuid| ifuuid.to_hyphenated().to_string())
                                        .unwrap();
                                    budget.set(jsb, "uuid", &ifstr)?;
                                    let vstr = format!("{}.{}", i.ver, i.ver_min);
                                    budget.set(jsb, "version", &vstr)?;
                                    if let Some(iface) = DCERPC_INTERFACE_MAP.get(&ifuuid.unwrap())
                                    {
                                        budget.set(jsb, "service", &iface.service)?;
                                        if let Some(pname) = iface.opcodes.get(&x.opnum) {
                                            budget.set(jsb, "procedure", pname)?;
                                        }
                                    }
                                    jsb.close()?;
                                }
                                jsb.close()?;
                            }
                        }
                    }
                    DCERPC_TYPE_BIND => {
                        if let Some(ref ifaces) = state.dcerpc_ifaces {
                            jsb.open_array("interfaces")?;
                            for i in ifaces {
                                jsb.start_object()?;
                                let ifuuid = uuid::Uuid::from_slice(&i.uuid);
                                let ifstr = ifuuid
                                    .as_ref()
                                    .map(|ifuuid| ifuuid.to_hyphenated().to_string())
                                    .unwrap();
                                budget.set(jsb, "uuid", &ifstr)?;
                                let vstr = format!("{}.{}", i.ver, i.ver_min);
                                budget.set(jsb, "version", &vstr)?;

                                if i.acked {
                                    jsb.set_uint("ack_result", i.ack_result as u64)?;
                                    jsb.set_uint("ack_reason", i.ack_reason as u64)?;
                                }
                                if let Some(iface) = DCERPC_INTERFACE_MAP.get(&ifuuid.unwrap()) {
                                    budget.set(jsb, "service", &iface.service)?;
                                }
                                jsb.close()?;
                            }
                            jsb.close()?;
                        }
                    }
                    _ => {}
                }
            }
            if x.res_set {
                #[allow(clippy::single_match)]
                match x.res_cmd {
                    DCERPC_TYPE_RESPONSE => {
                        jsb.open_object("res")?;
                        jsb.set_uint("frag_cnt", x.frag_cnt_tc as u64)?;
                        jsb.set_uint("stub_data_size", x.stub_data_tc.len() as u64)?;
                        jsb.close()?;
                    }
                    // we don't handle BINDACK w/o BIND
                    _ => {}
                }
            }
            jsb.set_uint("call_id", x.call_id as u64)?;
            jsb.close()?;
        }
        Some(SMBTransactionTypeData::IOCTL(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_IOCTL) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            budget.set(jsb, "function", &fsctl_func_to_string(x.func))?;
        }
        Some(SMBTransactionTypeData::SETFILEPATHINFO(ref x)) => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_SETFILEPATHINFO) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
            let mut name_raw = x.filename.to_vec();
            name_raw.retain(|&i| i != 0x00);
            if !name_raw.is_empty() {
                let name = String::from_utf8_lossy(&name_raw);
                budget.set(jsb, "filename", &name)?;
            } else {
                // name suggestion from Bro
                jsb.set_string("filename", "<share_root>")?;
            }
            if x.delete_on_close {
                jsb.set_string("access", "delete on close")?;
            } else {
                jsb.set_string("access", "normal")?;
            }

            match x.subcmd {
                8 => {
                    jsb.set_string("subcmd", "SET_FILE_INFO")?;
                }
                6 => {
                    jsb.set_string("subcmd", "SET_PATH_INFO")?;
                }
                _ => {}
            }

            #[allow(clippy::single_match)]
            match x.loi {
                1013 => {
                    // Set Disposition Information
                    jsb.set_string("level_of_interest", "Set Disposition Information")?;
                }
                _ => {}
            }

            let gs = fuid_to_string(&x.fid);
            jsb.set_string("fuid", &gs)?;
        }
        None => {
            if flags != SMB_LOG_DEFAULT_ALL && (flags & SMB_LOG_TYPE_GENERIC) == 0 {
                return Err(SmbLogError::SkippedByConf);
            }
        }
    }
    if budget.truncated {
        jsb.set_bool("truncated", true)?;
    }
    return Ok(());
}

#[no_mangle]
pub extern "C" fn SCSmbLogJsonResponse(
    jsb: &mut JsonBuilder, state: &mut SMBState, tx: &SMBTransaction, flags: u64,
) -> bool {
    smb_common_header(jsb, state, tx, flags).is_ok()
}

// Flag constants for logging types
const SMB_LOG_TYPE_FILE: u64 = BIT_U64!(0);
const SMB_LOG_TYPE_TREECONNECT: u64 = BIT_U64!(1);
const SMB_LOG_TYPE_NEGOTIATE: u64 = BIT_U64!(2);
const SMB_LOG_TYPE_DCERPC: u64 = BIT_U64!(3);
const SMB_LOG_TYPE_CREATE: u64 = BIT_U64!(4);
const SMB_LOG_TYPE_SESSIONSETUP: u64 = BIT_U64!(5);
const SMB_LOG_TYPE_IOCTL: u64 = BIT_U64!(6);
const SMB_LOG_TYPE_RENAME: u64 = BIT_U64!(7);
const SMB_LOG_TYPE_SETFILEPATHINFO: u64 = BIT_U64!(8);
const SMB_LOG_TYPE_GENERIC: u64 = BIT_U64!(9);
const SMB_LOG_DEFAULT_ALL: u64 = 0;

fn get_smb_log_type_from_str(s: &str) -> Option<u64> {
    match s {
        "file" => Some(SMB_LOG_TYPE_FILE),
        "tree_connect" => Some(SMB_LOG_TYPE_TREECONNECT),
        "negotiate" => Some(SMB_LOG_TYPE_NEGOTIATE),
        "dcerpc" => Some(SMB_LOG_TYPE_DCERPC),
        "create" => Some(SMB_LOG_TYPE_CREATE),
        "session_setup" => Some(SMB_LOG_TYPE_SESSIONSETUP),
        "ioctl" => Some(SMB_LOG_TYPE_IOCTL),
        "rename" => Some(SMB_LOG_TYPE_RENAME),
        "set_file_path_info" => Some(SMB_LOG_TYPE_SETFILEPATHINFO),
        "generic" => Some(SMB_LOG_TYPE_GENERIC),
        _ => None,
    }
}

#[no_mangle]
pub extern "C" fn SCSmbLogParseConfig(conf: *const SCConfNode) -> u64 {
    let conf = ConfNode::wrap(conf);
    if let Some(node) = conf.get_child_node("types") {
        // iterate smb.types list of types
        let mut r = SMB_LOG_DEFAULT_ALL;
        let mut node = node.first();
        loop {
            if node.is_none() {
                break;
            }
            let nodeu = node.unwrap();
            if let Some(f) = get_smb_log_type_from_str(nodeu.value()) {
                r |= f;
            } else {
                SCLogWarning!("unknown type for smb logging: {}", nodeu.value());
            }
            node = nodeu.next();
        }
        if r == SMB_LOG_DEFAULT_ALL {
            SCLogWarning!("empty types list for smb is interpreted as logging all");
        }
        return r;
    }
    return SMB_LOG_DEFAULT_ALL;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_log_budget() {
        let mut budget = SmbLogBudget::new();
        let mut jb = JsonBuilder::try_new_object().unwrap();
        let long = "x".repeat(SMB_LOG_MAX_STRING + 10);
        budget.set(&mut jb, "filename", &long).unwrap();
        let s = jb.as_str();
        assert!(s.contains("[truncated 10 additional bytes]"), "{s}");
        assert!(budget.truncated);
    }

    #[test]
    fn test_smb_log_budget_append_multibyte() {
        let mut budget = SmbLogBudget::new();
        let mut jb = JsonBuilder::try_new_array().unwrap();
        let mut val = "x".repeat(SMB_LOG_MAX_STRING - 1);
        val.push('é');
        val.push_str("tail");
        budget.append(&mut jb, &val).unwrap();
        let s = jb.as_str();
        assert!(s.contains("[truncated"), "{s}");
        assert!(budget.truncated);
    }
}
