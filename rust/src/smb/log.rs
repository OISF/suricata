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

use std::str;
use std::string::String;
use uuid;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::smb::smb::*;
use crate::smb::smb1::*;
use crate::smb::smb2::*;
use crate::dcerpc::dcerpc::*;
use crate::smb::funcs::*;
use crate::smb::smb_status::*;

#[cfg(not(feature = "debug"))]
fn debug_add_progress(_js: &mut JsonBuilder, _tx: &SMBTransaction) -> Result<(), JsonError> { Ok(()) }

#[cfg(feature = "debug")]
fn debug_add_progress(jsb: &mut JsonBuilder, tx: &SMBTransaction) -> Result<(), JsonError> {
    jsb.set_bool("request_done", tx.request_done)?;
    jsb.set_bool("response_done", tx.response_done)?;
    Ok(())
}

/// take in a file GUID (16 bytes) or FID (2 bytes). Also deal
/// with our frankenFID (2 bytes + 4 user_id)
fn fuid_to_string(fuid: &Vec<u8>) -> String {
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

fn guid_to_string(guid: &Vec<u8>) -> String {
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

fn smb_common_header(jsb: &mut JsonBuilder, state: &SMBState, tx: &SMBTransaction) -> Result<(), JsonError>
{
    jsb.set_uint("id", tx.id as u64)?;

    if state.dialect != 0 {
        let dialect = &smb2_dialect_string(state.dialect);
        jsb.set_string("dialect", dialect)?;
    } else {
        let dialect = match &state.dialect_vec {
            &Some(ref d) => str::from_utf8(d).unwrap_or("invalid"),
            &None        => "unknown",
        };
        jsb.set_string("dialect", dialect)?;
    }

    match tx.vercmd.get_version() {
        1 => {
            let (ok, cmd) = tx.vercmd.get_smb1_cmd();
            if ok {
                jsb.set_string("command", &smb1_command_string(cmd))?;
            }
        },
        2 => {
            let (ok, cmd) = tx.vercmd.get_smb2_cmd();
            if ok {
                jsb.set_string("command", &smb2_command_string(cmd))?;
            }
        },
        _ => { },
    }

    match tx.vercmd.get_ntstatus() {
        (true, ntstatus) => {
            let status = smb_ntstatus_string(ntstatus);
            match status {
                Some(x) => jsb.set_string("status", &x)?,
                None => {
                    let status_str = format!("{}", ntstatus);
                    jsb.set_string("status", &status_str)?
                },
            };
            let status_hex = format!("0x{:x}", ntstatus);
            jsb.set_string("status_code", &status_hex)?;
        },
        (false, _) => {
            match tx.vercmd.get_dos_error() {
                (true, errclass, errcode) => {
                    match errclass {
                        1 => { // DOSERR
                            let status = smb_dos_error_string(errcode);
                            jsb.set_string("status", &status)?;
                        },
                        2 => { // SRVERR
                            let status = smb_srv_error_string(errcode);
                            jsb.set_string("status", &status)?;
                        }
                        _ => {
                            let s = format!("UNKNOWN_{:02x}_{:04x}", errclass, errcode);
                            jsb.set_string("status", &s)?;
                        },
                    }
                    let status_hex = format!("0x{:04x}", errcode);
                    jsb.set_string("status_code", &status_hex)?;
                },
                (_, _, _) => {
                },
            }
        },
    }


    jsb.set_uint("session_id", tx.hdr.ssn_id as u64)?;
    jsb.set_uint("tree_id", tx.hdr.tree_id as u64)?;

    debug_add_progress(jsb, tx)?;

    match tx.type_data {
        Some(SMBTransactionTypeData::SESSIONSETUP(ref x)) => {
            if let Some(ref ntlmssp) = x.ntlmssp {
                jsb.open_object("ntlmssp")?;
                let domain = String::from_utf8_lossy(&ntlmssp.domain);
                jsb.set_string("domain", &domain)?;

                let user = String::from_utf8_lossy(&ntlmssp.user);
                jsb.set_string("user", &user)?;

                let host = String::from_utf8_lossy(&ntlmssp.host);
                jsb.set_string("host", &host)?;

                if let Some(ref v) = ntlmssp.version {
                    jsb.set_string("version", v.to_string().as_str())?;
                }

                jsb.close()?;
            }

            if let Some(ref ticket) = x.krb_ticket {
                jsb.open_object("kerberos")?;
                jsb.set_string("realm", &ticket.realm.0)?;
                jsb.open_array("snames")?;
                for sname in ticket.sname.name_string.iter() {
                    jsb.append_string(sname)?;
                }
                jsb.close()?;
                jsb.close()?;
            }

            match x.request_host {
                Some(ref r) => {
                    jsb.open_object("request")?;
                    let os = String::from_utf8_lossy(&r.native_os);
                    jsb.set_string("native_os", &os)?;
                    let lm = String::from_utf8_lossy(&r.native_lm);
                    jsb.set_string("native_lm", &lm)?;
                    jsb.close()?;
                },
                None => { },
            }
            match x.response_host {
                Some(ref r) => {
                    jsb.open_object("response")?;
                    let os = String::from_utf8_lossy(&r.native_os);
                    jsb.set_string("native_os", &os)?;
                    let lm = String::from_utf8_lossy(&r.native_lm);
                    jsb.set_string("native_lm", &lm)?;
                    jsb.close()?;
                },
                None => { },
            }
        },
        Some(SMBTransactionTypeData::CREATE(ref x)) => {
            let mut name_raw = x.filename.to_vec();
            name_raw.retain(|&i|i != 0x00);
            if name_raw.len() > 0 {
                let name = String::from_utf8_lossy(&name_raw);
                if x.directory {
                    jsb.set_string("directory", &name)?;
                } else {
                    jsb.set_string("filename", &name)?;
                }
            } else {
                // name suggestion from Bro
                jsb.set_string("filename", "<share_root>")?;
            }
            match x.disposition {
                0 => { jsb.set_string("disposition", "FILE_SUPERSEDE")?; },
                1 => { jsb.set_string("disposition", "FILE_OPEN")?; },
                2 => { jsb.set_string("disposition", "FILE_CREATE")?; },
                3 => { jsb.set_string("disposition", "FILE_OPEN_IF")?; },
                4 => { jsb.set_string("disposition", "FILE_OVERWRITE")?; },
                5 => { jsb.set_string("disposition", "FILE_OVERWRITE_IF")?; },
                _ => { jsb.set_string("disposition", "UNKNOWN")?; },
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
        },
        Some(SMBTransactionTypeData::NEGOTIATE(ref x)) => {
            if x.smb_ver == 1 {
                jsb.open_array("client_dialects")?;
                for d in &x.dialects {
                    let dialect = String::from_utf8_lossy(d);
                    jsb.append_string(&dialect)?;
                }
                jsb.close()?;
            } else if x.smb_ver == 2 {
                jsb.open_array("client_dialects")?;
                for d in &x.dialects2 {
                    let dialect = String::from_utf8_lossy(d);
                    jsb.append_string(&dialect)?;
                }
                jsb.close()?;
            }

            if let Some(ref g) = x.client_guid {
                jsb.set_string("client_guid", &guid_to_string(g))?;
            }

            jsb.set_string("server_guid", &guid_to_string(&x.server_guid))?;

            if state.max_read_size > 0 {
                jsb.set_uint("max_read_size", state.max_read_size.into())?;
            }
            if state.max_write_size > 0 {
                jsb.set_uint("max_write_size", state.max_write_size.into())?;
            }
        },
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            jsb.set_uint("tree_id", x.tree_id as u64)?;

            let share_name = String::from_utf8_lossy(&x.share_name);
            if x.is_pipe {
                jsb.set_string("named_pipe", &share_name)?;
            } else {
                jsb.set_string("share", &share_name)?;
            }

            // handle services
            if tx.vercmd.get_version() == 1 {
                jsb.open_object("service")?;

                if let Some(ref s) = x.req_service {
                    let serv = String::from_utf8_lossy(s);
                    jsb.set_string("request", &serv)?;
                }
                if let Some(ref s) = x.res_service {
                    let serv = String::from_utf8_lossy(s);
                    jsb.set_string("response", &serv)?;
                }
                jsb.close()?;

            // share type only for SMB2
            } else {
                match x.share_type {
                    1 => { jsb.set_string("share_type", "FILE")?; },
                    2 => { jsb.set_string("share_type", "PIPE")?; },
                    3 => { jsb.set_string("share_type", "PRINT")?; },
                    _ => { jsb.set_string("share_type", "UNKNOWN")?; },
                }
            }
        },
        Some(SMBTransactionTypeData::FILE(ref x)) => {
            let file_name = String::from_utf8_lossy(&x.file_name);
            jsb.set_string("filename", &file_name)?;
            let share_name = String::from_utf8_lossy(&x.share_name);
            jsb.set_string("share", &share_name)?;
            let gs = fuid_to_string(&x.fuid);
            jsb.set_string("fuid", &gs)?;
        },
        Some(SMBTransactionTypeData::RENAME(ref x)) => {
            if tx.vercmd.get_version() == 2 {
                jsb.open_object("set_info")?;
                jsb.set_string("class", "FILE_INFO")?;
                jsb.set_string("info_level", "SMB2_FILE_RENAME_INFO")?;
                jsb.close()?;
            }

            jsb.open_object("rename")?;
            let file_name = String::from_utf8_lossy(&x.oldname);
            jsb.set_string("from", &file_name)?;
            let file_name = String::from_utf8_lossy(&x.newname);
            jsb.set_string("to", &file_name)?;
            jsb.close()?;
            let gs = fuid_to_string(&x.fuid);
            jsb.set_string("fuid", &gs)?;
        },
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            jsb.open_object("dcerpc")?;
            if x.req_set {
                jsb.set_string("request", &dcerpc_type_string(x.req_cmd))?;
            } else {
                jsb.set_string("request", "REQUEST_LOST")?;
            }
            if x.res_set {
                jsb.set_string("response", &dcerpc_type_string(x.res_cmd))?;
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
                        match state.dcerpc_ifaces {
                            Some(ref ifaces) => {
                                for i in ifaces {
                                    if i.context_id == x.context_id {
                                        jsb.open_object("interface")?;
                                        let ifstr = uuid::Uuid::from_slice(&i.uuid);
                                        let ifstr = ifstr.map(|ifstr| ifstr.to_hyphenated().to_string()).unwrap();
                                        jsb.set_string("uuid", &ifstr)?;
                                        let vstr = format!("{}.{}", i.ver, i.ver_min);
                                        jsb.set_string("version", &vstr)?;
                                        jsb.close()?;
                                    }
                                }
                            },
                            _ => {},
                        }
                    },
                    DCERPC_TYPE_BIND => {
                        match state.dcerpc_ifaces {
                            Some(ref ifaces) => {
                                jsb.open_array("interfaces")?;
                                for i in ifaces {
                                    jsb.start_object()?;
                                    let ifstr = uuid::Uuid::from_slice(&i.uuid);
                                    let ifstr = ifstr.map(|ifstr| ifstr.to_hyphenated().to_string()).unwrap();
                                    jsb.set_string("uuid", &ifstr)?;
                                    let vstr = format!("{}.{}", i.ver, i.ver_min);
                                    jsb.set_string("version", &vstr)?;

                                    if i.acked {
                                        jsb.set_uint("ack_result", i.ack_result as u64)?;
                                        jsb.set_uint("ack_reason", i.ack_reason as u64)?;
                                    }
                                    jsb.close()?;
                                }
                                jsb.close()?;
                            },
                            _ => {},
                        }
                    },
                    _ => {},
                }
            }
            if x.res_set {
                match x.res_cmd {
                    DCERPC_TYPE_RESPONSE => {
                        jsb.open_object("res")?;
                        jsb.set_uint("frag_cnt", x.frag_cnt_tc as u64)?;
                        jsb.set_uint("stub_data_size", x.stub_data_tc.len() as u64)?;
                        jsb.close()?;
                    },
                    // we don't handle BINDACK w/o BIND
                    _ => {},
                }
            }
            jsb.set_uint("call_id", x.call_id as u64)?;
            jsb.close()?;
        }
        Some(SMBTransactionTypeData::IOCTL(ref x)) => {
            jsb.set_string("function", &fsctl_func_to_string(x.func))?;
        },
        Some(SMBTransactionTypeData::SETFILEPATHINFO(ref x)) => {
            let mut name_raw = x.filename.to_vec();
            name_raw.retain(|&i|i != 0x00);
            if name_raw.len() > 0 {
                let name = String::from_utf8_lossy(&name_raw);
                jsb.set_string("filename", &name)?;
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
                },
                6 => {
                    jsb.set_string("subcmd", "SET_PATH_INFO")?;
                },
                _ => { },
            }

            match x.loi {
                1013 => { // Set Disposition Information
                    jsb.set_string("level_of_interest", "Set Disposition Information")?;
                },
                _ => { },
            }

            let gs = fuid_to_string(&x.fid);
            jsb.set_string("fuid", &gs)?;
        },
        _ => {  },
    }
    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_smb_log_json_request(mut jsb: &mut JsonBuilder, state: &mut SMBState, tx: &mut SMBTransaction) -> bool
{
    smb_common_header(&mut jsb, state, tx).is_ok()
}

#[no_mangle]
pub extern "C" fn rs_smb_log_json_response(mut jsb: &mut JsonBuilder, state: &mut SMBState, tx: &mut SMBTransaction) -> bool
{
    smb_common_header(&mut jsb, state, tx).is_ok()
}

