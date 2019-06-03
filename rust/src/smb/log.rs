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
use json::*;
use smb::smb::*;
use smb::smb1::*;
use smb::smb2::*;
use smb::dcerpc::*;
use smb::funcs::*;

#[cfg(not(feature = "debug"))]
fn debug_add_progress(_js: &Json, _tx: &SMBTransaction) { }

#[cfg(feature = "debug")]
fn debug_add_progress(js: &Json, tx: &SMBTransaction) {
    js.set_boolean("request_done", tx.request_done);
    js.set_boolean("response_done", tx.request_done);
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

fn smb_common_header(state: &SMBState, tx: &SMBTransaction) -> Json
{
    let js = Json::object();
    js.set_integer("id", tx.id as u64);

    if state.dialect != 0 {
        let dialect = &smb2_dialect_string(state.dialect);
        js.set_string("dialect", &dialect);
    } else {
        let dialect = match &state.dialect_vec {
            &Some(ref d) => str::from_utf8(&d).unwrap_or("invalid"),
            &None        => "unknown",
        };
        js.set_string("dialect", &dialect);
    }

    match tx.vercmd.get_version() {
        1 => {
            let (ok, cmd) = tx.vercmd.get_smb1_cmd();
            if ok {
                js.set_string("command", &smb1_command_string(cmd));
            }
        },
        2 => {
            let (ok, cmd) = tx.vercmd.get_smb2_cmd();
            if ok {
                js.set_string("command", &smb2_command_string(cmd));
            }
        },
        _ => { },
    }

    match tx.vercmd.get_ntstatus() {
        (true, ntstatus) => {
            let status = smb_ntstatus_string(ntstatus);
            js.set_string("status", &status);
            let status_hex = format!("0x{:x}", ntstatus);
            js.set_string("status_code", &status_hex);
        },
        (false, _) => {
            match tx.vercmd.get_dos_error() {
                (true, errclass, errcode) => {
                    match errclass {
                        1 => { // DOSERR
                            let status = smb_dos_error_string(errcode);
                            js.set_string("status", &status);
                        },
                        2 => { // SRVERR
                            let status = smb_srv_error_string(errcode);
                            js.set_string("status", &status);
                        }
                        _ => {
                            let s = format!("UNKNOWN_{:02x}_{:04x}", errclass, errcode);
                            js.set_string("status", &s);
                        },
                    }
                    let status_hex = format!("0x{:04x}", errcode);
                    js.set_string("status_code", &status_hex);
                },
                (_, _, _) => {
                },
            }
        },
    }


    js.set_integer("session_id", tx.hdr.ssn_id);
    js.set_integer("tree_id", tx.hdr.tree_id as u64);

    debug_add_progress(&js, tx);

    match tx.type_data {
        Some(SMBTransactionTypeData::SESSIONSETUP(ref x)) => {
            if let Some(ref ntlmssp) = x.ntlmssp {
                let jsd = Json::object();
                let domain = String::from_utf8_lossy(&ntlmssp.domain);
                jsd.set_string("domain", &domain);

                let user = String::from_utf8_lossy(&ntlmssp.user);
                jsd.set_string("user", &user);

                let host = String::from_utf8_lossy(&ntlmssp.host);
                jsd.set_string("host", &host);

                if let Some(ref v) = ntlmssp.version {
                    jsd.set_string("version", v.to_string().as_str());
                }

                js.set("ntlmssp", jsd);
            }

            if let Some(ref ticket) = x.krb_ticket {
                let jsd = Json::object();
                jsd.set_string("realm", &ticket.realm.0);
                let jsa = Json::array();
                for sname in ticket.sname.name_string.iter() {
                    jsa.array_append_string(&sname);
                }
                jsd.set("snames", jsa);
                js.set("kerberos", jsd);
            }

            match x.request_host {
                Some(ref r) => {
                    let jsd = Json::object();
                    let os = String::from_utf8_lossy(&r.native_os);
                    jsd.set_string("native_os", &os);
                    let lm = String::from_utf8_lossy(&r.native_lm);
                    jsd.set_string("native_lm", &lm);
                    js.set("request", jsd);
                },
                None => { },
            }
            match x.response_host {
                Some(ref r) => {
                    let jsd = Json::object();
                    let os = String::from_utf8_lossy(&r.native_os);
                    jsd.set_string("native_os", &os);
                    let lm = String::from_utf8_lossy(&r.native_lm);
                    jsd.set_string("native_lm", &lm);
                    js.set("response", jsd);
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
                    js.set_string("directory", &name);
                } else {
                    js.set_string("filename", &name);
                }
            } else {
                // name suggestion from Bro
                js.set_string("filename", "<share_root>");
            }
            match x.disposition {
                0 => { js.set_string("disposition", "FILE_SUPERSEDE"); },
                1 => { js.set_string("disposition", "FILE_OPEN"); },
                2 => { js.set_string("disposition", "FILE_CREATE"); },
                3 => { js.set_string("disposition", "FILE_OPEN_IF"); },
                4 => { js.set_string("disposition", "FILE_OVERWRITE"); },
                5 => { js.set_string("disposition", "FILE_OVERWRITE_IF"); },
                _ => { js.set_string("disposition", "UNKNOWN"); },
            }
            if x.delete_on_close {
                js.set_string("access", "delete on close");
            } else {
                js.set_string("access", "normal");
            }

            // field names inspired by Bro
            js.set_integer("created", x.create_ts as u64);
            js.set_integer("accessed", x.last_access_ts as u64);
            js.set_integer("modified", x.last_write_ts as u64);
            js.set_integer("changed", x.last_change_ts as u64);
            js.set_integer("size", x.size);

            let gs = fuid_to_string(&x.guid);
            js.set_string("fuid", &gs);
        },
        Some(SMBTransactionTypeData::NEGOTIATE(ref x)) => {
            if x.smb_ver == 1 {
                let jsa = Json::array();
                for d in &x.dialects {
                    let dialect = String::from_utf8_lossy(&d);
                    jsa.array_append_string(&dialect);
                }
                js.set("client_dialects", jsa);
            } else if x.smb_ver == 2 {
                let jsa = Json::array();
                for d in &x.dialects2 {
                    let dialect = String::from_utf8_lossy(&d);
                    jsa.array_append_string(&dialect);
                }
                js.set("client_dialects", jsa);
            }

            if let Some(ref g) = x.client_guid {
                js.set_string("client_guid", &guid_to_string(g));
            }

            js.set_string("server_guid", &guid_to_string(&x.server_guid));
        },
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            js.set_integer("tree_id", x.tree_id as u64);

            let share_name = String::from_utf8_lossy(&x.share_name);
            if x.is_pipe {
                js.set_string("named_pipe", &share_name);
            } else {
                js.set_string("share", &share_name);
            }

            // handle services
            if tx.vercmd.get_version() == 1 {
                let jsd = Json::object();

                if let Some(ref s) = x.req_service {
                    let serv = String::from_utf8_lossy(&s);
                    jsd.set_string("request", &serv);
                }
                if let Some(ref s) = x.res_service {
                    let serv = String::from_utf8_lossy(&s);
                    jsd.set_string("response", &serv);
                }
                js.set("service", jsd);

            // share type only for SMB2
            } else {
                match x.share_type {
                    1 => { js.set_string("share_type", "FILE"); },
                    2 => { js.set_string("share_type", "PIPE"); },
                    3 => { js.set_string("share_type", "PRINT"); },
                    _ => { js.set_string("share_type", "UNKNOWN"); },
                }
            }
        },
        Some(SMBTransactionTypeData::FILE(ref x)) => {
            let file_name = String::from_utf8_lossy(&x.file_name);
            js.set_string("filename", &file_name);
            let share_name = String::from_utf8_lossy(&x.share_name);
            js.set_string("share", &share_name);
            let gs = fuid_to_string(&x.fuid);
            js.set_string("fuid", &gs);
        },
        Some(SMBTransactionTypeData::RENAME(ref x)) => {
            if tx.vercmd.get_version() == 2 {
                let jsd = Json::object();
                jsd.set_string("class", "FILE_INFO");
                jsd.set_string("info_level", "SMB2_FILE_RENAME_INFO");
                js.set("set_info", jsd);
            }

            let jsd = Json::object();
            let file_name = String::from_utf8_lossy(&x.oldname);
            jsd.set_string("from", &file_name);
            let file_name = String::from_utf8_lossy(&x.newname);
            jsd.set_string("to", &file_name);
            js.set("rename", jsd);
            let gs = fuid_to_string(&x.fuid);
            js.set_string("fuid", &gs);
        },
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            let jsd = Json::object();
            if x.req_set {
                jsd.set_string("request", &dcerpc_type_string(x.req_cmd));
            } else {
                jsd.set_string("request", "REQUEST_LOST");
            }
            if x.res_set {
                jsd.set_string("response", &dcerpc_type_string(x.res_cmd));
            } else {
                jsd.set_string("response", "UNREPLIED");
            }
            if x.req_set {
                match x.req_cmd {
                    DCERPC_TYPE_REQUEST => {
                        jsd.set_integer("opnum", x.opnum as u64);
                        let req = Json::object();
                        req.set_integer("frag_cnt", x.frag_cnt_ts as u64);
                        req.set_integer("stub_data_size", x.stub_data_ts.len() as u64);
                        jsd.set("req", req);
                    },
                    DCERPC_TYPE_BIND => {
                        match state.dcerpc_ifaces {
                            Some(ref ifaces) => {
                                let jsa = Json::array();
                                for i in ifaces {
                                    let jso = Json::object();
                                    let ifstr = dcerpc_uuid_to_string(&i);
                                    jso.set_string("uuid", &ifstr);
                                    let vstr = format!("{}.{}", i.ver, i.ver_min);
                                    jso.set_string("version", &vstr);

                                    if i.acked {
                                        jso.set_integer("ack_result", i.ack_result as u64);
                                        jso.set_integer("ack_reason", i.ack_reason as u64);
                                    }

                                    jsa.array_append(jso);
                                }

                                jsd.set("interfaces", jsa);
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
                        let res = Json::object();
                        res.set_integer("frag_cnt", x.frag_cnt_tc as u64);
                        res.set_integer("stub_data_size", x.stub_data_tc.len() as u64);
                        jsd.set("res", res);
                    },
                    // we don't handle BINDACK w/o BIND
                    _ => {},
                }
            }
            jsd.set_integer("call_id", x.call_id as u64);
            js.set("dcerpc", jsd);
        }
        Some(SMBTransactionTypeData::IOCTL(ref x)) => {
            js.set_string("function", &fsctl_func_to_string(x.func));
        },
        Some(SMBTransactionTypeData::SETFILEPATHINFO(ref x)) => {
            let mut name_raw = x.filename.to_vec();
            name_raw.retain(|&i|i != 0x00);
            if name_raw.len() > 0 {
                let name = String::from_utf8_lossy(&name_raw);
                js.set_string("filename", &name);
            } else {
                // name suggestion from Bro
                js.set_string("filename", "<share_root>");
            }
            if x.delete_on_close {
                js.set_string("access", "delete on close");
            } else {
                js.set_string("access", "normal");
            }

            match x.subcmd {
                8 => {
                    js.set_string("subcmd", "SET_FILE_INFO");
                },
                6 => {
                    js.set_string("subcmd", "SET_PATH_INFO");
                },
                _ => { },
            }

            match x.loi {
                1013 => { // Set Disposition Information
                    js.set_string("level_of_interest", "Set Disposition Information");
                },
                _ => { },
            }

            let gs = fuid_to_string(&x.fid);
            js.set_string("fuid", &gs);
        },
        _ => {  },
    }
    return js;
}

#[no_mangle]
pub extern "C" fn rs_smb_log_json_request(state: &mut SMBState, tx: &mut SMBTransaction) -> *mut JsonT
{
    let js = smb_common_header(state, tx);
    return js.unwrap();
}

#[no_mangle]
pub extern "C" fn rs_smb_log_json_response(state: &mut SMBState, tx: &mut SMBTransaction) -> *mut JsonT
{
    let js = smb_common_header(state, tx);
    return js.unwrap();
}

