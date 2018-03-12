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

extern crate libc;

use std::str;
use std::string::String;
use json::*;
use smb::smb::*;
use smb::smb1::*;
use smb::smb2::*;
use smb::dcerpc::*;
use nom;

fn smb_common_header(state: &SMBState, tx: &SMBTransaction) -> Json
{
    let js = Json::object();
    js.set_integer("id", tx.id as u64);

    if state.dialect != 0 {
        let dialect = &smb2_dialect_string(state.dialect);
        js.set_string("dialect", &dialect);
    } else {
        let dialect = match &state.dialect_vec {
            &Some(ref d) => {
                match str::from_utf8(&d) {
                    Ok(v) => v,
                    Err(_) => "invalid",
                }
            },
            &None => { "unknown" },
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
            js.set_string("statux", &status_hex);
        },
        (false, _) => {
            match tx.vercmd.get_dos_error() {
                (true, doserr) => {
                    let status = smb_dos_error_string(doserr);
                    js.set_string("status", &status);
                    let status_hex = format!("0x{:x}", doserr);
                    js.set_string("statux", &status_hex);
                },
                (_, _) => {
                },
            }
        },
    }


    js.set_integer("session_id", tx.hdr.ssn_id);
    js.set_integer("tree_id", tx.hdr.tree_id as u64);

    js.set_boolean("request_done", tx.request_done);
    js.set_boolean("response_done", tx.request_done);
    match tx.type_data {
        Some(SMBTransactionTypeData::SESSIONSETUP(ref x)) => {
            if let Some(ref ntlmssp) = x.ntlmssp {
                let jsd = Json::object();
                let domain = match str::from_utf8(&ntlmssp.domain) {
                    Ok(v) => v,
                    Err(_) => "UTF8_ERROR",
                };
                jsd.set_string("domain", &domain);

                let user = match str::from_utf8(&ntlmssp.user) {
                    Ok(v) => v,
                    Err(_) => "UTF8_ERROR",
                };
                jsd.set_string("user", &user);

                let host = match str::from_utf8(&ntlmssp.host) {
                    Ok(v) => v,
                    Err(_) => "UTF8_ERROR",
                };
                jsd.set_string("host", &host);

                if let Some(ref v) = ntlmssp.version {
                    jsd.set_string("version", v.to_string().as_str());
                }

                js.set("ntlmssp", jsd);
            }

            if let Some(ref ticket) = x.krb_ticket {
                let jsd = Json::object();
                let realm = match str::from_utf8(&ticket.realm) {
                    Ok(v) => v,
                    Err(_) => "UTF8_ERROR",
                };
                jsd.set_string("realm", &realm);
                let jsa = Json::array();
                for sname in &ticket.snames {
                    let name = match str::from_utf8(&sname) {
                        Ok(v) => v,
                        Err(_) => "UTF8_ERROR",
                    };
                    jsa.array_append_string(&name);
                }
                jsd.set("snames", jsa);
                js.set("kerberos", jsd);
            }

            match x.request_host {
                Some(ref r) => {
                    let jsd = Json::object();
                    let os = match str::from_utf8(&r.native_os) {
                        Ok(v) => v,
                            Err(_) => "UTF8_ERROR",
                    };
                    jsd.set_string("native_os", &os);
                    let lm = match str::from_utf8(&r.native_lm) {
                        Ok(v) => v,
                            Err(_) => "UTF8_ERROR",
                    };
                    jsd.set_string("native_lm", &lm);
                    js.set("request", jsd);
                },
                None => { },
            }
            match x.response_host {
                Some(ref r) => {
                    let jsd = Json::object();
                    let os = match str::from_utf8(&r.native_os) {
                        Ok(v) => v,
                            Err(_) => "UTF8_ERROR",
                    };
                    jsd.set_string("native_os", &os);
                    let lm = match str::from_utf8(&r.native_lm) {
                        Ok(v) => v,
                            Err(_) => "UTF8_ERROR",
                    };
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
                1 => { js.set_string("disposition", "open"); },
                2 => { js.set_string("disposition", "create"); },
                5 => { js.set_string("disposition", "overwrite"); },
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


            if x.guid.len() >= 2 {
                let fid_s = &x.guid[0..2];
                let fid_n = match nom::le_u16(&fid_s) {
                    nom::IResult::Done(_, x) => {
                        x as u16
                    }
                    _ => 0 as u16
                };
                let fid_hex_str = format!("0x{:00x}", fid_n);
                js.set_string("fid", &fid_hex_str);
            }
        },
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            let jsd = Json::object();
            jsd.set_string("request", &dcerpc_type_string(x.req_cmd));
            if x.res_set {
                jsd.set_string("response", &dcerpc_type_string(x.res_cmd));
            } else {
                jsd.set_string("response", "UNREPLIED");
            }
            match x.req_cmd {
                DCERPC_TYPE_REQUEST => {
                    jsd.set_integer("opnum", x.opnum as u64);
                    let req = Json::object();
                    req.set_integer("frag_cnt", x.frag_cnt_ts as u64);
                    req.set_integer("stub_data_size", x.stub_data_ts.len() as u64);
                    jsd.set("req", req);
                    let res = Json::object();
                    res.set_integer("frag_cnt", x.frag_cnt_tc as u64);
                    res.set_integer("stub_data_size", x.stub_data_tc.len() as u64);
                    jsd.set("res", res);
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
            jsd.set_integer("call_id", x.call_id as u64);
            js.set("dcerpc", jsd);
        }
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
