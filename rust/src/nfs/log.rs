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

use std::string::String;
use json::*;
use nfs::types::*;
use nfs::nfs::*;
use crc::crc32;

#[no_mangle]
pub extern "C" fn rs_nfs_tx_logging_is_filtered(tx: &mut NFSTransaction)
                                                 -> libc::uint8_t
{
    // TODO probably best to make this configurable

    if tx.procedure == NFSPROC3_GETATTR {
        return 1;
    }

    return 0;
}

fn nfs_rename_object(tx: &NFSTransaction) -> Json
{
    let js = Json::object();
    let from_str = String::from_utf8_lossy(&tx.file_name);
    js.set_string("from", &from_str);

    let to_vec = match tx.type_data {
        Some(NFSTransactionTypeData::RENAME(ref x)) => { x.to_vec() },
        _ => { Vec::new() }
    };

    let to_str = String::from_utf8_lossy(&to_vec);
    js.set_string("to", &to_str);
    return js;
}

fn nfs_creds_object(tx: &NFSTransaction) -> Json
{
    let js = Json::object();
    let mach_name = String::from_utf8_lossy(&tx.request_machine_name);
    js.set_string("machine_name", &mach_name);
    js.set_integer("uid", tx.request_uid as u64);
    js.set_integer("gid", tx.request_gid as u64);
    return js;
}

fn nfs_file_object(tx: &NFSTransaction) -> Json
{
    let js = Json::object();
    js.set_boolean("first", tx.is_first);
    js.set_boolean("last", tx.is_last);

    let ref tdf = match tx.type_data {
        Some(NFSTransactionTypeData::FILE(ref x)) => x,
        _ => { panic!("BUG") },
    };

    js.set_integer("last_xid", tdf.file_last_xid as u64);
    js.set_integer("chunks", tdf.chunk_count as u64);
    return js;
}
/*
fn nfs_handle2hex(bytes: &Vec<u8>) -> String {
    let strings: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strings.join("")
}
*/
fn nfs_handle2crc(bytes: &Vec<u8>) -> u32 {
    let c = crc32::checksum_ieee(bytes);
    c
}

fn nfs_common_header(state: &NFSState, tx: &NFSTransaction) -> Json
{
    let js = Json::object();
    js.set_integer("version", state.nfs_version as u64);
    js.set_string("procedure", &nfs3_procedure_string(tx.procedure));
    let file_name = String::from_utf8_lossy(&tx.file_name);
    js.set_string("filename", &file_name);

    if tx.file_handle.len() > 0 {
        //js.set_string("handle", &nfs_handle2hex(&tx.file_handle));
        let c = nfs_handle2crc(&tx.file_handle);
        let s = format!("{:x}", c);
        js.set_string("hhash", &s);
    }
    js.set_integer("id", tx.id as u64);
    js.set_boolean("file_tx", tx.is_file_tx);
    return js;
}

#[no_mangle]
pub extern "C" fn rs_nfs_log_json_request(state: &mut NFSState, tx: &mut NFSTransaction) -> *mut JsonT
{
    let js = nfs_common_header(state, tx);
    js.set_string("type", "request");
    return js.unwrap();
}

#[no_mangle]
pub extern "C" fn rs_nfs_log_json_response(state: &mut NFSState, tx: &mut NFSTransaction) -> *mut JsonT
{
    let js = nfs_common_header(state, tx);
    js.set_string("type", "response");

    js.set_string("status", &nfs3_status_string(tx.nfs_response_status));

    if tx.procedure == NFSPROC3_READ {
        let read_js = nfs_file_object(tx);
        js.set("read", read_js);
    } else if tx.procedure == NFSPROC3_WRITE {
        let write_js = nfs_file_object(tx);
        js.set("write", write_js);
    } else if tx.procedure == NFSPROC3_RENAME {
        let rename_js = nfs_rename_object(tx);
        js.set("rename", rename_js);
    }

    return js.unwrap();
}


#[no_mangle]
pub extern "C" fn rs_rpc_log_json_response(tx: &mut NFSTransaction) -> *mut JsonT
{
    let js = Json::object();
    js.set_integer("xid", tx.xid as u64);
    js.set_string("status", &rpc_status_string(tx.rpc_response_status));
    js.set_string("auth_type", &rpc_auth_type_string(tx.auth_type));
    if tx.auth_type == RPCAUTH_UNIX {
        let creds_js = nfs_creds_object(tx);
        js.set("creds", creds_js);
    }

    return js.unwrap();
}
