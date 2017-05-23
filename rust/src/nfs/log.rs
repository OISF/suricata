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
//use log::*;
use nfs::types::*;
use nfs::nfs3::*;

#[no_mangle]
pub extern "C" fn rs_nfs3_tx_logging_is_filtered(tx: &mut NFS3Transaction)
                                                 -> libc::uint8_t
{
    // TODO probably best to make this configurable

    if tx.procedure == NFSPROC3_GETATTR {
        return 1;
    }

    return 0;
}

fn nfs3_rename_object(tx: &NFS3Transaction) -> Json
{
    let js = Json::object();
    let from_str = String::from_utf8_lossy(&tx.file_name);
    js.set_string("from", &from_str);

    let to_vec = match tx.type_data {
        Some(NFS3TransactionTypeData::RENAME(ref x)) => { x.to_vec() },
        _ => { Vec::new() }
    };

    let to_str = String::from_utf8_lossy(&to_vec);
    js.set_string("to", &to_str);
    return js;
}

fn nfs3_creds_object(tx: &NFS3Transaction) -> Json
{
    let js = Json::object();
    let mach_name = String::from_utf8_lossy(&tx.request_machine_name);
    js.set_string("machine_name", &mach_name);
    js.set_integer("uid", tx.request_uid as u64);
    js.set_integer("gid", tx.request_gid as u64);
    return js;
}

fn nfs3_file_object(tx: &NFS3Transaction) -> Json
{
    let js = Json::object();
    js.set_boolean("first", tx.is_first);
    js.set_boolean("last", tx.is_last);

    let ref tdf = match tx.type_data {
        Some(NFS3TransactionTypeData::FILE(ref x)) => x,
        _ => { panic!("BUG") },
    };

    js.set_integer("last_xid", tdf.file_last_xid as u64);
    return js;
}

fn nfs3_common_header(tx: &NFS3Transaction) -> Json
{
    let js = Json::object();
    js.set_integer("xid", tx.xid as u64);
    js.set_string("procedure", &nfs3_procedure_string(tx.procedure));
    let file_name = String::from_utf8_lossy(&tx.file_name);
    js.set_string("filename", &file_name);
    js.set_integer("id", tx.id as u64);
    js.set_boolean("file_tx", tx.is_file_tx);
    return js;
}

#[no_mangle]
pub extern "C" fn rs_nfs3_log_json_request(tx: &mut NFS3Transaction) -> *mut JsonT
{
    let js = nfs3_common_header(tx);
    js.set_string("type", "request");
    return js.unwrap();
}

#[no_mangle]
pub extern "C" fn rs_nfs3_log_json_response(tx: &mut NFS3Transaction) -> *mut JsonT
{
    let js = nfs3_common_header(tx);
    js.set_string("type", "response");

    js.set_string("status", &nfs3_status_string(tx.response_status));

    if tx.has_creds {
        let creds_js = nfs3_creds_object(tx);
        js.set("creds", creds_js);
    }

    if tx.procedure == NFSPROC3_READ {
        let read_js = nfs3_file_object(tx);
        js.set("read", read_js);
    } else if tx.procedure == NFSPROC3_WRITE {
        let write_js = nfs3_file_object(tx);
        js.set("write", write_js);
    } else if tx.procedure == NFSPROC3_RENAME {
        let rename_js = nfs3_rename_object(tx);
        js.set("rename", rename_js);
    }

    return js.unwrap();
}
