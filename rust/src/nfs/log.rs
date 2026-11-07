/* Copyright (C) 2017-2020 Open Information Security Foundation
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

use crate::detect::EnumString;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::nfs::nfs::*;
use crate::nfs::types::*;
use crc::crc32;
use std::string::String;

/// The canonical procedure name for the transaction's version
/// (e.g. "GETATTR"), or the numeric value when the procedure is unknown.
fn nfs_proc_name(state: &NFSState, tx: &NFSTransaction) -> String {
    if state.nfs_version == 3 {
        if let Some(proc) = NfsProc3::from_u(tx.procedure) {
            return proc.to_str().to_string();
        }
    } else if state.nfs_version <= 2 {
        if let Some(proc) = NfsProc2::from_u(tx.procedure) {
            return proc.to_str().to_string();
        }
    } else if let Some(proc) = NfsProc4::from_u(tx.procedure) {
        return proc.to_str().to_string();
    }
    format!("{}", tx.procedure)
}

#[no_mangle]
pub extern "C" fn SCNfsTxLoggingIsFiltered(state: &mut NFSState, tx: &NFSTransaction) -> u8 {
    // A tx created only to carry an app-layer event has no request and no
    // reply: logging it would invent a procedure (0, i.e. NULL).
    if tx.is_event_only {
        return 1;
    }
    // When app-layer.protocols.nfs.filter is set -- even to an empty
    // list -- its procedure names (case-insensitive, matched against
    // the transaction's version) define exactly which transactions are
    // kept out of the EVE output. When the key is absent the historical
    // default applies: v3 GETATTR is by far the most frequent procedure
    // and rarely interesting on its own, so it is filtered.
    let (procs, filter_set) = unsafe { (&NFS_CFG_FILTER_PROCS, NFS_CFG_FILTER_SET) };
    if filter_set {
        let name = nfs_proc_name(state, tx).to_lowercase();
        if procs.iter().any(|p| p == &name) {
            return 1;
        }
        return 0;
    }
    if state.nfs_version <= 3 && tx.procedure == NFSPROC3_GETATTR {
        return 1;
    }

    return 0;
}

fn nfs_rename_object(tx: &NFSTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let from_str = String::from_utf8_lossy(&tx.file_name);
    js.set_string("from", &from_str)?;

    let to_vec = match tx.type_data {
        Some(NFSTransactionTypeData::RENAME(ref x)) => x.to_vec(),
        _ => Vec::new(),
    };

    let to_str = String::from_utf8_lossy(&to_vec);
    js.set_string("to", &to_str)?;
    Ok(())
}

fn nfs_creds_object(tx: &NFSTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let mach_name = String::from_utf8_lossy(&tx.request_machine_name);
    js.set_string("machine_name", &mach_name)?;
    js.set_uint("uid", tx.request_uid as u64)?;
    js.set_uint("gid", tx.request_gid as u64)?;
    Ok(())
}

fn nfs_file_object(tx: &NFSTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_bool("first", tx.is_first)?;
    js.set_bool("last", tx.is_last)?;

    if let Some(NFSTransactionTypeData::FILE(ref tdf)) = tx.type_data {
        js.set_uint("last_xid", tdf.file_last_xid as u64)?;
        js.set_uint("chunks", tdf.chunk_count as u64)?;
        js.set_uint("offset", tdf.first_offset)?;
        js.set_uint("size", tdf.total_bytes)?;
    }
    Ok(())
}
/*
fn nfs_handle2hex(bytes: &Vec<u8>) -> String {
    let strings: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strings.join("")
}
*/
fn nfs_handle2crc(bytes: &[u8]) -> u32 {
    let c = crc32::checksum_ieee(bytes);
    c
}

fn nfs_common_header(
    state: &NFSState, tx: &NFSTransaction, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    js.set_uint("version", state.nfs_version as u64)?;
    js.set_string("procedure", &nfs_proc_name(state, tx).to_uppercase())?;
    let file_name = String::from_utf8_lossy(&tx.file_name);
    js.set_string("filename", &file_name)?;

    if !tx.file_handle.is_empty() {
        //js.set_string("handle", &nfs_handle2hex(&tx.file_handle));
        let c = nfs_handle2crc(&tx.file_handle);
        let s = format!("{:x}", c);
        js.set_string("hhash", &s)?;
    }
    js.set_uint("id", tx.id)?;
    js.set_bool("file_tx", tx.is_file_tx)?;
    Ok(())
}

fn nfs_log_response(
    state: &NFSState, tx: &NFSTransaction, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    nfs_common_header(state, tx, js)?;
    js.set_string("type", "response")?;

    // The status name depends on the version: v4 has its own error
    // number space (RFC 7530 nfsstat4) that diverges from v3 in the
    // 10000s, so naming a v4 status from the v3 table would be wrong
    // (e.g. 10008 is DELAY in v4, JUKEBOX in v3).
    // Only log the status when the reply actually carried a status word:
    // an empty status on a truncated reply would read as a fake OK
    if tx.nfs_status_set {
        let status = if state.nfs_version == 4 {
            nfs4_status_string(tx.nfs_response_status)
        } else {
            nfs3_status_string(tx.nfs_response_status)
        };
        js.set_string("status", &status)?;
        // Numeric status code (SMB parity: status + status_code).
        js.set_uint("status_code", tx.nfs_response_status as u64)?;
    }

    // v4 session identity (RFC 7530): the minor version of the
    // compounds on this flow and the 8-byte client identifier
    // (clientid4) when observed. Session id (v4.1 CREATE_SESSION
    // ssn_id) is not logged: the CREATE_SESSION parser's field sizes
    // diverge from the RFC (ssn_id read as 16 bytes, not 8).
    if state.nfs_version == 4 {
        js.set_uint("minorversion", state.minorversion as u64)?;
        if let Some(ref cid) = state.client_id {
            js.set_hex("client_id", cid)?;
        }
    }

    if nfs_is_read(state.nfs_version, tx.procedure) {
        js.open_object("read")?;
        nfs_file_object(tx, js)?;
        if let Some(NFSTransactionTypeData::FILE(ref tdf)) = tx.type_data {
            js.set_bool("eof", tdf.eof)?;
        }
        js.close()?;
    } else if nfs_is_write(state.nfs_version, tx.procedure) {
        js.open_object("write")?;
        nfs_file_object(tx, js)?;
        js.close()?;
    } else if nfs_is_rename(state.nfs_version, tx.procedure) {
        js.open_object("rename")?;
        nfs_rename_object(tx, js)?;
        js.close()?;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn SCNfsLogJsonResponse(
    state: &mut NFSState, tx: &NFSTransaction, js: &mut JsonBuilder,
) -> bool {
    nfs_log_response(state, tx, js).is_ok()
}

fn rpc_log_response(tx: &NFSTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_uint("xid", tx.xid as u64)?;
    js.set_string("status", &rpc_status_string(tx.rpc_response_status))?;
    js.set_string("auth_type", &rpc_auth_type_string(tx.auth_type))?;
    if tx.auth_type == RPCAUTH_UNIX {
        js.open_object("creds")?;
        nfs_creds_object(tx, js)?;
        js.close()?;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn SCNfsRpcLogJsonResponse(tx: &NFSTransaction, js: &mut JsonBuilder) -> bool {
    rpc_log_response(tx, js).is_ok()
}
