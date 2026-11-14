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

/// Bounds for what the NFS logger writes. Names reach the transaction whole so
/// the `nfs.*` keywords can still match on them, which means the logger cannot
/// trust their size: a name is only limited by stream reassembly otherwise.
/// The per-record budget mirrors the DNS logger's (128 KiB); the per-string cap
/// (8 KiB) is what a single name can cost.
const NFS_LOG_MAX_RECORD_BYTES: usize = 128 * 1024;
const NFS_LOG_MAX_STRING_BYTES: usize = 8 * 1024;
/// Room for the `[truncated N additional bytes]` suffix a capped value carries.
const NFS_LOG_MARKER_BYTES: usize = 48;

pub(crate) struct NfsLogBudget {
    remaining: usize,
    truncated: bool,
}

impl NfsLogBudget {
    fn new() -> Self {
        Self {
            remaining: NFS_LOG_MAX_RECORD_BYTES,
            truncated: false,
        }
    }

    /// Note a value that exceeds the per-field cap: it will be shortened at
    /// emit, and the record has to say so.
    fn note(&mut self, len: usize) {
        if len > NFS_LOG_MAX_STRING_BYTES {
            self.truncated = true;
        }
    }

    /// Bytes a string field will actually take: what gets written, not what the
    /// parser was handed. Charging the input length would drop a field the
    /// budget still has room for.
    fn charge(len: usize, key: &str) -> usize {
        len.min(NFS_LOG_MAX_STRING_BYTES) + NFS_LOG_MARKER_BYTES + key.len() + 6
    }

    /// Account for a value about to be written; false once the budget is spent.
    fn cost(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining {
            self.truncated = true;
            return false;
        }
        self.remaining -= bytes;
        true
    }
}

/// Write a caller-supplied string within the field cap and the record budget.
/// `marker` names the boolean key to set when the budget refuses the value, so
/// a dropped field is not read as an absent one.
fn set_bounded_string(
    budget: &mut NfsLogBudget, js: &mut JsonBuilder, key: &str, marker: Option<&str>, val: &str,
) -> Result<(), JsonError> {
    budget.note(val.len());
    if !budget.cost(NfsLogBudget::charge(val.len(), key)) {
        if let Some(m) = marker {
            js.set_bool(m, true)?;
        }
        return Ok(());
    }
    if val.len() > NFS_LOG_MAX_STRING_BYTES {
        js.set_string_limited(key, val, NFS_LOG_MAX_STRING_BYTES)?;
    } else {
        js.set_string(key, val)?;
    }
    Ok(())
}

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

/// Filtering decision, with the config passed in so it can be tested
/// without writing to the config statics.
fn nfs_tx_is_filtered<'a, I>(
    state: &NFSState, tx: &NFSTransaction, filter_set: bool, procs: I,
) -> bool
where
    I: IntoIterator<Item = &'a String>,
{
    // A tx created only to carry an app-layer event has no request and no
    // reply: logging it would invent a procedure (0, i.e. NULL).
    if tx.is_event_only {
        return true;
    }
    // When app-layer.protocols.nfs.filter is set -- even to an empty
    // list -- its procedure names (case-insensitive, matched against
    // the transaction's version) define exactly which transactions are
    // kept out of the EVE output. When the key is absent the historical
    // default applies: v3 GETATTR is by far the most frequent procedure
    // and rarely interesting on its own, so it is filtered.
    if filter_set {
        let name = nfs_proc_name(state, tx).to_lowercase();
        return procs.into_iter().any(|p| p == &name);
    }
    state.nfs_version <= 3 && tx.procedure == NFSPROC3_GETATTR
}

#[no_mangle]
pub extern "C" fn SCNfsTxLoggingIsFiltered(state: &mut NFSState, tx: &NFSTransaction) -> u8 {
    let filter_set = unsafe { NFS_CFG_FILTER_SET };
    // The list is written once during config initialization and never
    // mutated again; read it through a raw pointer to avoid the
    // static_mut_refs lint on the shared reference.
    let procs_ptr = std::ptr::addr_of!(NFS_CFG_FILTER_PROCS);
    let filtered = unsafe { nfs_tx_is_filtered(state, tx, filter_set, (*procs_ptr).iter()) };
    if filtered {
        return 1;
    }
    return 0;
}

fn nfs_rename_object(
    tx: &NFSTransaction, js: &mut JsonBuilder, budget: &mut NfsLogBudget,
) -> Result<(), JsonError> {
    let from_str = String::from_utf8_lossy(&tx.file_name);
    set_bounded_string(budget, js, "from", Some("from_truncated"), &from_str)?;

    let to_vec = match tx.type_data {
        Some(NFSTransactionTypeData::RENAME(ref x)) => x.to_vec(),
        _ => Vec::new(),
    };

    let to_str = String::from_utf8_lossy(&to_vec);
    set_bounded_string(budget, js, "to", Some("to_truncated"), &to_str)?;
    Ok(())
}

fn nfs_creds_object(
    tx: &NFSTransaction, js: &mut JsonBuilder, budget: &mut NfsLogBudget,
) -> Result<(), JsonError> {
    let mach_name = String::from_utf8_lossy(&tx.request_machine_name);
    set_bounded_string(
        budget,
        js,
        "machine_name",
        Some("machine_name_truncated"),
        &mach_name,
    )?;
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
    state: &NFSState, tx: &NFSTransaction, js: &mut JsonBuilder, budget: &mut NfsLogBudget,
) -> Result<(), JsonError> {
    // the transaction's own version when it has one: a record logged before
    // the first reply would otherwise report 0
    js.set_uint(
        "version",
        if tx.nfs_version != 0 {
            tx.nfs_version as u64
        } else {
            state.nfs_version as u64
        },
    )?;
    js.set_string("procedure", &nfs_proc_name(state, tx).to_uppercase())?;
    let file_name = String::from_utf8_lossy(&tx.file_name);
    set_bounded_string(
        budget,
        js,
        "filename",
        Some("filename_truncated"),
        &file_name,
    )?;

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
    state: &NFSState, tx: &NFSTransaction, js: &mut JsonBuilder, status_required: bool,
) -> Result<(), JsonError> {
    let mut budget = NfsLogBudget::new();
    nfs_common_header(state, tx, js, &mut budget)?;
    js.set_string("type", "response")?;

    // The status name depends on the version: v4 has its own error
    // number space (RFC 7530 nfsstat4) that diverges from v3 in the
    // 10000s, so naming a v4 status from the v3 table would be wrong
    // (e.g. 10008 is DELAY in v4, JUKEBOX in v3).
    // Only log the status when the reply actually carried a status word:
    // an empty status on a truncated reply would read as a fake OK
    if tx.nfs_status_set || !status_required {
        let status = if state.nfs_version == 4 {
            nfs4_status_string(tx.nfs_response_status)
        } else {
            nfs3_status_string(tx.nfs_response_status)
        };
        js.set_string("status", &status)?;
    }
    // Numeric status code (SMB parity: status + status_code), but only when a
    // reply status was actually seen: 0 reads as NFS3_OK, and a transaction
    // closed from the request side (v3 FILE_SYNC WRITE, v4 COMMIT) has no
    // reply yet, so emitting it there would claim success.
    if tx.nfs_status_set {
        js.set_uint("status_code", tx.nfs_response_status as u64)?;
    }

    // v4 session identity (RFC 7530): the minor version of the
    // compounds on this flow and the 8-byte client identifier
    // (clientid4) when observed. Session id (v4.1 CREATE_SESSION
    // ssn_id) is not logged: it is a 16-byte binary opaque
    // (nfs4_sessionid4), which has no printable representation.
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
        nfs_rename_object(tx, js, &mut budget)?;
        js.close()?;
    }
    if budget.truncated {
        js.set_bool("truncated", true)?;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn SCNfsLogJsonResponse(
    state: &mut NFSState, tx: &NFSTransaction, js: &mut JsonBuilder,
) -> bool {
    nfs_log_response(state, tx, js, true).is_ok()
}

/// nfs block of an alert or fileinfo record: taken from the transaction while
/// it may still be open (an alert can be raised on the request packet), so an
/// unset status is reported as mainline does rather than dropped. Event-only
/// transactions are skipped: nothing was parsed as a call, so the fields would
/// be whatever the record mark happened to look like.
#[no_mangle]
pub extern "C" fn SCNfsLogJsonResponseMetadata(
    state: &mut NFSState, tx: &NFSTransaction, js: &mut JsonBuilder,
) -> bool {
    if tx.is_event_only {
        return false;
    }
    nfs_log_response(state, tx, js, false).is_ok()
}

fn rpc_log_response(tx: &NFSTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let mut budget = NfsLogBudget::new();
    js.set_uint("xid", tx.xid as u64)?;
    js.set_string("status", &rpc_status_string(tx.rpc_response_status))?;
    js.set_string("auth_type", &rpc_auth_type_string(tx.auth_type))?;
    if tx.auth_type == RPCAUTH_UNIX {
        js.open_object("creds")?;
        nfs_creds_object(tx, js, &mut budget)?;
        js.close()?;
    }
    if budget.truncated {
        js.set_bool("truncated", true)?;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn SCNfsRpcLogJsonResponse(tx: &NFSTransaction, js: &mut JsonBuilder) -> bool {
    // no RPC reply behind an event-only tx: xid and status would be invented
    if tx.is_event_only {
        return false;
    }
    rpc_log_response(tx, js).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(version: u16) -> NFSState {
        let mut s = NFSState::new();
        s.nfs_version = version;
        s
    }

    fn tx(procedure: u32) -> NFSTransaction {
        let mut t = NFSTransaction::new();
        t.procedure = procedure;
        t
    }

    #[test]
    fn test_tx_is_filtered_event_only() {
        let mut t = tx(NFSPROC3_READ);
        t.is_event_only = true;
        assert!(nfs_tx_is_filtered(&state(3), &t, false, &[]));
        assert!(nfs_tx_is_filtered(&state(3), &t, true, &[]));
        // alert metadata must not render a procedure or status for a tx that
        // stands for an event rather than a call
        let mut st = state(3);
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(!SCNfsLogJsonResponseMetadata(&mut st, &t, &mut js));
        assert!(!SCNfsRpcLogJsonResponse(&t, &mut js));
        // a parsed tx still renders both
        let t2 = tx(NFSPROC3_READ);
        assert!(SCNfsLogJsonResponseMetadata(&mut st, &t2, &mut js));
        assert!(SCNfsRpcLogJsonResponse(&t2, &mut js));
    }

    #[test]
    fn test_tx_is_filtered_default() {
        // No filter configured: v3 GETATTR is the one thing dropped.
        assert!(nfs_tx_is_filtered(
            &state(3),
            &tx(NFSPROC3_GETATTR),
            false,
            &[]
        ));
        assert!(nfs_tx_is_filtered(
            &state(2),
            &tx(NFSPROC3_GETATTR),
            false,
            &[]
        ));
        assert!(!nfs_tx_is_filtered(
            &state(4),
            &tx(NFSPROC4_GETATTR),
            false,
            &[]
        ));
        assert!(!nfs_tx_is_filtered(
            &state(3),
            &tx(NFSPROC3_READ),
            false,
            &[]
        ));
    }

    #[test]
    fn test_tx_is_filtered_config_list() {
        // An explicit list replaces the default, including when empty.
        let procs = vec!["getattr".to_string()];
        assert!(nfs_tx_is_filtered(
            &state(3),
            &tx(NFSPROC3_GETATTR),
            true,
            &procs
        ));
        assert!(!nfs_tx_is_filtered(
            &state(3),
            &tx(NFSPROC3_READ),
            true,
            &procs
        ));
        assert!(!nfs_tx_is_filtered(
            &state(3),
            &tx(NFSPROC3_GETATTR),
            true,
            &[]
        ));
        // Names are matched per version, so the same word means the v4 op.
        let procs = vec!["read".to_string()];
        assert!(nfs_tx_is_filtered(
            &state(4),
            &tx(NFSPROC4_READ),
            true,
            &procs
        ));
        assert!(!nfs_tx_is_filtered(
            &state(4),
            &tx(NFSPROC4_WRITE),
            true,
            &procs
        ));
    }

    #[test]
    fn test_budget_flags_oversized_string() {
        let mut budget = NfsLogBudget::new();
        budget.note(NFS_LOG_MAX_STRING_BYTES);
        assert!(!budget.truncated);
        budget.note(NFS_LOG_MAX_STRING_BYTES + 1);
        assert!(budget.truncated);
    }

    #[test]
    fn test_budget_charges_what_is_written_not_what_was_parsed() {
        // a name longer than the field cap must not cost more than the cap: at
        // 70 KiB the old charge dropped rename.from although the record was
        // nowhere near the budget
        assert!(NfsLogBudget::charge(70 * 1024, "filename") < 9 * 1024);
        let mut budget = NfsLogBudget::new();
        for key in ["filename", "from", "to", "machine_name"] {
            assert!(budget.cost(NfsLogBudget::charge(64 * 1024, key)), "{key}");
        }
        assert!(!budget.truncated);
    }

    #[test]
    fn test_budget_spends_down_to_the_record_limit() {
        let mut budget = NfsLogBudget::new();
        assert!(budget.cost(NFS_LOG_MAX_RECORD_BYTES));
        assert!(!budget.cost(1));
        assert!(budget.truncated);
    }
}
