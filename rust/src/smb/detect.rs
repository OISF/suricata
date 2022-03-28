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

use std::ptr;
use crate::core::*;
use crate::smb::smb::*;
use crate::dcerpc::detect::{DCEIfaceData, DCEOpnumData, DETECT_DCE_OPNUM_RANGE_UNINITIALIZED};
use crate::dcerpc::dcerpc::DCERPC_TYPE_REQUEST;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::collections::{HashMap, HashSet};
use super::smb1;
use super::smb2;

#[no_mangle]
pub unsafe extern "C" fn rs_smb_tx_get_share(tx: &mut SMBTransaction,
                                            buffer: *mut *const u8,
                                            buffer_len: *mut u32)
                                            -> u8
{
    match tx.type_data {
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            SCLogDebug!("is_pipe {}", x.is_pipe);
            if !x.is_pipe {
                *buffer = x.share_name.as_ptr();
                *buffer_len = x.share_name.len() as u32;
                return 1;
            }
        }
        _ => {
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_tx_get_named_pipe(tx: &mut SMBTransaction,
                                            buffer: *mut *const u8,
                                            buffer_len: *mut u32)
                                            -> u8
{
    match tx.type_data {
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            SCLogDebug!("is_pipe {}", x.is_pipe);
            if x.is_pipe {
                *buffer = x.share_name.as_ptr();
                *buffer_len = x.share_name.len() as u32;
                return 1;
            }
        }
        _ => {
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_tx_get_stub_data(tx: &mut SMBTransaction,
                                            direction: u8,
                                            buffer: *mut *const u8,
                                            buffer_len: *mut u32)
                                            -> u8
{
    match tx.type_data {
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            let vref = if direction == Direction::ToServer as u8 {
                &x.stub_data_ts
            } else {
                &x.stub_data_tc
            };
            if vref.len() > 0 {
                *buffer = vref.as_ptr();
                *buffer_len = vref.len() as u32;
                return 1;
            }
        }
        _ => {
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_match_dce_opnum(tx: &mut SMBTransaction,
                                          dce_data: &mut DCEOpnumData)
                                            -> u8
{
    SCLogDebug!("rs_smb_tx_get_dce_opnum: start");
    match tx.type_data {
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            if x.req_cmd == DCERPC_TYPE_REQUEST {
                for range in dce_data.data.iter() {
                    if range.range2 == DETECT_DCE_OPNUM_RANGE_UNINITIALIZED {
                        if range.range1 == x.opnum as u32 {
                            return 1;
                        }
                    } else if range.range1 <= x.opnum as u32 && range.range2 >= x.opnum as u32 {
                        return 1;
                    }
                }
            }
        }
        _ => {
        }
    }

    return 0;
}

/* based on:
 * typedef enum DetectDceIfaceOperators_ {
 *    DETECT_DCE_IFACE_OP_NONE = 0,
 *    DETECT_DCE_IFACE_OP_LT,
 *    DETECT_DCE_IFACE_OP_GT,
 *    DETECT_DCE_IFACE_OP_EQ,
 *    DETECT_DCE_IFACE_OP_NE,
 * } DetectDceIfaceOperators;
 */
#[inline]
fn match_version(op: u8, them: u16, us: u16) -> bool {
    let result = match op {
        0 => { // NONE
            true
        },
        1 => { // LT
            them < us
        },
        2 => { // GT
            them > us
        },
        3 => { // EQ
            them == us
        },
        4 => { // NE
            them != us
        },
        _ => {
            panic!("called with invalid op {}", op);
        },
    };
    result
}

/* mimic logic that is/was in the C code:
 * - match on REQUEST (so not on BIND/BINDACK (probably for mixing with
 *                     dce_opnum and dce_stub_data)
 * - only match on approved ifaces (so ack_result == 0) */
#[no_mangle]
pub extern "C" fn rs_smb_tx_get_dce_iface(state: &mut SMBState,
                                            tx: &mut SMBTransaction,
                                            dce_data: &mut DCEIfaceData)
                                            -> u8
{
    let if_uuid = dce_data.if_uuid.as_slice();
    let if_op = dce_data.op;
    let if_version = dce_data.version;
    let is_dcerpc_request = match tx.type_data {
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            x.req_cmd == DCERPC_TYPE_REQUEST
        },
        _ => { false },
    };
    if !is_dcerpc_request {
        return 0;
    }
    let ifaces = match state.dcerpc_ifaces {
        Some(ref x) => x,
        _ => {
            return 0;
        },
    };

    SCLogDebug!("looking for UUID {:?}", if_uuid);

    for i in ifaces {
        SCLogDebug!("stored UUID {:?} acked {} ack_result {}", i, i.acked, i.ack_result);

        if i.acked && i.ack_result == 0 && i.uuid == if_uuid {
            if match_version(if_op as u8, if_version as u16, i.ver) {
                return 1;
            }
        }
    }
    return 0;
}


#[no_mangle]
pub unsafe extern "C" fn rs_smb_cmd_match(
    tx: &mut SMBTransaction, cmd_valid_codes: &mut SmbCmdValidCodes,
) -> u8 {

    let version = tx.vercmd.get_version();
    let cmd;
    if version == 1 {
        cmd = tx.vercmd.get_smb1_cmd().1.into();
    } else {
        cmd = tx.vercmd.get_smb2_cmd().1;
    }

    SCLogDebug!("rs_smb_cmd_match: version {} cmd {}", version, cmd);

    if let Some(valid_codes) = cmd_valid_codes.0.get(&version) {
        if valid_codes.contains(&cmd) {
            return 1;
        }
    }

    return 0;
}


#[no_mangle]
pub unsafe extern "C" fn rs_smb_cmd_parse(carg: *const c_char) -> *mut c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }
    let arg = match CStr::from_ptr(carg).to_str() {
        Ok(arg) => arg,
        _ => {
            return std::ptr::null_mut();
        }
    };

    match parse_cmd_data(arg) {
        Ok(detect) => Box::into_raw(Box::new(detect)) as *mut _,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_cmd_free(ptr: *mut c_void) {
    if ptr != std::ptr::null_mut() {
        std::mem::drop(Box::from_raw(ptr as *mut SmbCmdValidCodes));
    }
}

/// Stores the SMB command codes used to match with smb.cmd keyword.
/// It includes both valid codes for SMB1 and SMB2.
#[derive(Debug, PartialEq)]
pub struct SmbCmdValidCodes (HashMap<u8, HashSet<u16>>);

impl SmbCmdValidCodes {

    fn new(cmd_codes1: HashSet<u16>, cmd_codes2: HashSet<u16>) -> Self {

        let mut cmd_data = HashMap::new();
        cmd_data.insert(1, cmd_codes1);
        cmd_data.insert(2, cmd_codes2);

        return Self(cmd_data);
    }

}

fn str_to_u16(v: &str) -> Result<u16, ()> {
    let size;
    if v.starts_with("0x") {
        let no_prefix = v.trim_start_matches("0x");
        size = u16::from_str_radix(&no_prefix, 16);
    } else {
        size = u16::from_str_radix(&v, 10);
    }

    return size.map_err(|_| ());
}

fn parse_cmd_data(arg: &str) -> Result<SmbCmdValidCodes, ()> {
    let cmd_names1 = gen_smb1_command_names();
    let cmd_names2 = gen_smb2_command_names();

    let split_args: Vec<&str> = arg.split(',').collect();

    let mut cmd_codes1 = HashSet::new();
    let mut cmd_codes2 = HashSet::new();

    for cmd in split_args.iter() {
        let cmd = cmd.trim().to_ascii_lowercase();

        match str_to_u16(&cmd) {
            Ok(cmd_code) => {
                cmd_codes1.insert(cmd_code);
                cmd_codes2.insert(cmd_code);
            }
            Err(_) => {
                let mut in_any = false;
                if let Some(cmd_code) = cmd_names1.get(cmd.as_str()) {
                    cmd_codes1.insert(*cmd_code);
                    in_any = true;
                }

                if let Some(cmd_code) = cmd_names2.get(cmd.as_str()) {
                    cmd_codes2.insert(*cmd_code);
                    in_any = true;
                }

                if !in_any {
                    return Err(());
                }
            }
        }
    }
    return Ok(SmbCmdValidCodes::new(cmd_codes1, cmd_codes2));
}

fn gen_smb2_command_names() -> HashMap<String, u16> {
    let commands = [
        smb2::SMB2_COMMAND_NEGOTIATE_PROTOCOL,
        smb2::SMB2_COMMAND_SESSION_SETUP,
        smb2::SMB2_COMMAND_SESSION_LOGOFF,
        smb2::SMB2_COMMAND_TREE_CONNECT,
        smb2::SMB2_COMMAND_TREE_DISCONNECT,
        smb2::SMB2_COMMAND_CREATE,
        smb2::SMB2_COMMAND_CLOSE,
        smb2::SMB2_COMMAND_FLUSH,
        smb2::SMB2_COMMAND_READ,
        smb2::SMB2_COMMAND_WRITE,
        smb2::SMB2_COMMAND_LOCK,
        smb2::SMB2_COMMAND_IOCTL,
        smb2::SMB2_COMMAND_CANCEL,
        smb2::SMB2_COMMAND_KEEPALIVE,
        smb2::SMB2_COMMAND_FIND,
        smb2::SMB2_COMMAND_CHANGE_NOTIFY,
        smb2::SMB2_COMMAND_GET_INFO,
        smb2::SMB2_COMMAND_SET_INFO,
        smb2::SMB2_COMMAND_OPLOCK_BREAK,
    ];
    let mut cmd_names2 = HashMap::new();

    for cmd in commands {
        cmd_names2.insert(smb2::smb2_command_string(cmd), cmd);
    }

    cmd_names2.insert("negotiate".into(), smb2::SMB2_COMMAND_NEGOTIATE_PROTOCOL);
    cmd_names2.insert(
        "smb2_command_session_setup".into(),
        smb2::SMB2_COMMAND_SESSION_SETUP,
    );
    cmd_names2.insert("session_setup".into(), smb2::SMB2_COMMAND_SESSION_SETUP);
    cmd_names2.insert("logoff".into(), smb2::SMB2_COMMAND_SESSION_LOGOFF);
    cmd_names2.insert("tree_connect".into(), smb2::SMB2_COMMAND_TREE_CONNECT);
    cmd_names2.insert("tree_disconnect".into(), smb2::SMB2_COMMAND_TREE_DISCONNECT);
    cmd_names2.insert("create".into(), smb2::SMB2_COMMAND_CREATE);
    cmd_names2.insert("close".into(), smb2::SMB2_COMMAND_CLOSE);
    cmd_names2.insert("flush".into(), smb2::SMB2_COMMAND_FLUSH);
    cmd_names2.insert("read".into(), smb2::SMB2_COMMAND_READ);
    cmd_names2.insert("write".into(), smb2::SMB2_COMMAND_WRITE);
    cmd_names2.insert("lock".into(), smb2::SMB2_COMMAND_LOCK);
    cmd_names2.insert("ioctl".into(), smb2::SMB2_COMMAND_IOCTL);
    cmd_names2.insert("cancel".into(), smb2::SMB2_COMMAND_CANCEL);
    cmd_names2.insert("echo".into(), smb2::SMB2_COMMAND_KEEPALIVE);
    cmd_names2.insert("keep_alive".into(), smb2::SMB2_COMMAND_KEEPALIVE);
    cmd_names2.insert("find".into(), smb2::SMB2_COMMAND_FIND);
    cmd_names2.insert("query_directory".into(), smb2::SMB2_COMMAND_FIND);
    cmd_names2.insert("change_notify".into(), smb2::SMB2_COMMAND_CHANGE_NOTIFY);
    cmd_names2.insert("get_info".into(), smb2::SMB2_COMMAND_GET_INFO);
    cmd_names2.insert("query_info".into(), smb2::SMB2_COMMAND_GET_INFO);
    cmd_names2.insert("set_info".into(), smb2::SMB2_COMMAND_SET_INFO);
    cmd_names2.insert("oplock_break".into(), smb2::SMB2_COMMAND_OPLOCK_BREAK);

    return cmd_names2;
}

fn gen_smb1_command_names() -> HashMap<String, u16> {
    let commands = [
        smb1::SMB1_COMMAND_CREATE_DIRECTORY,
        smb1::SMB1_COMMAND_DELETE_DIRECTORY,
        smb1::SMB1_COMMAND_OPEN,
        smb1::SMB1_COMMAND_CREATE,
        smb1::SMB1_COMMAND_CLOSE,
        smb1::SMB1_COMMAND_FLUSH,
        smb1::SMB1_COMMAND_DELETE,
        smb1::SMB1_COMMAND_RENAME,
        smb1::SMB1_COMMAND_QUERY_INFORMATION,
        smb1::SMB1_COMMAND_SET_INFORMATION,
        smb1::SMB1_COMMAND_READ,
        smb1::SMB1_COMMAND_WRITE,
        smb1::SMB1_COMMAND_LOCK_BYTE_RANGE,
        smb1::SMB1_COMMAND_UNLOCK_BYTE_RANGE,
        smb1::SMB1_COMMAND_CREATE_TEMPORARY,
        smb1::SMB1_COMMAND_CREATE_NEW,
        smb1::SMB1_COMMAND_CHECK_DIRECTORY,
        smb1::SMB1_COMMAND_PROCESS_EXIT,
        smb1::SMB1_COMMAND_SEEK,
        smb1::SMB1_COMMAND_LOCK_AND_READ,
        smb1::SMB1_COMMAND_WRITE_AND_UNLOCK,
        smb1::SMB1_COMMAND_READ_RAW,
        smb1::SMB1_COMMAND_READ_MPX,
        smb1::SMB1_COMMAND_READ_MPX_SECONDARY,
        smb1::SMB1_COMMAND_WRITE_RAW,
        smb1::SMB1_COMMAND_WRITE_MPX,
        smb1::SMB1_COMMAND_WRITE_MPX_SECONDARY,
        smb1::SMB1_COMMAND_WRITE_COMPLETE,
        smb1::SMB1_COMMAND_QUERY_SERVER,
        smb1::SMB1_COMMAND_SET_INFORMATION2,
        smb1::SMB1_COMMAND_QUERY_INFORMATION2,
        smb1::SMB1_COMMAND_LOCKING_ANDX,
        smb1::SMB1_COMMAND_TRANS,
        smb1::SMB1_COMMAND_TRANS_SECONDARY,
        smb1::SMB1_COMMAND_IOCTL,
        smb1::SMB1_COMMAND_IOCTL_SECONDARY,
        smb1::SMB1_COMMAND_COPY,
        smb1::SMB1_COMMAND_MOVE,
        smb1::SMB1_COMMAND_ECHO,
        smb1::SMB1_COMMAND_WRITE_AND_CLOSE,
        smb1::SMB1_COMMAND_OPEN_ANDX,
        smb1::SMB1_COMMAND_READ_ANDX,
        smb1::SMB1_COMMAND_WRITE_ANDX,
        smb1::SMB1_COMMAND_NEW_FILE_SIZE,
        smb1::SMB1_COMMAND_CLOSE_AND_TREE_DISC,
        smb1::SMB1_COMMAND_TRANS2,
        smb1::SMB1_COMMAND_TRANS2_SECONDARY,
        smb1::SMB1_COMMAND_FIND_CLOSE2,
        smb1::SMB1_COMMAND_FIND_NOTIFY_CLOSE,
        smb1::SMB1_COMMAND_TREE_CONNECT,
        smb1::SMB1_COMMAND_TREE_DISCONNECT,
        smb1::SMB1_COMMAND_NEGOTIATE_PROTOCOL,
        smb1::SMB1_COMMAND_SESSION_SETUP_ANDX,
        smb1::SMB1_COMMAND_LOGOFF_ANDX,
        smb1::SMB1_COMMAND_TREE_CONNECT_ANDX,
        smb1::SMB1_COMMAND_SECURITY_PACKAGE_ANDX,
        smb1::SMB1_COMMAND_QUERY_INFO_DISK,
        smb1::SMB1_COMMAND_SEARCH,
        smb1::SMB1_COMMAND_FIND,
        smb1::SMB1_COMMAND_FIND_UNIQUE,
        smb1::SMB1_COMMAND_FIND_CLOSE,
        smb1::SMB1_COMMAND_NT_TRANS,
        smb1::SMB1_COMMAND_NT_TRANS_SECONDARY,
        smb1::SMB1_COMMAND_NT_CREATE_ANDX,
        smb1::SMB1_COMMAND_NT_CANCEL,
        smb1::SMB1_COMMAND_NT_RENAME,
        smb1::SMB1_COMMAND_OPEN_PRINT_FILE,
        smb1::SMB1_COMMAND_WRITE_PRINT_FILE,
        smb1::SMB1_COMMAND_CLOSE_PRINT_FILE,
        smb1::SMB1_COMMAND_GET_PRINT_QUEUE,
        smb1::SMB1_COMMAND_READ_BULK,
        smb1::SMB1_COMMAND_WRITE_BULK,
        smb1::SMB1_COMMAND_WRITE_BULK_DATA,
        smb1::SMB1_COMMAND_INVALID,
        smb1::SMB1_COMMAND_NONE,
    ];

    let mut cmd_names1 = HashMap::new();

    for cmd in commands {
        cmd_names1.insert(smb1::smb1_command_string(cmd), cmd);
    }

    cmd_names1.insert(
        "create_directory".into(),
        smb1::SMB1_COMMAND_CREATE_DIRECTORY,
    );
    cmd_names1.insert(
        "delete_directory".into(),
        smb1::SMB1_COMMAND_DELETE_DIRECTORY,
    );
    cmd_names1.insert("open".into(), smb1::SMB1_COMMAND_OPEN);
    cmd_names1.insert("create".into(), smb1::SMB1_COMMAND_CREATE);
    cmd_names1.insert("close".into(), smb1::SMB1_COMMAND_CLOSE);
    cmd_names1.insert("flush".into(), smb1::SMB1_COMMAND_FLUSH);
    cmd_names1.insert("delete".into(), smb1::SMB1_COMMAND_DELETE);
    cmd_names1.insert("rename".into(), smb1::SMB1_COMMAND_RENAME);
    cmd_names1.insert(
        "query_information".into(),
        smb1::SMB1_COMMAND_QUERY_INFORMATION,
    );
    cmd_names1.insert("set_information".into(), smb1::SMB1_COMMAND_SET_INFORMATION);
    cmd_names1.insert("read".into(), smb1::SMB1_COMMAND_READ);
    cmd_names1.insert("write".into(), smb1::SMB1_COMMAND_WRITE);
    cmd_names1.insert("lock_byte_range".into(), smb1::SMB1_COMMAND_LOCK_BYTE_RANGE);
    cmd_names1.insert(
        "unlock_byte_range".into(),
        smb1::SMB1_COMMAND_UNLOCK_BYTE_RANGE,
    );
    cmd_names1.insert(
        "create_temporary".into(),
        smb1::SMB1_COMMAND_CREATE_TEMPORARY,
    );
    cmd_names1.insert("create_new".into(), smb1::SMB1_COMMAND_CREATE_NEW);
    cmd_names1.insert("check_directory".into(), smb1::SMB1_COMMAND_CHECK_DIRECTORY);
    cmd_names1.insert("process_exit".into(), smb1::SMB1_COMMAND_PROCESS_EXIT);
    cmd_names1.insert("seek".into(), smb1::SMB1_COMMAND_SEEK);
    cmd_names1.insert("lock_and_read".into(), smb1::SMB1_COMMAND_LOCK_AND_READ);
    cmd_names1.insert(
        "write_and_unlock".into(),
        smb1::SMB1_COMMAND_WRITE_AND_UNLOCK,
    );
    cmd_names1.insert("read_raw".into(), smb1::SMB1_COMMAND_READ_RAW);
    cmd_names1.insert("read_mpx".into(), smb1::SMB1_COMMAND_READ_MPX);
    cmd_names1.insert(
        "read_mpx_secondary".into(),
        smb1::SMB1_COMMAND_READ_MPX_SECONDARY,
    );
    cmd_names1.insert("write_raw".into(), smb1::SMB1_COMMAND_WRITE_RAW);
    cmd_names1.insert("write_mpx".into(), smb1::SMB1_COMMAND_WRITE_MPX);
    cmd_names1.insert(
        "write_mpx_secondary".into(),
        smb1::SMB1_COMMAND_WRITE_MPX_SECONDARY,
    );
    cmd_names1.insert("write_complete".into(), smb1::SMB1_COMMAND_WRITE_COMPLETE);
    cmd_names1.insert("query_server".into(), smb1::SMB1_COMMAND_QUERY_SERVER);
    cmd_names1.insert(
        "set_information2".into(),
        smb1::SMB1_COMMAND_SET_INFORMATION2,
    );
    cmd_names1.insert(
        "query_information2".into(),
        smb1::SMB1_COMMAND_QUERY_INFORMATION,
    );
    cmd_names1.insert("locking_andx".into(), smb1::SMB1_COMMAND_LOCKING_ANDX);
    cmd_names1.insert("transaction".into(), smb1::SMB1_COMMAND_TRANS);
    cmd_names1.insert(
        "transaction_secondary".into(),
        smb1::SMB1_COMMAND_TRANS_SECONDARY,
    );
    cmd_names1.insert("ioctl".into(), smb1::SMB1_COMMAND_IOCTL);
    cmd_names1.insert("ioctl_secondary".into(), smb1::SMB1_COMMAND_IOCTL_SECONDARY);
    cmd_names1.insert("copy".into(), smb1::SMB1_COMMAND_COPY);
    cmd_names1.insert("move".into(), smb1::SMB1_COMMAND_MOVE);
    cmd_names1.insert("echo".into(), smb1::SMB1_COMMAND_ECHO);
    cmd_names1.insert("write_and_close".into(), smb1::SMB1_COMMAND_WRITE_AND_CLOSE);
    cmd_names1.insert("open_andx".into(), smb1::SMB1_COMMAND_OPEN_ANDX);
    cmd_names1.insert("read_andx".into(), smb1::SMB1_COMMAND_READ_ANDX);
    cmd_names1.insert("write_andx".into(), smb1::SMB1_COMMAND_WRITE_ANDX);
    cmd_names1.insert("new_file_size".into(), smb1::SMB1_COMMAND_NEW_FILE_SIZE);
    cmd_names1.insert(
        "close_and_tree_disc".into(),
        smb1::SMB1_COMMAND_CLOSE_AND_TREE_DISC,
    );
    cmd_names1.insert("transaction2".into(), smb1::SMB1_COMMAND_TRANS2);
    cmd_names1.insert(
        "transaction2_secondary".into(),
        smb1::SMB1_COMMAND_TRANS2_SECONDARY,
    );
    cmd_names1.insert("find_close2".into(), smb1::SMB1_COMMAND_FIND_CLOSE2);
    cmd_names1.insert(
        "find_notify_close".into(),
        smb1::SMB1_COMMAND_FIND_NOTIFY_CLOSE,
    );
    cmd_names1.insert("tree_connect".into(), smb1::SMB1_COMMAND_TREE_CONNECT);
    cmd_names1.insert("tree_disconnect".into(), smb1::SMB1_COMMAND_TREE_DISCONNECT);
    cmd_names1.insert("negotiate".into(), smb1::SMB1_COMMAND_NEGOTIATE_PROTOCOL);
    cmd_names1.insert(
        "session_setup_andx".into(),
        smb1::SMB1_COMMAND_SESSION_SETUP_ANDX,
    );
    cmd_names1.insert("logoff_andx".into(), smb1::SMB1_COMMAND_LOGOFF_ANDX);
    cmd_names1.insert(
        "tree_connect_andx".into(),
        smb1::SMB1_COMMAND_TREE_CONNECT_ANDX,
    );
    cmd_names1.insert(
        "security_package_andx".into(),
        smb1::SMB1_COMMAND_SECURITY_PACKAGE_ANDX,
    );
    cmd_names1.insert(
        "query_information_disk".into(),
        smb1::SMB1_COMMAND_QUERY_INFO_DISK,
    );
    cmd_names1.insert("search".into(), smb1::SMB1_COMMAND_SEARCH);
    cmd_names1.insert("find".into(), smb1::SMB1_COMMAND_FIND);
    cmd_names1.insert("find_unique".into(), smb1::SMB1_COMMAND_FIND_UNIQUE);
    cmd_names1.insert("find_close".into(), smb1::SMB1_COMMAND_FIND_CLOSE);
    cmd_names1.insert("nt_transact".into(), smb1::SMB1_COMMAND_NT_TRANS);
    cmd_names1.insert(
        "nt_transact_secondary".into(),
        smb1::SMB1_COMMAND_NT_TRANS_SECONDARY,
    );
    cmd_names1.insert("nt_create_andx".into(), smb1::SMB1_COMMAND_NT_CREATE_ANDX);
    cmd_names1.insert("nt_cancel".into(), smb1::SMB1_COMMAND_NT_CANCEL);
    cmd_names1.insert("nt_rename".into(), smb1::SMB1_COMMAND_NT_RENAME);
    cmd_names1.insert("open_print_file".into(), smb1::SMB1_COMMAND_OPEN_PRINT_FILE);
    cmd_names1.insert(
        "write_print_file".into(),
        smb1::SMB1_COMMAND_WRITE_PRINT_FILE,
    );
    cmd_names1.insert(
        "close_print_file".into(),
        smb1::SMB1_COMMAND_CLOSE_PRINT_FILE,
    );
    cmd_names1.insert("get_print_queue".into(), smb1::SMB1_COMMAND_GET_PRINT_QUEUE);
    cmd_names1.insert("read_bulk".into(), smb1::SMB1_COMMAND_READ_BULK);
    cmd_names1.insert("write_bulk".into(), smb1::SMB1_COMMAND_WRITE_BULK);
    cmd_names1.insert("write_bulk_data".into(), smb1::SMB1_COMMAND_WRITE_BULK_DATA);
    cmd_names1.insert("invalid".into(), smb1::SMB1_COMMAND_INVALID);
    cmd_names1.insert("no_andx_command".into(), smb1::SMB1_COMMAND_NONE);

    return cmd_names1.into_iter().map(|(k, v)| (k, v.into())).collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cmd_data() {
        let option = "5,negotiate, 0x8";

        let cmd_names1 = gen_smb1_command_names();
        let cmd_names2 = gen_smb2_command_names();

        let mut cmd_codes1 = HashSet::new();
        cmd_codes1.insert(5);
        cmd_codes1.insert(*cmd_names1.get("negotiate").unwrap());
        cmd_codes1.insert(0x8);

        let mut cmd_codes2 = HashSet::new();
        cmd_codes2.insert(5);
        cmd_codes2.insert(*cmd_names2.get("negotiate").unwrap());
        cmd_codes2.insert(0x8);

        assert_eq!(
            SmbCmdValidCodes::new(cmd_codes1, cmd_codes2),
            parse_cmd_data(option).unwrap(),
        );
    }
}
