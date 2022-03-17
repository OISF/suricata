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
    tx: &mut SMBTransaction, cmd_data: &mut SmbCmdData,
) -> u8 {

    let version = tx.vercmd.get_version();
    let cmd;
    if version == 1 {
        cmd = tx.vercmd.get_smb1_cmd().1.into();
    } else {
        cmd = tx.vercmd.get_smb2_cmd().1;
    }

    SCLogDebug!("rs_smb_cmd_match: version {} cmd {}", version, cmd);

    if let Some(set) = cmd_data.0.get(&version) {
        if set.contains(&cmd) {
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
        std::mem::drop(Box::from_raw(ptr as *mut SmbCmdData));
    }
}

#[derive(Debug, PartialEq)]
pub struct SmbCmdData (HashMap<u8, HashSet<u16>>);

impl SmbCmdData {

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


fn parse_cmd_data(arg: &str) -> Result<SmbCmdData, ()> {

    let cmd_names1 = gen_smb1_command_names();
    let cmd_names2 = gen_smb2_command_names();


    let split_args: Vec<&str> = arg.split(',').collect();

    let mut cmd_codes1 = HashSet::new();
    let mut cmd_codes2 = HashSet::new();

    for cmd in split_args.iter() {
        let cmd = cmd.trim();

        match str_to_u16(cmd) {
            Ok(cmd_code) =>  {
                cmd_codes1.insert(cmd_code);
                cmd_codes2.insert(cmd_code);
            }
            Err(_) => {
                let mut in_any = false;
                if let Some(cmd_code) = cmd_names1.get(cmd) {
                    cmd_codes1.insert(*cmd_code);
                    in_any = true;
                }

                if let Some(cmd_code) = cmd_names2.get(cmd) {
                    cmd_codes2.insert(*cmd_code);
                    in_any = true;
                }

                if !in_any {
                    return Err(());
                }
            }
        }

    }
    return Ok(SmbCmdData::new(cmd_codes1, cmd_codes2));
}

fn gen_smb2_command_names() -> HashMap<&'static str, u16> {
    let mut cmd_names2 = HashMap::new();
    cmd_names2.insert("negotiate", smb2::SMB2_COMMAND_NEGOTIATE_PROTOCOL);
    cmd_names2.insert("session_setup", smb2::SMB2_COMMAND_SESSION_SETUP);
    cmd_names2.insert("logoff", smb2::SMB2_COMMAND_SESSION_LOGOFF);
    cmd_names2.insert("tree_connect", smb2::SMB2_COMMAND_TREE_CONNECT);
    cmd_names2.insert("tree_disconnect", smb2::SMB2_COMMAND_TREE_DISCONNECT);
    cmd_names2.insert("create", smb2::SMB2_COMMAND_CREATE);
    cmd_names2.insert("close", smb2::SMB2_COMMAND_CLOSE);
    cmd_names2.insert("flush", smb2::SMB2_COMMAND_FLUSH);
    cmd_names2.insert("read", smb2::SMB2_COMMAND_READ);
    cmd_names2.insert("write", smb2::SMB2_COMMAND_WRITE);
    cmd_names2.insert("lock", smb2::SMB2_COMMAND_LOCK);
    cmd_names2.insert("ioctl", smb2::SMB2_COMMAND_IOCTL);
    cmd_names2.insert("cancel", smb2::SMB2_COMMAND_CANCEL);
    cmd_names2.insert("echo", smb2::SMB2_COMMAND_KEEPALIVE);
    cmd_names2.insert("keep_alive", smb2::SMB2_COMMAND_KEEPALIVE);
    cmd_names2.insert("find", smb2::SMB2_COMMAND_FIND);
    cmd_names2.insert("query_directory", smb2::SMB2_COMMAND_FIND);
    cmd_names2.insert("change_notify", smb2::SMB2_COMMAND_CHANGE_NOTIFY);
    cmd_names2.insert("query_info", smb2::SMB2_COMMAND_GET_INFO);
    cmd_names2.insert("set_info", smb2::SMB2_COMMAND_SET_INFO);
    cmd_names2.insert("oplock_break", smb2::SMB2_COMMAND_OPLOCK_BREAK);

    return cmd_names2;
}

fn gen_smb1_command_names() -> HashMap<&'static str, u16> {
    let mut cmd_names1 = HashMap::new();
    cmd_names1.insert("create_directory", smb1::SMB1_COMMAND_CREATE_DIRECTORY);
    cmd_names1.insert("delete_directory", smb1::SMB1_COMMAND_DELETE_DIRECTORY);
    cmd_names1.insert("open", smb1::SMB1_COMMAND_OPEN);
    cmd_names1.insert("create", smb1::SMB1_COMMAND_CREATE);
    cmd_names1.insert("close", smb1::SMB1_COMMAND_CLOSE);
    cmd_names1.insert("flush", smb1::SMB1_COMMAND_FLUSH);
    cmd_names1.insert("delete", smb1::SMB1_COMMAND_DELETE);
    cmd_names1.insert("rename", smb1::SMB1_COMMAND_RENAME);
    cmd_names1.insert("query_information", smb1::SMB1_COMMAND_QUERY_INFORMATION);
    cmd_names1.insert("set_information", smb1::SMB1_COMMAND_SET_INFORMATION);
    cmd_names1.insert("read", smb1::SMB1_COMMAND_READ);
    cmd_names1.insert("write", smb1::SMB1_COMMAND_WRITE);
    cmd_names1.insert("lock_byte_range", smb1::SMB1_COMMAND_LOCK_BYTE_RANGE);
    cmd_names1.insert("unlock_byte_range", smb1::SMB1_COMMAND_UNLOCK_BYTE_RANGE);
    cmd_names1.insert("create_temporary", smb1::SMB1_COMMAND_CREATE_TEMPORARY);
    cmd_names1.insert("create_new", smb1::SMB1_COMMAND_CREATE_NEW);
    cmd_names1.insert("check_directory", smb1::SMB1_COMMAND_CHECK_DIRECTORY);
    cmd_names1.insert("process_exit", smb1::SMB1_COMMAND_PROCESS_EXIT);
    cmd_names1.insert("seek", smb1::SMB1_COMMAND_SEEK);
    cmd_names1.insert("lock_and_read", smb1::SMB1_COMMAND_LOCK_AND_READ);
    cmd_names1.insert("write_and_unlock", smb1::SMB1_COMMAND_WRITE_AND_UNLOCK);
    cmd_names1.insert("read_raw", smb1::SMB1_COMMAND_READ_RAW);
    cmd_names1.insert("read_mpx", smb1::SMB1_COMMAND_READ_MPX);
    cmd_names1.insert("read_mpx_secondary", smb1::SMB1_COMMAND_READ_MPX_SECONDARY);
    cmd_names1.insert("write_raw", smb1::SMB1_COMMAND_WRITE_RAW);
    cmd_names1.insert("write_mpx", smb1::SMB1_COMMAND_WRITE_MPX);
    cmd_names1.insert("write_mpx_secondary", smb1::SMB1_COMMAND_WRITE_MPX_SECONDARY);
    cmd_names1.insert("write_complete", smb1::SMB1_COMMAND_WRITE_COMPLETE);
    cmd_names1.insert("query_server", smb1::SMB1_COMMAND_QUERY_SERVER);
    cmd_names1.insert("set_information2", smb1::SMB1_COMMAND_SET_INFORMATION2);
    cmd_names1.insert("query_information2", smb1::SMB1_COMMAND_QUERY_INFORMATION);
    cmd_names1.insert("locking_andx", smb1::SMB1_COMMAND_LOCKING_ANDX);
    cmd_names1.insert("transaction", smb1::SMB1_COMMAND_TRANS);
    cmd_names1.insert("transaction_secondary", smb1::SMB1_COMMAND_TRANS_SECONDARY);
    cmd_names1.insert("ioctl", smb1::SMB1_COMMAND_IOCTL);
    cmd_names1.insert("ioctl_secondary", smb1::SMB1_COMMAND_IOCTL_SECONDARY);
    cmd_names1.insert("copy", smb1::SMB1_COMMAND_COPY);
    cmd_names1.insert("move", smb1::SMB1_COMMAND_MOVE);
    cmd_names1.insert("echo", smb1::SMB1_COMMAND_ECHO);
    cmd_names1.insert("write_and_close", smb1::SMB1_COMMAND_WRITE_AND_CLOSE);
    cmd_names1.insert("open_andx", smb1::SMB1_COMMAND_OPEN_ANDX);
    cmd_names1.insert("read_andx", smb1::SMB1_COMMAND_READ_ANDX);
    cmd_names1.insert("write_andx", smb1::SMB1_COMMAND_WRITE_ANDX);
    cmd_names1.insert("new_file_size", smb1::SMB1_COMMAND_NEW_FILE_SIZE);
    cmd_names1.insert("close_and_tree_disc", smb1::SMB1_COMMAND_CLOSE_AND_TREE_DISC);
    cmd_names1.insert("transaction2", smb1::SMB1_COMMAND_TRANS2);
    cmd_names1.insert("transaction2_secondary", smb1::SMB1_COMMAND_TRANS2_SECONDARY);
    cmd_names1.insert("find_close2", smb1::SMB1_COMMAND_FIND_CLOSE2);
    cmd_names1.insert("find_notify_close", smb1::SMB1_COMMAND_FIND_NOTIFY_CLOSE);
    cmd_names1.insert("tree_connect", smb1::SMB1_COMMAND_TREE_CONNECT);
    cmd_names1.insert("tree_disconnect", smb1::SMB1_COMMAND_TREE_DISCONNECT);
    cmd_names1.insert("negotiate", smb1::SMB1_COMMAND_NEGOTIATE_PROTOCOL);
    cmd_names1.insert("session_setup_andx", smb1::SMB1_COMMAND_SESSION_SETUP_ANDX);
    cmd_names1.insert("logoff_andx", smb1::SMB1_COMMAND_LOGOFF_ANDX);
    cmd_names1.insert("tree_connect_andx", smb1::SMB1_COMMAND_TREE_CONNECT_ANDX);
    cmd_names1.insert("security_package_andx", smb1::SMB1_COMMAND_SECURITY_PACKAGE_ANDX);
    cmd_names1.insert("query_information_disk", smb1::SMB1_COMMAND_QUERY_INFO_DISK);
    cmd_names1.insert("search", smb1::SMB1_COMMAND_SEARCH);
    cmd_names1.insert("find", smb1::SMB1_COMMAND_FIND);
    cmd_names1.insert("find_unique", smb1::SMB1_COMMAND_FIND_UNIQUE);
    cmd_names1.insert("find_close", smb1::SMB1_COMMAND_FIND_CLOSE);
    cmd_names1.insert("nt_transact", smb1::SMB1_COMMAND_NT_TRANS);
    cmd_names1.insert("nt_transact_secondary", smb1::SMB1_COMMAND_NT_TRANS_SECONDARY);
    cmd_names1.insert("nt_create_andx", smb1::SMB1_COMMAND_NT_CREATE_ANDX);
    cmd_names1.insert("nt_cancel", smb1::SMB1_COMMAND_NT_CANCEL);
    cmd_names1.insert("nt_rename", smb1::SMB1_COMMAND_NT_RENAME);
    cmd_names1.insert("open_print_file", smb1::SMB1_COMMAND_OPEN_PRINT_FILE);
    cmd_names1.insert("write_print_file", smb1::SMB1_COMMAND_WRITE_PRINT_FILE);
    cmd_names1.insert("close_print_file", smb1::SMB1_COMMAND_CLOSE_PRINT_FILE);
    cmd_names1.insert("get_print_queue", smb1::SMB1_COMMAND_GET_PRINT_QUEUE);
    cmd_names1.insert("read_bulk", smb1::SMB1_COMMAND_READ_BULK);
    cmd_names1.insert("write_bulk", smb1::SMB1_COMMAND_WRITE_BULK);
    cmd_names1.insert("write_bulk_data", smb1::SMB1_COMMAND_WRITE_BULK_DATA);
    cmd_names1.insert("invalid", smb1::SMB1_COMMAND_INVALID);
    cmd_names1.insert("no_andx_command", smb1::SMB1_COMMAND_NONE);

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
            SmbCmdData::new(cmd_codes1, cmd_codes2),
            parse_cmd_data(option).unwrap(),
        );
    }
}
