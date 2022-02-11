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
        cmd = tx.vercmd.get_smb1_cmd().1 as u16;
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
    cmd_names2.insert("negotiate", 0u16);
    cmd_names2.insert("session_setup", 1u16);
    cmd_names2.insert("logoff", 2u16);
    cmd_names2.insert("tree_connect", 3u16);
    cmd_names2.insert("tree_disconnect", 4u16);
    cmd_names2.insert("create", 5u16);
    cmd_names2.insert("close", 6u16);
    cmd_names2.insert("flush", 7u16);
    cmd_names2.insert("read", 8u16);
    cmd_names2.insert("write", 9u16);
    cmd_names2.insert("lock", 0xau16);
    cmd_names2.insert("ioctl", 0xbu16);
    cmd_names2.insert("cancel", 0xcu16);
    cmd_names2.insert("echo", 0xdu16);
    cmd_names2.insert("query_directory", 0xeu16);
    cmd_names2.insert("change_notify", 0xfu16);
    cmd_names2.insert("query_info", 0x10u16);
    cmd_names2.insert("set_info", 0x11u16);
    cmd_names2.insert("oplock_break", 0x12u16);

    return cmd_names2;
}

fn gen_smb1_command_names() -> HashMap<&'static str, u16> {
    let mut cmd_names1 = HashMap::new();
    cmd_names1.insert("create_directory", 0x00u16);
    cmd_names1.insert("delete_directory", 0x01u16);
    cmd_names1.insert("open", 0x02u16);
    cmd_names1.insert("create", 0x03u16);
    cmd_names1.insert("close", 0x04u16);
    cmd_names1.insert("flush", 0x05u16);
    cmd_names1.insert("delete", 0x06u16);
    cmd_names1.insert("rename", 0x07u16);
    cmd_names1.insert("query_information", 0x08u16);
    cmd_names1.insert("set_information", 0x09u16);
    cmd_names1.insert("read", 0x0Au16);
    cmd_names1.insert("write", 0x0Bu16);
    cmd_names1.insert("lock_byte_range", 0x0Cu16);
    cmd_names1.insert("unlock_byte_range", 0x0Du16);
    cmd_names1.insert("create_temporary", 0x0Eu16);
    cmd_names1.insert("create_new", 0x0Fu16);
    cmd_names1.insert("check_directory", 0x10u16);
    cmd_names1.insert("process_exit", 0x11u16);
    cmd_names1.insert("seek", 0x12u16);
    cmd_names1.insert("lock_and_read", 0x13u16);
    cmd_names1.insert("write_and_unlock", 0x14u16);
    cmd_names1.insert("read_raw", 0x1Au16);
    cmd_names1.insert("read_mpx", 0x1Bu16);
    cmd_names1.insert("read_mpx_secondary", 0x1Cu16);
    cmd_names1.insert("write_raw", 0x1Du16);
    cmd_names1.insert("write_mpx", 0x1Eu16);
    cmd_names1.insert("write_mpx_secondary", 0x1Fu16);
    cmd_names1.insert("write_complete", 0x20u16);
    cmd_names1.insert("query_server", 0x21u16);
    cmd_names1.insert("set_information2", 0x22u16);
    cmd_names1.insert("query_information2", 0x23u16);
    cmd_names1.insert("locking_andx", 0x24u16);
    cmd_names1.insert("transaction", 0x25u16);
    cmd_names1.insert("transaction_secondary", 0x26u16);
    cmd_names1.insert("ioctl", 0x27u16);
    cmd_names1.insert("ioctl_secondary", 0x28u16);
    cmd_names1.insert("copy", 0x29u16);
    cmd_names1.insert("move", 0x2Au16);
    cmd_names1.insert("echo", 0x2Bu16);
    cmd_names1.insert("write_and_close", 0x2Cu16);
    cmd_names1.insert("open_andx", 0x2Du16);
    cmd_names1.insert("read_andx", 0x2Eu16);
    cmd_names1.insert("write_andx", 0x2Fu16);
    cmd_names1.insert("new_file_size", 0x30u16);
    cmd_names1.insert("close_and_tree_disc", 0x31u16);
    cmd_names1.insert("transaction2", 0x32u16);
    cmd_names1.insert("transaction2_secondary", 0x33u16);
    cmd_names1.insert("find_close2", 0x34u16);
    cmd_names1.insert("find_notify_close", 0x35u16);
    cmd_names1.insert("tree_connect", 0x70u16);
    cmd_names1.insert("tree_disconnect", 0x71u16);
    cmd_names1.insert("negotiate", 0x72u16);
    cmd_names1.insert("session_setup_andx", 0x73u16);
    cmd_names1.insert("logoff_andx", 0x74u16);
    cmd_names1.insert("tree_connect_andx", 0x75u16);
    cmd_names1.insert("security_package_andx", 0x7Eu16);
    cmd_names1.insert("query_information_disk", 0x80u16);
    cmd_names1.insert("search", 0x81u16);
    cmd_names1.insert("find", 0x82u16);
    cmd_names1.insert("find_unique", 0x83u16);
    cmd_names1.insert("find_close", 0x84u16);
    cmd_names1.insert("nt_transact", 0xA0u16);
    cmd_names1.insert("nt_transact_secondary", 0xA1u16);
    cmd_names1.insert("nt_create_andx", 0xA2u16);
    cmd_names1.insert("nt_cancel", 0xA4u16);
    cmd_names1.insert("nt_rename", 0xA5u16);
    cmd_names1.insert("open_print_file", 0xC0u16);
    cmd_names1.insert("write_print_file", 0xC1u16);
    cmd_names1.insert("close_print_file", 0xC2u16);
    cmd_names1.insert("get_print_queue", 0xC3u16);
    cmd_names1.insert("read_bulk", 0xD8u16);
    cmd_names1.insert("write_bulk", 0xD9u16);
    cmd_names1.insert("write_bulk_data", 0xDAu16);
    cmd_names1.insert("invalid", 0xFEu16);
    cmd_names1.insert("no_andx_command", 0xFFu16);

    return cmd_names1;
}
