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

use std;
use std::ptr;
use crate::core::*;
use crate::smb::smb::*;
use crate::smb::dcerpc::DCERPC_TYPE_REQUEST;

#[no_mangle]
pub extern "C" fn rs_smb_tx_get_share(tx: &mut SMBTransaction,
                                            buffer: *mut *const u8,
                                            buffer_len: *mut u32)
                                            -> u8
{
    match tx.type_data {
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            SCLogDebug!("is_pipe {}", x.is_pipe);
            if !x.is_pipe {
                unsafe {
                    *buffer = x.share_name.as_ptr();
                    *buffer_len = x.share_name.len() as u32;
                    return 1;
                }
            }
        }
        _ => {
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_get_named_pipe(tx: &mut SMBTransaction,
                                            buffer: *mut *const u8,
                                            buffer_len: *mut u32)
                                            -> u8
{
    match tx.type_data {
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            SCLogDebug!("is_pipe {}", x.is_pipe);
            if x.is_pipe {
                unsafe {
                    *buffer = x.share_name.as_ptr();
                    *buffer_len = x.share_name.len() as u32;
                    return 1;
                }
            }
        }
        _ => {
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_get_stub_data(tx: &mut SMBTransaction,
                                            direction: u8,
                                            buffer: *mut *const u8,
                                            buffer_len: *mut u32)
                                            -> u8
{
    match tx.type_data {
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            let vref = if direction == STREAM_TOSERVER {
                &x.stub_data_ts
            } else {
                &x.stub_data_tc
            };
            if vref.len() > 0 {
                unsafe {
                    *buffer = vref.as_ptr();
                    *buffer_len = vref.len() as u32;
                    return 1;
                }
            }
        }
        _ => {
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_smb_tx_get_dce_opnum(tx: &mut SMBTransaction,
                                            opnum: *mut u16)
                                            -> u8
{
    SCLogDebug!("rs_smb_tx_get_dce_opnum: start");
    match tx.type_data {
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            if x.req_cmd == DCERPC_TYPE_REQUEST {
                unsafe {
                    *opnum = x.opnum as u16;
                    return 1;
                }
            }
        }
        _ => {
        }
    }

    unsafe {
        *opnum = 0;
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
                                            uuid_ptr: *mut u8,
                                            uuid_len: u16,
                                            ver_op: u8,
                                            ver_check: u16)
                                            -> u8
{
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

    let uuid = unsafe{std::slice::from_raw_parts(uuid_ptr, uuid_len as usize)};
    SCLogDebug!("looking for UUID {:?}", uuid);

    for i in ifaces {
        SCLogDebug!("stored UUID {:?} acked {} ack_result {}", i, i.acked, i.ack_result);

        if i.acked && i.ack_result == 0 && i.uuid == uuid {
            if match_version(ver_op as u8, ver_check as u16, i.ver) {
                return 1;
            }
        }
    }
    return 0;
}
