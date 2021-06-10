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
use crate::detect::detect_match_uint;

use md5::Digest;

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
            if let Some(x) = &dce_data.du16 {
                if detect_match_uint(&x, i.ver) {
                    return 1;
                }
            } else {
                return 1;
            }
        }
    }
    return 0;
}

pub fn smb_get_fingerprint(state: &SMBState, tx : &SMBTransaction, outbuf: &mut [u8; 16]) -> Result<(), ()> {
    match tx.type_data {
        Some(SMBTransactionTypeData::SESSIONSETUP(ref _x)) => {
            if state.fingerprint_state == SMBFingerprintState::Finished {
                let result = state.fingerprint_hasher.clone();
                let rs1 = result.finalize();
                let rs2 = rs1.as_slice();
                outbuf.clone_from_slice(rs2);
                return Ok(());
            }
        }
        _ => {}
    }
    return Err(());
}

#[no_mangle]
pub extern "C" fn rs_smb_get_fingerprint(
    state: &mut SMBState, tx: &mut SMBTransaction, outbuf: &mut [u8; 16],
) -> std::os::raw::c_int {
    if let Ok(_) = smb_get_fingerprint(&state, &tx, outbuf) {
        return 0;
    }
    return -1;
}
