/* Copyright (C) 2017-2023 Open Information Security Foundation
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

use crate::dcerpc::dcerpc::DCERPC_TYPE_REQUEST;
use crate::dcerpc::detect::{DCEIfaceData, DCEOpnumData, DETECT_DCE_OPNUM_RANGE_UNINITIALIZED};
use crate::detect::uint::detect_match_uint;
use crate::direction::Direction;
use crate::smb::smb::*;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;

#[no_mangle]
pub unsafe extern "C" fn SCSmbTxGetShare(
    tx: &SMBTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(SMBTransactionTypeData::TREECONNECT(ref x)) = tx.type_data {
        SCLogDebug!("is_pipe {}", x.is_pipe);
        if !x.is_pipe {
            *buffer = x.share_name.as_ptr();
            *buffer_len = x.share_name.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCSmbTxGetNamedPipe(
    tx: &SMBTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(SMBTransactionTypeData::TREECONNECT(ref x)) = tx.type_data {
        SCLogDebug!("is_pipe {}", x.is_pipe);
        if x.is_pipe {
            *buffer = x.share_name.as_ptr();
            *buffer_len = x.share_name.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCSmbTxGetStubData(
    tx: &SMBTransaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(SMBTransactionTypeData::DCERPC(ref x)) = tx.type_data {
        let vref = if direction == Direction::ToServer as u8 {
            &x.stub_data_ts
        } else {
            &x.stub_data_tc
        };
        if !vref.is_empty() {
            *buffer = vref.as_ptr();
            *buffer_len = vref.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub extern "C" fn SCSmbTxMatchDceOpnum(
    tx: &SMBTransaction, dce_data: &mut DCEOpnumData,
) -> u8 {
    SCLogDebug!("SCSmbTxMatchDceOpnum: start");
    if let Some(SMBTransactionTypeData::DCERPC(ref x)) = tx.type_data {
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

    return 0;
}

/* mimic logic that is/was in the C code:
 * - match on REQUEST (so not on BIND/BINDACK (probably for mixing with
 *                     dce_opnum and dce_stub_data)
 * - only match on approved ifaces (so ack_result == 0) */
#[no_mangle]
pub extern "C" fn SCSmbTxGetDceIface(
    state: &mut SMBState, tx: &SMBTransaction, dce_data: &mut DCEIfaceData,
) -> u8 {
    let if_uuid = dce_data.if_uuid.as_slice();
    let is_dcerpc_request = match tx.type_data {
        Some(SMBTransactionTypeData::DCERPC(ref x)) => x.req_cmd == DCERPC_TYPE_REQUEST,
        _ => false,
    };
    if !is_dcerpc_request {
        return 0;
    }
    let ifaces = match state.dcerpc_ifaces {
        Some(ref x) => x,
        _ => {
            return 0;
        }
    };

    SCLogDebug!("looking for UUID {:?}", if_uuid);

    for i in ifaces {
        SCLogDebug!(
            "stored UUID {:?} acked {} ack_result {}",
            i,
            i.acked,
            i.ack_result
        );

        if i.acked && i.ack_result == 0 && i.uuid == if_uuid {
            if let Some(x) = &dce_data.du16 {
                if detect_match_uint(x, i.ver) {
                    return 1;
                }
            } else {
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCSmbTxGetNtlmsspUser(
    tx: &SMBTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(SMBTransactionTypeData::SESSIONSETUP(ref x)) = tx.type_data {
        if let Some(ref ntlmssp) = x.ntlmssp {
            *buffer = ntlmssp.user.as_ptr();
            *buffer_len = ntlmssp.user.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCSmbTxGetNtlmsspDomain(
    tx: &SMBTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(SMBTransactionTypeData::SESSIONSETUP(ref x)) = tx.type_data {
        if let Some(ref ntlmssp) = x.ntlmssp {
            *buffer = ntlmssp.domain.as_ptr();
            *buffer_len = ntlmssp.domain.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCSmbVersionMatch(tx: &SMBTransaction, version_data: &mut u8) -> u8 {
    let version = tx.vercmd.get_version();
    SCLogDebug!("smb_version: version returned: {}", version);
    if version == *version_data {
        return 1;
    }

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCSmbVersionParse(carg: *const c_char) -> *mut c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }

    if let Ok(arg) = CStr::from_ptr(carg).to_str() {
        if let Ok(detect) = parse_version_data(arg) {
            return Box::into_raw(Box::new(detect)) as *mut _;
        }
    }

    return std::ptr::null_mut();
}

fn parse_version_data(arg: &str) -> Result<u8, ()> {
    let arg = arg.trim();
    let version: u8 = arg.parse().map_err(|_| ())?;

    SCLogDebug!("smb_version: sig parse arg: {} version: {}", arg, version);

    if version != 1 && version != 2 {
        return Err(());
    }

    return Ok(version);
}

#[no_mangle]
pub unsafe extern "C" fn SCSmbVersionFree(ptr: *mut c_void) {
    std::mem::drop(Box::from_raw(ptr as *mut u8));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cmd_data() {
        assert_eq!(Err(()), parse_version_data("0"));
        assert_eq!(1u8, parse_version_data("1").unwrap());
        assert_eq!(2u8, parse_version_data("2").unwrap());
        assert_eq!(Err(()), parse_version_data("3"));
    }

    #[test]
    fn test_parse_cmd_data_with_spaces() {
        assert_eq!(1u8, parse_version_data(" 1").unwrap());
        assert_eq!(2u8, parse_version_data(" 2 ").unwrap());
    }
}
