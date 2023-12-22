/* Copyright (C) 2023 Open Information Security Foundation
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

use super::websocket::WebSocketTransaction;
use crate::detect::uint::DetectUintData;
use crate::websocket::parser::WebSocketOpcode;
use std::ffi::CStr;

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetOpcode(tx: &mut WebSocketTransaction) -> u8 {
    return WebSocketOpcode::into_u(&tx.pdu.opcode);
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetFin(tx: &mut WebSocketTransaction) -> bool {
    return tx.pdu.fin;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetPayload(
    tx: &WebSocketTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    *buffer = tx.pdu.payload.as_ptr();
    *buffer_len = tx.pdu.payload.len() as u32;
    return true;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetMask(
    tx: &mut WebSocketTransaction, value: *mut u32,
) -> bool {
    if let Some(xorkey) = tx.pdu.mask {
        *value = xorkey;
        return true;
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketParseOpcode(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = WebSocketOpcode::to_detect_ctx(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}
