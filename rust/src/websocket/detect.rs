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
use super::logger::web_socket_opcode_parse;
use crate::detect::uint::{detect_parse_uint, DetectUintData, DetectUintMode};
use std::ffi::CStr;

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetOpcode(tx: &mut WebSocketTransaction) -> u8 {
    return tx.pdu.opcode;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetMask(tx: &mut WebSocketTransaction) -> bool {
    return tx.pdu.mask;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketParseOpcode(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
        if let Some(arg1) = web_socket_opcode_parse(s) {
            let ctx = DetectUintData::<u8> {
                arg1,
                arg2: 0,
                mode: DetectUintMode::DetectUintModeEqual,
            };
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}
