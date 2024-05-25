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

use super::parser::WebSocketOpcode;
use super::websocket::WebSocketTransaction;
use crate::detect::EnumString;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_websocket(
    tx: &WebSocketTransaction, js: &mut JsonBuilder, pp: bool, pb64: bool,
) -> Result<(), JsonError> {
    js.open_object("websocket")?;
    js.set_bool("fin", tx.pdu.fin)?;
    if let Some(xorkey) = tx.pdu.mask {
        js.set_uint("mask", xorkey.into())?;
    }
    if let Some(opcode) = WebSocketOpcode::from_u(tx.pdu.opcode) {
        js.set_string("opcode", opcode.to_str())?;
    } else {
        js.set_string("opcode", &format!("unknown-{}", tx.pdu.opcode))?;
    }
    if pp {
        js.set_string(
            "payload_printable",
            &String::from_utf8_lossy(&tx.pdu.payload),
        )?;
    }
    if pb64 {
        js.set_base64("payload_base64", &tx.pdu.payload)?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_websocket_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder, _: *mut std::os::raw::c_void
) -> bool {
    let tx = cast_pointer!(tx, WebSocketTransaction);
    log_websocket(tx, js, false, false).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketLogDetails(
    tx: &WebSocketTransaction, js: &mut JsonBuilder, pp: bool, pb64: bool,
) -> bool {
    log_websocket(tx, js, pp, pb64).is_ok()
}
