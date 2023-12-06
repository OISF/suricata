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

use super::websockets::WebSocketsTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

//TODOws detection on opcode and mask, and payload buffer
//TODOws json schema + SV test

fn ws_opcode_string(p: u8) -> Option<&'static str> {
    match p {
        0 => Some("continuation"),
        1 => Some("text"),
        2 => Some("binary"),
        8 => Some("connection_close"),
        9 => Some("ping"),
        0xa => Some("pong"),
        _ => None,
    }
}

fn log_websockets(tx: &WebSocketsTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("websockets")?;
    js.set_bool("mask", tx.pdu.mask)?;
    if let Some(val) = ws_opcode_string(tx.pdu.opcode) {
        js.set_string("opcode", val)?;
    } else {
        js.set_string("opcode", &format!("unknown-{}", tx.pdu.opcode))?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_websockets_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, WebSocketsTransaction);
    log_websockets(tx, js).is_ok()
}
