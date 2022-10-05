/* Copyright (C) 2020 Open Information Security Foundation
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

use super::ssh::SSHTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_ssh(tx: &SSHTransaction, js: &mut JsonBuilder) -> Result<bool, JsonError> {
    if tx.cli_hdr.protover.is_empty() && tx.srv_hdr.protover.is_empty() {
        return Ok(false);
    }
    if !tx.cli_hdr.protover.is_empty() {
        js.open_object("client")?;
        js.set_string_from_bytes("proto_version", &tx.cli_hdr.protover)?;
        if !tx.cli_hdr.swver.is_empty() {
            js.set_string_from_bytes("software_version", &tx.cli_hdr.swver)?;
        }
        if !tx.cli_hdr.hassh.is_empty() || !tx.cli_hdr.hassh_string.is_empty() {
            js.open_object("hassh")?;
            if !tx.cli_hdr.hassh.is_empty() {
                js.set_string_from_bytes("hash", &tx.cli_hdr.hassh)?;
            }
            if !tx.cli_hdr.hassh_string.is_empty() {
                js.set_string_from_bytes("string", &tx.cli_hdr.hassh_string)?;
            }
            js.close()?;
        }
        js.close()?;
    }
    if !tx.srv_hdr.protover.is_empty() {
        js.open_object("server")?;
        js.set_string_from_bytes("proto_version", &tx.srv_hdr.protover)?;
        if !tx.srv_hdr.swver.is_empty() {
            js.set_string_from_bytes("software_version", &tx.srv_hdr.swver)?;
        }
        if !tx.srv_hdr.hassh.is_empty() || !tx.srv_hdr.hassh_string.is_empty() {
            js.open_object("hassh")?;
            if !tx.srv_hdr.hassh.is_empty() {
                js.set_string_from_bytes("hash", &tx.srv_hdr.hassh)?;
            }
            if !tx.srv_hdr.hassh_string.is_empty() {
                js.set_string_from_bytes("string", &tx.srv_hdr.hassh_string)?;
            }
            js.close()?;
        }
        js.close()?;
    }
    Ok(true)
}

#[no_mangle]
pub unsafe extern "C" fn rs_ssh_log_json(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    if let Ok(x) = log_ssh(tx, js) {
        return x;
    }
    false
}
