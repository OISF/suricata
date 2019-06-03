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

// written by Clément Galland <clement.galland@epita.fr>

use json::*;
use tftp::tftp::*;

#[no_mangle]
pub extern "C" fn rs_tftp_log_json_request(tx: &mut TFTPTransaction) -> *mut JsonT
{
    let js = Json::object();
    match tx.opcode {
        1 => js.set_string("packet", "read"),
        2 => js.set_string("packet", "write"),
        _ => js.set_string("packet", "error")
    };
    js.set_string("file", tx.filename.as_str());
    js.set_string("mode", tx.mode.as_str());
    js.unwrap()
}
