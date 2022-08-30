/* Copyright (C) 2017-2022 Open Information Security Foundation
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

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::tftp::tftp::TFTPTransaction;

fn tftp_log_request(tx: &mut TFTPTransaction,
                    jb: &mut JsonBuilder)
                    -> Result<(), JsonError>
{
    match tx.opcode {
        1 => jb.set_string("packet", "read")?,
        2 => jb.set_string("packet", "write")?,
        _ => jb.set_string("packet", "error")?
    };
    jb.set_string("file", tx.filename.as_str())?;
    jb.set_string("mode", tx.mode.as_str())?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn rs_tftp_log_json_request(tx: &mut TFTPTransaction,
                                           jb: &mut JsonBuilder)
                                           -> bool
{
    tftp_log_request(tx, jb).is_ok()
}
