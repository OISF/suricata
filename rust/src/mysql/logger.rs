/* Copyright (C) 2024 Open Information Security Foundation
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

// Author: QianKaiLin <linqiankai666@outlook.com>

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::mysql::mysql::*;

fn log_mysql(tx: &MysqlTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("mysql")?;
    js.set_string("version", tx.version.as_str())?;
    js.set_bool("tls", tx.tls)?;

    if let Some(command) = &tx.command {
        js.set_string("command", command)?;
    }

    if let Some(affected_rows) = tx.affected_rows {
        js.set_uint("affected_rows", affected_rows)?;
    }

    if let Some(rows) = &tx.rows {
        js.open_array("rows")?;
        for row in rows {
            js.append_string(row)?;
        }
        js.close()?;
    }

    js.close()?;

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCMysqlLogger(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx_mysql = cast_pointer!(tx, MysqlTransaction);
    let result = log_mysql(tx_mysql, js);
    if let Err(ref _err) = result {
        return false;
    }
    return result.is_ok();
}
