/* Copyright (C) 2022 Open Information Security Foundation
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

// written by linqiankai <linqiankai@geweian.com>
//
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::mysql::mysql::*;

fn log_mysql(tx: &MysqlTransaction, _flags: u32, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("mysql")?;
    if let Some(version) = &tx.version {
        js.set_string("version", version)?;
    }
    if let Some(tls) = &tx.tls {
        js.set_bool("tls", *tls)?;
    } else {
        js.set_bool("tls", false)?;
    }

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
    tx: *mut std::os::raw::c_void, flags: u32, js: &mut JsonBuilder,
) -> bool {
    let tx_mysql = cast_pointer!(tx, MysqlTransaction);
    SCLogDebug!(
        "----------- MySQL rs_mysql_logger call. Tx is {:?}",
        tx_mysql
    );
    let result = log_mysql(tx_mysql, flags, js);
    if let Err(ref err) = result {
        SCLogError!("----------- MySQL rs_mysql_logger failed. err is {:?}", err);
    }
    return result.is_ok();
}
