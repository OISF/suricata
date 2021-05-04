/* Copyright (C) 2021 Open Information Security Foundation
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

use std;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use super::pgsql::PgsqlTransaction;

fn log_pgsql(tx: &PgsqlTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if let Some(ref request) = tx.request {
        js.set_string("request", &request.to_string())?;
    }
    if let Some(ref response) = tx.response {
        js.set_string("response", &response.to_string())?;
    }
    // TODO
    // Check tx vectors and alternately print request and response? >_<
    Ok(())
}

#[no_mangle]
pub extern "C" fn rs_pgsql_logger_log(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, PgsqlTransaction);
    log_pgsql(tx, js).is_ok()
}
