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

use super::enip::EnipTransaction;
use super::parser::{enip_command_string, enip_status_string, EnipHeader};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_enip_header(h: &EnipHeader, js: &mut JsonBuilder) -> Result<(), JsonError> {
    match enip_command_string(h.cmd) {
        Some(val) => {
            js.set_string("enip_command", val)?;
        }
        None => {
            js.set_string("enip_command", &format!("unknown-{}", h.cmd))?;
        }
    }
    match enip_status_string(h.status) {
        Some(val) => {
            js.set_string("enip_status", val)?;
        }
        None => {
            js.set_string("enip_status", &format!("unknown-{}", h.status))?;
        }
    }
    js.set_uint("length", h.pdulen.into())?;
    if h.options != 0 {
        js.set_uint("options", h.options.into())?;
    }
    Ok(())
}

fn log_enip(tx: &EnipTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("enip")?;
    if let Some(ref request) = tx.request {
        js.open_object("request")?;
        log_enip_header(&request.header, js)?;
        js.close()?;
    }
    if let Some(ref response) = tx.response {
        js.open_object("response")?;
        log_enip_header(&response.header, js)?;
        js.close()?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_enip_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, EnipTransaction);
    if tx.request.is_none() && tx.response.is_none() {
        return false;
    }
    log_enip(tx, js).is_ok()
}
