/* Copyright (C) 2018 Open Information Security Foundation
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

// Author: Alex Savage <alexander.savage@cyber.gc.ca>
use super::pop3::POP3Transaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use sawp_pop3::ErrorFlag;
use std;

fn log_pop3(tx: &POP3Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if let Some(ref request) = tx.request {
        js.set_string("keyword", &request.keyword.to_string())?;

        let mut js_args = JsonBuilder::new_array();
        for arg in &request.args {
            js_args.append_string_from_bytes(arg)?;
        }
        js_args.close()?;
        js.set_object("args", &js_args)?;
    }
    if let Some(ref response) = tx.response {
        js.set_string("status", response.status.to_str())?;
        js.set_string_from_bytes("header", &response.header)?;

        let mut js_data = JsonBuilder::new_array();
        for data in &response.data {
            js_data.append_string_from_bytes(data)?;
        }
        js_data.close()?;
        js.set_object("data", &js_data)?;
    }

    let mut js_flags = JsonBuilder::new_array();
    if tx.error_flags.intersects(ErrorFlag::CommandTooLong) {
        js_flags.append_string("CommandTooLong")?;
    }
    if tx.error_flags.intersects(ErrorFlag::ResponseTooLong) {
        js_flags.append_string("ResponseTooLong")?;
    }
    if tx.error_flags.intersects(ErrorFlag::IncorrectArgumentNum) {
        js_flags.append_string("IncorrectArgumentNum")?;
    }
    if tx.error_flags.intersects(ErrorFlag::UnknownKeyword) {
        js_flags.append_string("UnknownKeyword")?;
    }
    js_flags.close();
    js.set_object("error_flags", &js_flags)?;

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_pop3_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, POP3Transaction);
    log_pop3(tx, js).is_ok()
}
