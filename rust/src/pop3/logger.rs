/* Copyright (C) 2025 Open Information Security Foundation
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

// Author: Alex Savage <exlavasage@gmail.com>

//! POP3 parser json logger

use super::pop3::POP3Transaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_pop3(tx: &POP3Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("pop3")?;
    if let Some(ref request) = tx.request {
        let js_request = js.open_object("request")?;
        js_request.set_string("command", &request.keyword.to_string())?;

        let js_args = js_request.open_array("args")?;
        for arg in &request.args {
            js_args.append_string_from_bytes(arg)?;
        }
        js_args.close()?;
        js_request.close()?;
    }
    if let Some(ref response) = tx.response {
        let js_response = js.open_object("response")?;
        js_response.set_bool("success", response.status == sawp_pop3::Status::OK)?;
        js_response.set_string("status", response.status.to_str())?;
        js_response.set_string_from_bytes("header", &response.header)?;

        let js_data = js_response.open_array("data")?;
        for data in &response.data {
            js_data.append_string_from_bytes(data)?;
        }
        js_data.close()?;
        js_response.close()?;
    }

    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCPop3LoggerLog(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, POP3Transaction);
    log_pop3(tx, js).is_ok()
}
