/* Copyright (C) 2022-2024 Open Information Security Foundation
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

use super::stun::*;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_stun(tx: &StunTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if let Some(ref request) = tx.request {
        SCLogDebug!("inside log request");
        js.open_object("request")?;
        js.set_string("message_type", request.message_type.to_str())?;
        js.close()?;
    }
    if let Some(ref response) = tx.response {
        js.open_object("response")?;
        js.set_string("message_type", response.message_type.to_str())?;
        if let Some(attributes) = &response.attrs {
            js.open_array("attributes")?;
            for attribute in attributes {
                js.start_object()?;
                if let Some(val) = &attribute.value {
                    js.set_string_from_bytes(attribute.attr_type.to_str(), val)?;
                } else {
        		    js.append_string(attribute.attr_type.to_str())?;
		        }
                js.close()?;
            }
            js.close()?;
        }
        js.close()?;
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCStunLoggerLog(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, StunTransaction);
    log_stun(tx, js).is_ok()
}
