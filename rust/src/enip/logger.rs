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
use super::parser::{
    enip_command_string, enip_status_string, EnipHeader, EnipItemPayload, EnipPayload,
};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_enip_header(h: &EnipHeader, js: &mut JsonBuilder) -> Result<(), JsonError> {
    match enip_command_string(h.cmd) {
        Some(val) => {
            js.set_string("command", val)?;
        }
        None => {
            js.set_string("command", &format!("unknown-{}", h.cmd))?;
        }
    }
    match enip_status_string(h.status) {
        Some(val) => {
            js.set_string("status", val)?;
        }
        None => {
            js.set_string("status", &format!("unknown-{}", h.status))?;
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
        match &response.payload {
            EnipPayload::ListIdentity(lip) if !lip.is_empty() => {
                if let EnipItemPayload::Identity(li) = &lip[0].payload {
                    js.open_object("identity")?;
                    js.set_uint("protocol_version", li.protocol_version.into())?;
                    js.set_string(
                        "revision",
                        &format!("{}.{}", li.revision_major, li.revision_minor),
                    )?;
                    js.set_uint("vendor_id", li.vendor_id.into())?;
                    js.set_uint("device_type", li.device_type.into())?;
                    js.set_uint("product_code", li.product_code.into())?;
                    js.set_uint("status", li.status.into())?;
                    js.set_uint("serial", li.serial.into())?;
                    js.set_string("product_name", &String::from_utf8_lossy(&li.product_name))?;
                    js.set_uint("state", li.state.into())?;
                    js.close()?;
                }
            }
            _ => {}
        }
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
