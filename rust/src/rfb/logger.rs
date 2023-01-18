/* Copyright (C) 2020 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>

use std;
use std::fmt::Write;
use super::rfb::{RFBState, RFBTransaction};
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_rfb(tx: &RFBTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("rfb")?;

    // Protocol version
    if let Some(tx_spv) = &tx.tc_server_protocol_version {
        js.open_object("server_protocol_version")?;
        js.set_string("major", &tx_spv.major)?;
        js.set_string("minor", &tx_spv.minor)?;
        js.close()?;
    }
    if let Some(tx_cpv) = &tx.ts_client_protocol_version {
        js.open_object("client_protocol_version")?;
        js.set_string("major", &tx_cpv.major)?;
        js.set_string("minor", &tx_cpv.minor)?;
        js.close()?;
    }

    // Authentication
    js.open_object("authentication")?;
    if let Some(chosen_security_type) = tx.chosen_security_type {
        js.set_uint("security_type", chosen_security_type as u64)?;
    }
    #[allow(clippy::single_match)]
    match tx.chosen_security_type {
        Some(2) => {
            js.open_object("vnc")?;
            if let Some(ref sc) = tx.tc_vnc_challenge {
                let mut s = String::new();
                for &byte in &sc.secret[..] {
                    write!(&mut s, "{:02x}", byte).expect("Unable to write");
                }
                js.set_string("challenge", &s)?;
            }
            if let Some(ref sr) = tx.ts_vnc_response {
                let mut s = String::new();
                for &byte in &sr.secret[..] {
                    write!(&mut s, "{:02x}", byte).expect("Unable to write");
                }
                js.set_string("response", &s)?;
            }
            js.close()?;
        }
        _ => ()
    }
    if let Some(security_result) = &tx.tc_security_result {
        let _ = match security_result.status {
            0 => js.set_string("security_result", "OK")?,
            1 => js.set_string("security-result", "FAIL")?,
            2 => js.set_string("security_result", "TOOMANY")?,
            _ => js.set_string("security_result",
                    &format!("UNKNOWN ({})", security_result.status))?,
        };
    }
    js.close()?; // Close authentication.

    if let Some(ref reason) = tx.tc_failure_reason {
        js.set_string("server_security_failure_reason", &reason.reason_string)?;
    }

    // Client/Server init
    if let Some(s) = &tx.ts_client_init {
        js.set_bool("screen_shared", s.shared != 0)?;
    }
    if let Some(tc_server_init) = &tx.tc_server_init {
        js.open_object("framebuffer")?;
        js.set_uint("width", tc_server_init.width as u64)?;
        js.set_uint("height", tc_server_init.height as u64)?;
        js.set_string_from_bytes("name", &tc_server_init.name)?;

        js.open_object("pixel_format")?;
        js.set_uint("bits_per_pixel", tc_server_init.pixel_format.bits_per_pixel as u64)?;
        js.set_uint("depth", tc_server_init.pixel_format.depth as u64)?;
        js.set_bool("big_endian", tc_server_init.pixel_format.big_endian_flag != 0)?;
        js.set_bool("true_color", tc_server_init.pixel_format.true_colour_flag != 0)?;
        js.set_uint("red_max", tc_server_init.pixel_format.red_max as u64)?;
        js.set_uint("green_max", tc_server_init.pixel_format.green_max as u64)?;
        js.set_uint("blue_max", tc_server_init.pixel_format.blue_max as u64)?;
        js.set_uint("red_shift", tc_server_init.pixel_format.red_shift as u64)?;
        js.set_uint("green_shift", tc_server_init.pixel_format.green_shift as u64)?;
        js.set_uint("blue_shift", tc_server_init.pixel_format.blue_shift as u64)?;
        js.set_uint("depth", tc_server_init.pixel_format.depth as u64)?;
        js.close()?;

        js.close()?;
    }

    js.close()?;

    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_logger_log(_state: &mut RFBState,
                                    tx: *mut std::os::raw::c_void,
                                    js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, RFBTransaction);
    log_rfb(tx, js).is_ok()
}
