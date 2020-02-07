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
use crate::json::*;
use super::rfb::RFBTransaction;

fn log_rfb(tx: &RFBTransaction) -> Option<Json> {
    let js = Json::object();

    // Protocol version
    if let Some(tx_spv) = &tx.tc_server_protocol_version {
        let spv = Json::object();
        spv.set_string("major", &tx_spv.major);
        spv.set_string("minor", &tx_spv.minor);
        js.set("server_protocol_version", spv);
    }
    if let Some(tx_cpv) = &tx.ts_client_protocol_version {
        let cpv = Json::object();
        cpv.set_string("major", &tx_cpv.major);
        cpv.set_string("minor", &tx_cpv.minor);
        js.set("client_protocol_version", cpv);
    }

    // Authentication
    let auth = Json::object();
    if let Some(chosen_security_type) = tx.chosen_security_type {
        auth.set_integer("security_type", chosen_security_type as u64);
    }
    match tx.chosen_security_type {
        Some(2) => {
            let vncauth = Json::object();
            if let Some(ref sc) = tx.tc_vnc_challenge {
                let mut s = String::new();
                for &byte in &sc.secret[..] {
                    write!(&mut s, "{:02x}", byte).expect("Unable to write");
                }
                vncauth.set_string("challenge", &s);
            }
            if let Some(ref sr) = tx.ts_vnc_response {
                let mut s = String::new();
                for &byte in &sr.secret[..] {
                    write!(&mut s, "{:02x}", byte).expect("Unable to write");
                }
                vncauth.set_string("response", &s);
            }
            auth.set("vnc", vncauth);
        }
        _ => ()
    }
    if let Some(security_result) = &tx.tc_security_result {
        match security_result.status {
            0 => auth.set_string("security-result", "OK"),
            1 => auth.set_string("security-result", "FAIL"),
            2 => auth.set_string("security-result", "TOOMANY"),
            _ => auth.set_string("security-result", "UNKNOWN")
        }
    }
    js.set("authentication", auth);

    if let Some(ref reason) = tx.tc_failure_reason {
        js.set_string("server_security_failure_reason", &reason.reason_string);
    }

    // Client/Server init
    if let Some(s) = &tx.ts_client_init {
        js.set_boolean("screen shared", s.shared != 0);
    }
    if let Some(tc_server_init) = &tx.tc_server_init {
        let fb = Json::object();
        fb.set_integer("width", tc_server_init.width as u64);
        fb.set_integer("height", tc_server_init.height as u64);
        fb.set_string_from_bytes("name", &tc_server_init.name);

        let pfj = Json::object();
        pfj.set_integer("bits_per_pixel", tc_server_init.pixel_format.bits_per_pixel as u64);
        pfj.set_integer("depth", tc_server_init.pixel_format.depth as u64);
        pfj.set_boolean("big_endian", tc_server_init.pixel_format.big_endian_flag != 0);
        pfj.set_boolean("true_color", tc_server_init.pixel_format.true_colour_flag != 0);
        pfj.set_integer("red_max", tc_server_init.pixel_format.red_max as u64);
        pfj.set_integer("green_max", tc_server_init.pixel_format.green_max as u64);
        pfj.set_integer("blue_max", tc_server_init.pixel_format.blue_max as u64);
        pfj.set_integer("red_shift", tc_server_init.pixel_format.red_shift as u64);
        pfj.set_integer("green_shift", tc_server_init.pixel_format.green_shift as u64);
        pfj.set_integer("blue_shift", tc_server_init.pixel_format.blue_shift as u64);
        pfj.set_integer("depth", tc_server_init.pixel_format.depth as u64);
        pfj.set_integer("depth", tc_server_init.pixel_format.depth as u64);
        fb.set("pixel_format", pfj);

        js.set("framebuffer", fb);
    }

    return Some(js);
}

#[no_mangle]
pub extern "C" fn rs_rfb_logger_log(tx: *mut std::os::raw::c_void) -> *mut JsonT {
    let tx = cast_pointer!(tx, RFBTransaction);
    match log_rfb(tx) {
        Some(js) => js.unwrap(),
        None => std::ptr::null_mut(),
    }
}
