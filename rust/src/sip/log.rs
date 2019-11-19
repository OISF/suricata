/* Copyright (C) 2019 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use json::*;
use sip::sip::{SIPState, SIPTransaction};

#[no_mangle]
pub extern "C" fn rs_sip_log_json_request(_state: &mut SIPState, tx: &mut SIPTransaction) -> *mut JsonT {
    let js = Json::object();

    match tx.request {
        Some(ref req) => {
            js.set_string("method", &req.method);
            js.set_string("uri", &req.path);
            js.set_string("version", &req.version);
            if let Some(ref req_line) = tx.request_line {
                js.set_string("request_line", &req_line);
            }
            return js.unwrap();
        }
        None => {}
    }

    return std::ptr::null_mut();
}

#[no_mangle]
pub extern "C" fn rs_sip_log_json_response(_state: &mut SIPState, tx: &mut SIPTransaction) -> *mut JsonT {
    let js = Json::object();

    match tx.response {
        Some(ref resp) => {
            js.set_string("version", &resp.version);
            js.set_string("code", &resp.code);
            js.set_string("reason", &resp.reason);
            if let Some(ref resp_line) = tx.response_line {
                js.set_string("response_line", &resp_line);
            }
            return js.unwrap();
        }
        None => {}
    }

    return std::ptr::null_mut();
}