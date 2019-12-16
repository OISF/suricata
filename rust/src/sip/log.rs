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

use crate::json::*;
use crate::sip::sip::{SIPState, SIPTransaction};

#[no_mangle]
pub extern "C" fn rs_sip_log_json(_state: &mut SIPState, tx: &mut SIPTransaction) -> *mut JsonT {
    let js = Json::object();

    match tx.request {
        Some(ref req) => {
            js.set_string("method", &req.method);
            js.set_string("uri", &req.path);
            js.set_string("version", &req.version);
        }
        None => {}
    }
    match tx.request_line {
        Some(ref req_line) => {
            js.set_string("request_line", &req_line);
        }
        None => {}
    }
    match tx.response {
        Some(ref resp) => {
            js.set_string("version", &resp.version);
            js.set_string("code", &resp.code);
            js.set_string("reason", &resp.reason);
        }
        None => {}
    }
    match tx.response_line {
        Some(ref resp_line) => {
            js.set_string("response_line", &resp_line);
        }
        None => {}
    }

    return js.unwrap();
}
