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

use super::http2::HTTP2Transaction;
use crate::json::*;
use std;

fn log_http2(tx: &HTTP2Transaction) -> Option<Json> {
    let js = Json::object();
    if let Some(ref ftype) = tx.ftype {
        js.set_string("frame_type", &ftype.to_string());
    }
    return Some(js);
}

#[no_mangle]
pub extern "C" fn rs_http2_log_json(tx: *mut std::os::raw::c_void) -> *mut JsonT {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    match log_http2(tx) {
        Some(js) => js.unwrap(),
        None => std::ptr::null_mut(),
    }
}
