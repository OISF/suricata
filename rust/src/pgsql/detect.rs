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

// written by Juliana Fajardini <jufajardini@oisf.net>

use super::pgsql::{PgsqlTransaction, ALPROTO_PGSQL};
use crate::pgsql::parser::PgsqlFEMessage;
use crate::core::{STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferMpmRegister, SCDetectSignatureSetAppProto,
    Signature,
};
use std::os::raw::{c_int, c_void};

static mut G_PGSQL_QUERY_BUFFER_ID: c_int = 0;

unsafe extern "C" fn pgsql_detect_query_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,) -> c_int
{
    if SCDetectSignatureSetAppProto(s, ALPROTO_PGSQL) != 0 {
        return - 1;
    }
    if SCDetectBufferSetActiveList(de, s, G_PGSQL_QUERY_BUFFER_ID) < 0 {
        return - 1;
    }
    0
}

unsafe extern "C" fn pgsql_detect_query_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, PgsqlTransaction);

    for request in &tx.requests {
        if let PgsqlFEMessage::SimpleQuery(ref query) = request {
            *buffer = query.payload.as_ptr();
            *buffer_len = query.payload.len() as u32;
            return true;
        }
    }

    *buffer = std::ptr::null();
    *buffer_len = 0;
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectPgsqlRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("pgsql.query"),
        desc: String::from("match PGSQL  query request content"),
        url: String::from("/rules/pgsql-keywords.html#pgsql.query"),
        setup: pgsql_detect_query_setup,
    };
    let _g_pgsql_query_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_PGSQL_QUERY_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"pgsql.query\0".as_ptr() as *const libc::c_char,
        b"pgsql query request content\0".as_ptr() as *const libc::c_char,
        ALPROTO_PGSQL,
        STREAM_TOSERVER,
        Some(pgsql_detect_query_get_data),
    );
}
