/* Copyright (C) 2024 Open Information Security Foundation
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

use super::template::{TemplateTransaction, ALPROTO_TEMPLATE};
/* TEMPLATE_START_REMOVE */
use crate::conf::conf_get_node;
/* TEMPLATE_END_REMOVE */
use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperGetData,
    DetectHelperKeywordRegister, DetectSignatureSetAppProto, SCSigTableAppLiteElmt,
    SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
};
use crate::direction::Direction;
use std::os::raw::{c_int, c_void};

static mut G_TEMPLATE_BUFFER_BUFFER_ID: c_int = 0;

unsafe extern "C" fn template_buffer_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_TEMPLATE) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_TEMPLATE_BUFFER_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// Get the request/response buffer for a transaction from C.
unsafe extern "C" fn template_buffer_get_data(
    tx: *const c_void, flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, TemplateTransaction);
    if flags & Direction::ToClient as u8 != 0 {
        if let Some(ref response) = tx.response {
            *len = response.len() as u32;
            *buf = response.as_ptr();
            return true;
        }
    } else if let Some(ref request) = tx.request {
        *len = request.len() as u32;
        *buf = request.as_ptr();
        return true;
    }
    return false;
}

unsafe extern "C" fn template_buffer_get(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int,
) -> *mut c_void {
    return DetectHelperGetData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        template_buffer_get_data,
    );
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectTemplateRegister() {
    /* TEMPLATE_START_REMOVE */
    if conf_get_node("app-layer.protocols.template").is_none() {
        return;
    }
    /* TEMPLATE_END_REMOVE */
    // TODO create a suricata-verify test
    // Setup a keyword structure and register it
    let kw = SCSigTableAppLiteElmt {
        name: b"template.buffer\0".as_ptr() as *const libc::c_char,
        desc: b"Template content modifier to match on the template buffer\0".as_ptr()
            as *const libc::c_char,
        // TODO use the right anchor for url and write doc
        url: b"/rules/template-keywords.html#buffer\0".as_ptr() as *const libc::c_char,
        Setup: template_buffer_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_template_buffer_kw_id = DetectHelperKeywordRegister(&kw);
    G_TEMPLATE_BUFFER_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"template.buffer\0".as_ptr() as *const libc::c_char,
        b"template.buffer intern description\0".as_ptr() as *const libc::c_char,
        ALPROTO_TEMPLATE,
        true, //toclient
        true, //toserver
        template_buffer_get,
    );
}
