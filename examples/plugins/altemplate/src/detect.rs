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

// same file as rust/src/applayertemplate/detect.rs except
// TEMPLATE_START_REMOVE removed
// different paths for use statements
// keywords prefixed with altemplate instead of just template

use super::template::{TemplateTransaction, ALPROTO_TEMPLATE};
use std::os::raw::{c_int, c_void};
use suricata::cast_pointer;
use suricata::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use suricata::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use suricata::direction::Direction;
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

static mut G_TEMPLATE_BUFFER_BUFFER_ID: c_int = 0;

unsafe extern "C" fn template_buffer_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_TEMPLATE) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_TEMPLATE_BUFFER_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// Get the request/response buffer for a transaction from C.
unsafe extern "C" fn template_buffer_get(
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

pub(super) unsafe extern "C" fn detect_template_register() {
    // TODO create a suricata-verify test
    // Setup a keyword structure and register it
    let kw = SigTableElmtStickyBuffer {
        name: String::from("altemplate.buffer"),
        desc: String::from("Template content modifier to match on the template buffer"),
        // TODO use the right anchor for url and write doc
        url: String::from("/rules/template-keywords.html#buffer"),
        setup: template_buffer_setup,
    };
    let _g_template_buffer_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_TEMPLATE_BUFFER_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"altemplate.buffer\0".as_ptr() as *const libc::c_char,
        b"template.buffer intern description\0".as_ptr() as *const libc::c_char,
        ALPROTO_TEMPLATE,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(template_buffer_get),
    );
}
