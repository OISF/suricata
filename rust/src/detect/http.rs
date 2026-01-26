/* Copyright (C) 2026 Open Information Security Foundation
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

use crate::core::STREAM_TOSERVER;
use crate::detect::transforms::urldecode::G_TRANSFORM_URL_DECODE_ID;
use crate::detect::{helper_keyword_register_multi_buffer, SigTableElmtStickyBuffer};
use crate::http2::detect::http2_form_get_data;
use std::os::raw::{c_int, c_void};
use std::ptr;
use suricata_sys::sys::AppProtoEnum::{ALPROTO_HTTP, ALPROTO_HTTP1, ALPROTO_HTTP2};
use suricata_sys::sys::{
    AppProto, DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperMultiBufferMpmRegister, SCDetectSignatureAddTransform,
    SCDetectSignatureSetAppProto, Signature,
};

static mut G_HTTP_FORM_BUFFER_ID: c_int = 0;

unsafe extern "C" fn http_form_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_HTTP as AppProto) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_HTTP_FORM_BUFFER_ID) < 0 {
        return -1;
    }
    return SCDetectSignatureAddTransform(s, G_TRANSFORM_URL_DECODE_ID, ptr::null_mut());
}

unsafe extern "C" fn http1_form_get_data(
    _de: *mut DetectEngineThreadCtx, _tx: *const c_void, _flow_flags: u8, _local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    //TODO let tx = cast_pointer!(tx, SIPTransaction);
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectHttpFormRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("http.form"),
        desc: String::from(
            "sticky buffer to match on HTTP 1/2 query args or form data in request body",
        ),
        url: String::from("/rules/http-keywords.html#http-form"),
        setup: http_form_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_HTTP_FORM_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"http.form\0".as_ptr() as *const libc::c_char,
        b"http form\0".as_ptr() as *const libc::c_char,
        ALPROTO_HTTP1 as AppProto,
        STREAM_TOSERVER,
        Some(http1_form_get_data),
    );
    let h2 = SCDetectHelperMultiBufferMpmRegister(
        b"http.form\0".as_ptr() as *const libc::c_char,
        b"http form\0".as_ptr() as *const libc::c_char,
        ALPROTO_HTTP2 as AppProto,
        STREAM_TOSERVER,
        Some(http2_form_get_data),
    );
    if h2 != G_HTTP_FORM_BUFFER_ID {
        SCLogError!("Different buffer ids for http1/2 for http.form");
    }
}
