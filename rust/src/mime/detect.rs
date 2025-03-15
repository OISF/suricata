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

use super::mime;
use super::smtp::{MimeStateSMTP, ALPROTO_SMTP};
use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperGetData,
    DetectHelperKeywordRegister, DetectSignatureSetAppProto, SCSigTableElmt,
    SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
};

use std::os::raw::{c_int, c_void};

static mut G_MIME_EMAIL_FROM_BUFFER_ID: c_int = 0;

unsafe extern "C" fn mime_detect_email_from_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SMTP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MIME_EMAIL_FROM_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mime_detect_email_from_get_data(
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
        mime_tx_get_email_from,
    );
}

unsafe extern "C" fn mime_tx_get_email_from(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MimeStateSMTP);

    *buffer = std::ptr::null();
    *buffer_len = 0;

    let hname: &str = "from";
    for header in &tx.headers[..tx.main_headers_nb] {
        if mime::slice_equals_lowercase(&header.name, hname.as_bytes()) {
            SCLogInfo!(
                "detect: value=[{}]\n",
                &String::from_utf8_lossy(&header.value)
            );
            let str_buffer: &str = &String::from_utf8_lossy(&header.value);
            *buffer = str_buffer.as_ptr();
            *buffer_len = str_buffer.len() as u32;
            return true;
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectMimeRegister() {
    let kw = SCSigTableElmt {
        name: b"email.from\0".as_ptr() as *const libc::c_char,
        desc: b"match MIME email from\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mime-keywords.html#email.from\0".as_ptr() as *const libc::c_char,
        Setup: mime_detect_email_from_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mime_email_from_kw_id = DetectHelperKeywordRegister(&kw);
    G_MIME_EMAIL_FROM_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"email.from\0".as_ptr() as *const libc::c_char,
        b"MIME EMAIL FROM\0".as_ptr() as *const libc::c_char,
        ALPROTO_SMTP,
        true, //to client
        true, //to server
        mime_detect_email_from_get_data,
    );
}
