/* Copyright (C) 2019-2024 Open Information Security Foundation
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

use crate::core::Direction;
use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperGetData,
    DetectHelperGetMultiData, DetectHelperKeywordRegister, DetectHelperMultiBufferMpmRegister,
    DetectSignatureSetAppProto, SCSigTableElmt, SIGMATCH_NOOPT,
};
use crate::sip::sip::{SIPTransaction, ALPROTO_SIP};
use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_SIP_PROTOCOL_BUFFER_ID: c_int = 0;
static mut G_SIP_STAT_CODE_BUFFER_ID: c_int = 0;
static mut G_SIP_STAT_MSG_BUFFER_ID: c_int = 0;
static mut G_SIP_REQUEST_LINE_BUFFER_ID: c_int = 0;
static mut G_SIP_RESPONSE_LINE_BUFFER_ID: c_int = 0;
static mut G_SIP_FROM_HDR_BUFFER_ID: c_int = 0;
static mut G_SIP_TO_HDR_BUFFER_ID: c_int = 0;
static mut G_SIP_VIA_HDR_BUFFER_ID: c_int = 0;
static mut G_SIP_UA_HDR_BUFFER_ID: c_int = 0;
static mut G_SIP_CONTENT_TYPE_HDR_BUFFER_ID: c_int = 0;
static mut G_SIP_CONTENT_LENGTH_HDR_BUFFER_ID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_method(
    tx: &mut SIPTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.request {
        let m = &r.method;
        if !m.is_empty() {
            *buffer = m.as_ptr();
            *buffer_len = m.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_uri(
    tx: &mut SIPTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.request {
        let p = &r.path;
        if !p.is_empty() {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

unsafe extern "C" fn sip_protocol_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_PROTOCOL_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_protocol_get(
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
        sip_protocol_get_data,
    );
}

unsafe extern "C" fn sip_protocol_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    match direction.into() {
        Direction::ToServer => {
            if let Some(ref r) = tx.request {
                let v = &r.version;
                if !v.is_empty() {
                    *buffer = v.as_ptr();
                    *buffer_len = v.len() as u32;
                    return true;
                }
            }
        }
        Direction::ToClient => {
            if let Some(ref r) = tx.response {
                let v = &r.version;
                if !v.is_empty() {
                    *buffer = v.as_ptr();
                    *buffer_len = v.len() as u32;
                    return true;
                }
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_stat_code_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_STAT_CODE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_stat_code_get(
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
        sip_stat_code_get_data,
    );
}

unsafe extern "C" fn sip_stat_code_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(ref r) = tx.response {
        let c = &r.code;
        if !c.is_empty() {
            *buffer = c.as_ptr();
            *buffer_len = c.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_stat_msg_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_STAT_MSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_stat_msg_get(
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
        sip_stat_msg_get_data,
    );
}
unsafe extern "C" fn sip_stat_msg_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(ref r) = tx.response {
        let re = &r.reason;
        if !re.is_empty() {
            *buffer = re.as_ptr();
            *buffer_len = re.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_request_line_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_REQUEST_LINE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_request_line_get(
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
        sip_request_line_get_data,
    );
}

unsafe extern "C" fn sip_request_line_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(ref r) = tx.request_line {
        if !r.is_empty() {
            *buffer = r.as_ptr();
            *buffer_len = r.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_response_line_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_RESPONSE_LINE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_response_line_get(
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
        sip_response_line_get_data,
    );
}

unsafe extern "C" fn sip_response_line_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(ref r) = tx.response_line {
        if !r.is_empty() {
            *buffer = r.as_ptr();
            *buffer_len = r.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

fn sip_get_header_value<'a, 'b>(
    tx: &'a SIPTransaction, i: u32, direction: Direction, s: &'b str,
) -> Option<&'a str> {
    let headers = match direction {
        Direction::ToServer => tx.request.as_ref().map(|r| &r.headers),
        Direction::ToClient => tx.response.as_ref().map(|r| &r.headers),
    };
    if let Some(headers) = headers {
        if let Some(header_vals) = headers.get(s) {
            if (i as usize) < header_vals.len() {
                let value = &header_vals[i as usize];
                return Some(value);
            }
        }
    }
    return None;
}

unsafe extern "C" fn sip_from_hdr_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_FROM_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_from_hdr_get(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int, local_id: u32,
) -> *mut c_void {
    return DetectHelperGetMultiData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        local_id,
        sip_from_hdr_get_data,
    );
}

unsafe extern "C" fn sip_from_hdr_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "From") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    // else
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_to_hdr_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_TO_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_to_hdr_get(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int, local_id: u32,
) -> *mut c_void {
    return DetectHelperGetMultiData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        local_id,
        sip_to_hdr_get_data,
    );
}

unsafe extern "C" fn sip_to_hdr_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "To") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    // else
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_via_hdr_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_VIA_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_via_hdr_get(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int, local_id: u32,
) -> *mut c_void {
    return DetectHelperGetMultiData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        local_id,
        sip_via_hdr_get_data,
    );
}

unsafe extern "C" fn sip_via_hdr_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "Via") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    // else
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_ua_hdr_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_UA_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_ua_hdr_get(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int, local_id: u32,
) -> *mut c_void {
    return DetectHelperGetMultiData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        local_id,
        sip_ua_hdr_get_data,
    );
}

unsafe extern "C" fn sip_ua_hdr_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "User-Agent") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    // else
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_content_type_hdr_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_CONTENT_TYPE_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_content_type_hdr_get(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int, local_id: u32,
) -> *mut c_void {
    return DetectHelperGetMultiData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        local_id,
        sip_content_type_hdr_get_data,
    );
}

unsafe extern "C" fn sip_content_type_hdr_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "Content-Type") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    // else
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_content_length_hdr_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SIP_CONTENT_LENGTH_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_content_length_hdr_get(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int, local_id: u32,
) -> *mut c_void {
    return DetectHelperGetMultiData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        local_id,
        sip_content_length_hdr_get_data,
    );
}

unsafe extern "C" fn sip_content_length_hdr_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "Content-Length") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    // else
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}
#[no_mangle]
pub unsafe extern "C" fn ScDetectSipRegister() {
    let kw = SCSigTableElmt {
        name: b"sip.protocol\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP protocol\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-protocol\0".as_ptr() as *const libc::c_char,
        Setup: sip_protocol_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_protocol_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_PROTOCOL_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sip.protocol\0".as_ptr() as *const libc::c_char,
        b"sip.protocol\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sip_protocol_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.stat_code\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP status code\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-stat-code\0".as_ptr() as *const libc::c_char,
        Setup: sip_stat_code_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_stat_code_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_STAT_CODE_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sip.stat_code\0".as_ptr() as *const libc::c_char,
        b"sip.stat_code\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        false,
        sip_stat_code_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.stat_msg\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP status message\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-stat-msg\0".as_ptr() as *const libc::c_char,
        Setup: sip_stat_msg_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_stat_msg_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_STAT_MSG_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sip.stat_msg\0".as_ptr() as *const libc::c_char,
        b"sip.stat_msg\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        false,
        sip_stat_msg_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.request_line\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP request line\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-request-line\0".as_ptr() as *const libc::c_char,
        Setup: sip_request_line_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_request_line_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_REQUEST_LINE_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sip.request_line\0".as_ptr() as *const libc::c_char,
        b"sip.request_line\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        false,
        true,
        sip_request_line_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.response_line\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP response line\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-response-line\0".as_ptr() as *const libc::c_char,
        Setup: sip_response_line_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_response_line_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_RESPONSE_LINE_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sip.response_line\0".as_ptr() as *const libc::c_char,
        b"sip.response_line\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        false,
        sip_response_line_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.from\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP From header\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-from\0".as_ptr() as *const libc::c_char,
        Setup: sip_from_hdr_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_from_hdr_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_FROM_HDR_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sip.from\0".as_ptr() as *const libc::c_char,
        b"sip.from\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sip_from_hdr_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.to\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP To header\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-to\0".as_ptr() as *const libc::c_char,
        Setup: sip_to_hdr_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_to_hdr_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_TO_HDR_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sip.to\0".as_ptr() as *const libc::c_char,
        b"sip.to\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sip_to_hdr_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.via\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP Via header\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-via\0".as_ptr() as *const libc::c_char,
        Setup: sip_via_hdr_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_via_hdr_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_VIA_HDR_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sip.via\0".as_ptr() as *const libc::c_char,
        b"sip.via\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sip_via_hdr_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.user_agent\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP User-Agent header\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-user-agent\0".as_ptr() as *const libc::c_char,
        Setup: sip_ua_hdr_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_ua_hdr_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_UA_HDR_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sip.ua\0".as_ptr() as *const libc::c_char,
        b"sip.ua\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sip_ua_hdr_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.content_type\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP Content-Type header\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-content-type\0".as_ptr() as *const libc::c_char,
        Setup: sip_content_type_hdr_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_content_type_hdr_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_CONTENT_TYPE_HDR_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sip.content_type\0".as_ptr() as *const libc::c_char,
        b"sip.content_type\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sip_content_type_hdr_get,
    );
    let kw = SCSigTableElmt {
        name: b"sip.content_length\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SIP Content-Length header\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sip-keywords.html#sip-content-length\0".as_ptr() as *const libc::c_char,
        Setup: sip_content_length_hdr_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_sip_content_length_hdr_kw_id = DetectHelperKeywordRegister(&kw);
    G_SIP_CONTENT_LENGTH_HDR_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sip.content_length\0".as_ptr() as *const libc::c_char,
        b"sip.content_length\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sip_content_length_hdr_get,
    );
}
