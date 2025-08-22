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

use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{
    helper_keyword_register_multi_buffer, helper_keyword_register_sticky_buffer,
    SigTableElmtStickyBuffer,
};
use crate::direction::Direction;
use crate::sip::sip::{SIPTransaction, ALPROTO_SIP};
use std::os::raw::{c_int, c_void};
use std::ptr;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperMultiBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

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
pub unsafe extern "C" fn SCSipTxGetMethod(
    tx: &SIPTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
pub unsafe extern "C" fn SCSipTxGetUri(
    tx: &SIPTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_PROTOCOL_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_protocol_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_STAT_CODE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_stat_code_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_STAT_MSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_stat_msg_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_REQUEST_LINE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_request_line_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_RESPONSE_LINE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_response_line_get(
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

fn sip_get_header_value<'a>(
    tx: &'a SIPTransaction, i: u32, direction: Direction, s: &str,
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_FROM_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_from_hdr_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "From") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_to_hdr_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_TO_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_to_hdr_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "To") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_via_hdr_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_VIA_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_via_hdr_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "Via") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_ua_hdr_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_UA_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_ua_hdr_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "User-Agent") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_content_type_hdr_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_CONTENT_TYPE_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_content_type_hdr_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "Content-Type") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sip_content_length_hdr_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SIP_CONTENT_LENGTH_HDR_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_content_length_hdr_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    if let Some(value) = sip_get_header_value(tx, local_id, flow_flags.into(), "Content-Length") {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}
#[no_mangle]
pub unsafe extern "C" fn SCDetectSipRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.protocol"),
        desc: String::from("sticky buffer to match on the SIP protocol"),
        url: String::from("/rules/sip-keywords.html#sip-protocol"),
        setup: sip_protocol_setup,
    };
    let _g_sip_protocol_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SIP_PROTOCOL_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sip.protocol\0".as_ptr() as *const libc::c_char,
        b"sip.protocol\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_protocol_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.stat_code"),
        desc: String::from("sticky buffer to match on the SIP status code"),
        url: String::from("/rules/sip-keywords.html#sip-stat-code"),
        setup: sip_stat_code_setup,
    };
    let _g_sip_stat_code_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SIP_STAT_CODE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sip.stat_code\0".as_ptr() as *const libc::c_char,
        b"sip.stat_code\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOCLIENT,
        Some(sip_stat_code_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.stat_msg"),
        desc: String::from("sticky buffer to match on the SIP status message"),
        url: String::from("/rules/sip-keywords.html#sip-stat-msg"),
        setup: sip_stat_msg_setup,
    };
    let _g_sip_stat_msg_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SIP_STAT_MSG_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sip.stat_msg\0".as_ptr() as *const libc::c_char,
        b"sip.stat_msg\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOCLIENT,
        Some(sip_stat_msg_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.request_line"),
        desc: String::from("sticky buffer to match on the SIP request line"),
        url: String::from("/rules/sip-keywords.html#sip-request-line"),
        setup: sip_request_line_setup,
    };
    let _g_sip_request_line_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SIP_REQUEST_LINE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sip.request_line\0".as_ptr() as *const libc::c_char,
        b"sip.request_line\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER,
        Some(sip_request_line_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.response_line"),
        desc: String::from("sticky buffer to match on the SIP response line"),
        url: String::from("/rules/sip-keywords.html#sip-response-line"),
        setup: sip_response_line_setup,
    };
    let _g_sip_response_line_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SIP_RESPONSE_LINE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sip.response_line\0".as_ptr() as *const libc::c_char,
        b"sip.response_line\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOCLIENT,
        Some(sip_response_line_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.from"),
        desc: String::from("sticky buffer to match on the SIP From header"),
        url: String::from("/rules/sip-keywords.html#sip-from"),
        setup: sip_from_hdr_setup,
    };
    let _g_sip_from_hdr_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_SIP_FROM_HDR_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sip.from\0".as_ptr() as *const libc::c_char,
        b"sip.from\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_from_hdr_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.to"),
        desc: String::from("sticky buffer to match on the SIP To header"),
        url: String::from("/rules/sip-keywords.html#sip-to"),
        setup: sip_to_hdr_setup,
    };
    let _g_sip_to_hdr_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_SIP_TO_HDR_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sip.to\0".as_ptr() as *const libc::c_char,
        b"sip.to\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_to_hdr_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.via"),
        desc: String::from("sticky buffer to match on the SIP Via header"),
        url: String::from("/rules/sip-keywords.html#sip-via"),
        setup: sip_via_hdr_setup,
    };
    let _g_sip_via_hdr_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_SIP_VIA_HDR_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sip.via\0".as_ptr() as *const libc::c_char,
        b"sip.via\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_via_hdr_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.user_agent"),
        desc: String::from("sticky buffer to match on the SIP User-Agent header"),
        url: String::from("/rules/sip-keywords.html#sip-user-agent"),
        setup: sip_ua_hdr_setup,
    };
    let _g_sip_ua_hdr_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_SIP_UA_HDR_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sip.ua\0".as_ptr() as *const libc::c_char,
        b"sip.ua\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_ua_hdr_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.content_type"),
        desc: String::from("sticky buffer to match on the SIP Content-Type header"),
        url: String::from("/rules/sip-keywords.html#sip-content-type"),
        setup: sip_content_type_hdr_setup,
    };
    let _g_sip_content_type_hdr_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_SIP_CONTENT_TYPE_HDR_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sip.content_type\0".as_ptr() as *const libc::c_char,
        b"sip.content_type\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_content_type_hdr_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sip.content_length"),
        desc: String::from("sticky buffer to match on the SIP Content-Length header"),
        url: String::from("/rules/sip-keywords.html#sip-content-length"),
        setup: sip_content_length_hdr_setup,
    };
    let _g_sip_content_length_hdr_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_SIP_CONTENT_LENGTH_HDR_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sip.content_length\0".as_ptr() as *const libc::c_char,
        b"sip.content_length\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_content_length_hdr_get_data),
    );
}
