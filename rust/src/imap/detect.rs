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

// Author: Giuseppe Longo <glongo@oisf.net>

use super::imap::{ImapEmailDirection, ImapTransaction, ALPROTO_IMAP};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{detect_match_uint, detect_parse_uint_enum, DetectUintData, SCDetectU8Free};
use crate::detect::{
    helper_keyword_register_multi_buffer, helper_keyword_register_sticky_buffer,
    SigTableElmtStickyBuffer, SIGMATCH_INFO_ENUM_UINT, SIGMATCH_INFO_UINT8,
};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperBufferRegister, SCDetectHelperKeywordRegister,
    SCDetectHelperMultiBufferMpmRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

static mut G_IMAP_REQUEST_BUFFER_ID: c_int = 0;
static mut G_IMAP_RESPONSE_BUFFER_ID: c_int = 0;
static mut G_IMAP_MSG_DIRECTION_KW_ID: u16 = 0;
static mut G_IMAP_MSG_DIRECTION_BUFFER_ID: c_int = 0;
static mut G_IMAP_MSG_BODY_BUFFER_ID: c_int = 0;
static mut G_IMAP_MSG_HEADER_BUFFER_ID: c_int = 0;
static mut G_IMAP_MSG_HEADER_NAME_BUFFER_ID: c_int = 0;
static mut G_IMAP_MSG_HEADER_VALUE_BUFFER_ID: c_int = 0;

unsafe extern "C" fn imap_detect_request_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IMAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IMAP_REQUEST_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn imap_tx_get_request(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);

    if local_id as usize >= tx.request_lines.len() {
        return false;
    }

    let line = &tx.request_lines[local_id as usize];
    *buffer = line.as_ptr();
    *buffer_len = line.len() as u32;
    true
}

unsafe extern "C" fn imap_detect_response_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IMAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IMAP_RESPONSE_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn imap_tx_get_response(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);

    if local_id as usize >= tx.response_lines.len() {
        return false;
    }

    let line = &tx.response_lines[local_id as usize];
    *buffer = line.as_ptr();
    *buffer_len = line.len() as u32;
    true
}

unsafe extern "C" fn imap_parse_email_direction(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr);
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u8, ImapEmailDirection>(s) {
            return Box::into_raw(Box::new(ctx)) as *mut _;
        }
    }
    std::ptr::null_mut()
}

unsafe extern "C" fn imap_detect_email_direction_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IMAP) != 0 {
        return -1;
    }
    let ctx = imap_parse_email_direction(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_IMAP_MSG_DIRECTION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_IMAP_MSG_DIRECTION_BUFFER_ID,
    )
    .is_null()
    {
        imap_detect_email_direction_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn imap_detect_email_direction_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ImapTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(cache) = &tx.parsed_email {
        return detect_match_uint(ctx, cache.direction) as c_int;
    }
    0
}

unsafe extern "C" fn imap_detect_email_direction_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn imap_msg_body_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IMAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IMAP_MSG_BODY_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn imap_tx_get_msg_body(
    tx: *const c_void, _direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(cache) = &tx.parsed_email {
        if !cache.body.is_empty() {
            *buffer = cache.body.as_ptr();
            *buffer_len = cache.body.len() as u32;
            return true;
        }
    }
    false
}

unsafe extern "C" fn imap_msg_header_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IMAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IMAP_MSG_HEADER_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn imap_tx_get_msg_header(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(cache) = &tx.parsed_email {
        if let Some(header) = cache.headers.get(local_id as usize) {
            *buffer = header.as_ptr();
            *buffer_len = header.len() as u32;
            return true;
        }
    }
    false
}

// imap.email.header.name - multi buffer (bidirectional), just header names
unsafe extern "C" fn imap_msg_header_name_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IMAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IMAP_MSG_HEADER_NAME_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn imap_tx_get_msg_header_name(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(cache) = &tx.parsed_email {
        if let Some(name) = cache.header_names.get(local_id as usize) {
            *buffer = name.as_ptr();
            *buffer_len = name.len() as u32;
            return true;
        }
    }
    false
}

// imap.email.header.value - multi buffer (bidirectional), just header values
unsafe extern "C" fn imap_msg_header_value_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IMAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IMAP_MSG_HEADER_VALUE_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn imap_tx_get_msg_header_value(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(cache) = &tx.parsed_email {
        if let Some(value) = cache.header_values.get(local_id as usize) {
            *buffer = value.as_ptr();
            *buffer_len = value.len() as u32;
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("imap.request"),
        desc: String::from("match on IMAP request line"),
        url: String::from("/rules/imap-keywords.html#imap.request"),
        setup: imap_detect_request_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);

    G_IMAP_REQUEST_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"imap.request\0".as_ptr() as *const libc::c_char,
        b"IMAP REQUEST LINE\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOSERVER,
        Some(imap_tx_get_request),
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("imap.response"),
        desc: String::from("match on IMAP response line"),
        url: String::from("/rules/imap-keywords.html#imap.response"),
        setup: imap_detect_response_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);

    G_IMAP_RESPONSE_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"imap.response\0".as_ptr() as *const libc::c_char,
        b"IMAP RESPONSE LINE\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOCLIENT,
        Some(imap_tx_get_response),
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"imap.email.direction\0".as_ptr() as *const libc::c_char,
        desc: b"match IMAP email direction\0".as_ptr() as *const libc::c_char,
        url: b"/rules/imap-keywords.html#imap.email.direction\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(imap_detect_email_direction_match),
        Setup: Some(imap_detect_email_direction_setup),
        Free: Some(imap_detect_email_direction_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_ENUM_UINT,
    };
    G_IMAP_MSG_DIRECTION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_IMAP_MSG_DIRECTION_BUFFER_ID = SCDetectHelperBufferRegister(
        b"imap.email.direction\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("imap.email.body"),
        desc: String::from("match on IMAP email body"),
        url: String::from("/rules/imap-keywords.html#imap.email.body"),
        setup: imap_msg_body_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);

    G_IMAP_MSG_BODY_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"imap.email.body\0".as_ptr() as *const libc::c_char,
        b"IMAP EMAIL BODY\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(imap_tx_get_msg_body),
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("imap.email.header"),
        desc: String::from("match on IMAP email header (Name: Value format)"),
        url: String::from("/rules/imap-keywords.html#imap.email.header"),
        setup: imap_msg_header_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);

    G_IMAP_MSG_HEADER_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"imap.email.header\0".as_ptr() as *const libc::c_char,
        b"IMAP EMAIL HEADER\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(imap_tx_get_msg_header),
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("imap.email.header.name"),
        desc: String::from("match on IMAP email header name"),
        url: String::from("/rules/imap-keywords.html#imap.email.header.name"),
        setup: imap_msg_header_name_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);

    G_IMAP_MSG_HEADER_NAME_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"imap.email.header.name\0".as_ptr() as *const libc::c_char,
        b"IMAP EMAIL HEADER NAME\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(imap_tx_get_msg_header_name),
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("imap.email.header.value"),
        desc: String::from("match on IMAP email header value"),
        url: String::from("/rules/imap-keywords.html#imap.email.header.value"),
        setup: imap_msg_header_value_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);

    G_IMAP_MSG_HEADER_VALUE_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"imap.email.header.value\0".as_ptr() as *const libc::c_char,
        b"IMAP EMAIL HEADER VALUE\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(imap_tx_get_msg_header_value),
    );
}
