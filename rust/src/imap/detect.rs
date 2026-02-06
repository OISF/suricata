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

use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_multi_buffer, SigTableElmtStickyBuffer};
use crate::imap::imap::{ImapTransaction, ALPROTO_IMAP};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperMultiBufferMpmRegister, SCDetectSignatureSetAppProto, Signature,
};

static mut G_IMAP_REQUEST_BUFFER_ID: c_int = 0;
static mut G_IMAP_RESPONSE_BUFFER_ID: c_int = 0;

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

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetBody(
    tx: *const c_void, flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(email) = &tx.parsed_email {
        if (email.direction & flow_flags) == 0 {
            return false;
        }
        if !email.body.is_empty() {
            *buffer = email.body.as_ptr();
            *buffer_len = email.body.len() as u32;
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetHeader(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(email) = &tx.parsed_email {
        if (email.direction & flow_flags) == 0 {
            return false;
        }
        if let Some(header) = email.headers.get(local_id as usize) {
            *buffer = header.as_ptr();
            *buffer_len = header.len() as u32;
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetHeaderName(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(email) = &tx.parsed_email {
        if (email.direction & flow_flags) == 0 {
            return false;
        }
        if let Some(name) = email.header_names.get(local_id as usize) {
            *buffer = name.as_ptr();
            *buffer_len = name.len() as u32;
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetHeaderValue(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(email) = &tx.parsed_email {
        if (email.direction & flow_flags) == 0 {
            return false;
        }
        if let Some(value) = email.header_values.get(local_id as usize) {
            *buffer = value.as_ptr();
            *buffer_len = value.len() as u32;
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetData(
    tx: *const c_void, flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
    hname: *const libc::c_char,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(ref parsed) = tx.parsed_email {
        if (parsed.direction & flow_flags) == 0 {
            return false;
        }
        let hname = CStr::from_ptr(hname);
        if let Ok(hname_str) = hname.to_str() {
            let normalized = hname_str.to_lowercase().replace('-', "_");
            for (i, name) in parsed.header_names.iter().enumerate() {
                if name.as_slice() == normalized.as_bytes() {
                    *buffer = parsed.header_values[i].as_ptr();
                    *buffer_len = parsed.header_values[i].len() as u32;
                    return true;
                }
            }
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetDataArray(
    tx: *const c_void, flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
    hname: *const libc::c_char, idx: u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(ref parsed) = tx.parsed_email {
        if (parsed.direction & flow_flags) == 0 {
            return false;
        }
        let hname = CStr::from_ptr(hname);
        if let Ok(hname_str) = hname.to_str() {
            let normalized = hname_str.to_lowercase().replace('-', "_");
            let mut count: u32 = 0;
            for (i, name) in parsed.header_names.iter().enumerate() {
                if name.as_slice() == normalized.as_bytes() {
                    if count == idx {
                        *buffer = parsed.header_values[i].as_ptr();
                        *buffer_len = parsed.header_values[i].len() as u32;
                        return true;
                    }
                    count += 1;
                }
            }
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetCommand(
    tx: *const c_void, flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(email) = &tx.parsed_email {
        if (email.direction & flow_flags) == 0 {
            return false;
        }
        if !email.command.is_empty() {
            *buffer = email.command.as_ptr();
            *buffer_len = email.command.len() as u32;
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
}
