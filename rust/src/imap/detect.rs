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
use crate::detect::{
    SIGMATCH_INFO_MULTI_BUFFER, SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
    SIGMATCH_SUPPORT_FIREWALL,
};
use crate::imap::imap::{ImapTransaction, ALPROTO_IMAP};
use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperKeywordRegister, SCDetectHelperKeywordSetCleanCString,
    SCDetectHelperMultiBufferProgressMpmRegister, SCDetectSignatureSetAppProto,
    SCSigTableAppLiteElmt, Signature,
};

static mut G_IMAP_REQUEST_BUFFER_ID: c_int = 0;
static mut G_IMAP_RESPONSE_BUFFER_ID: c_int = 0;

#[derive(Clone, Copy)]
enum EmailField {
    Body,
    Command,
    BodyMd5,
}

#[derive(Clone, Copy)]
enum EmailList {
    Header,
    HeaderName,
    HeaderValue,
}

fn get_email_field(
    tx: &ImapTransaction, flow_flags: u8, local_id: u32, field: EmailField,
) -> Option<&[u8]> {
    tx.parsed_emails
        .iter()
        .filter(|email| (email.direction & flow_flags) != 0)
        .filter_map(|email| {
            let value = match field {
                EmailField::Body => email.body.as_slice(),
                EmailField::Command => email.command.as_slice(),
                EmailField::BodyMd5 => email.body_md5.as_deref()?.as_bytes(),
            };
            (!value.is_empty()).then_some(value)
        })
        .nth(local_id as usize)
}

fn get_email_list_entry(
    tx: &ImapTransaction, flow_flags: u8, local_id: u32, list: EmailList,
) -> Option<&[u8]> {
    let mut index = local_id as usize;
    for email in &tx.parsed_emails {
        if (email.direction & flow_flags) == 0 {
            continue;
        }
        if index < email.headers.len() {
            let header = &email.headers[index];
            return Some(match list {
                EmailList::Header => header.data.as_slice(),
                EmailList::HeaderName => &header.data[..header.name_len],
                EmailList::HeaderValue => &header.data[header.value_offset..],
            });
        }
        index -= email.headers.len();
    }
    None
}

fn get_email_header_value<'a>(
    tx: &'a ImapTransaction, flow_flags: u8, local_id: u32, header_name: &[u8],
) -> Option<&'a [u8]> {
    let mut index = local_id;
    for email in &tx.parsed_emails {
        if (email.direction & flow_flags) == 0 {
            continue;
        }
        for header in &email.headers {
            let name = &header.data[..header.name_len];
            if name.eq_ignore_ascii_case(header_name) {
                if index == 0 {
                    return Some(&header.data[header.value_offset..]);
                }
                index -= 1;
            }
        }
    }
    None
}

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
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(value) = get_email_field(tx, flow_flags, local_id, EmailField::Body) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetHeader(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(value) = get_email_list_entry(tx, flow_flags, local_id, EmailList::Header) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetHeaderName(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(value) = get_email_list_entry(tx, flow_flags, local_id, EmailList::HeaderName) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetHeaderValue(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(value) = get_email_list_entry(tx, flow_flags, local_id, EmailList::HeaderValue) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetData(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
    hname: *const libc::c_char,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    let hname = CStr::from_ptr(hname);
    if let Some(value) = get_email_header_value(tx, flow_flags, local_id, hname.to_bytes()) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetDataArray(
    tx: *const c_void, flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
    hname: *const libc::c_char, idx: u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    let hname = CStr::from_ptr(hname);
    if let Some(value) = get_email_header_value(tx, flow_flags, idx, hname.to_bytes()) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetCommand(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(value) = get_email_field(tx, flow_flags, local_id, EmailField::Command) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapEmailGetBodyMd5(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    if let Some(value) = get_email_field(tx, flow_flags, local_id, EmailField::BodyMd5) {
        *buffer = value.as_ptr();
        *buffer_len = value.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectImapRegister() {
    let name = CString::new("imap.request").unwrap().into_raw();
    let desc = CString::new("match on IMAP request line")
        .unwrap()
        .into_raw();
    let url = CString::new("/rules/imap-keywords.html#imap-request")
        .unwrap()
        .into_raw();
    let kw = SCSigTableAppLiteElmt {
        name,
        desc,
        url,
        Setup: Some(imap_detect_request_setup),
        flags: SIGMATCH_NOOPT
            | SIGMATCH_INFO_STICKY_BUFFER
            | SIGMATCH_INFO_MULTI_BUFFER
            | SIGMATCH_SUPPORT_FIREWALL,
        AppLayerTxMatch: None,
        Free: None,
    };
    let r = SCDetectHelperKeywordRegister(&kw);
    SCDetectHelperKeywordSetCleanCString(r);

    G_IMAP_REQUEST_BUFFER_ID = SCDetectHelperMultiBufferProgressMpmRegister(
        b"imap.request\0".as_ptr() as *const libc::c_char,
        b"IMAP REQUEST LINE\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOSERVER,
        Some(imap_tx_get_request),
        0,
    );

    let name = CString::new("imap.response").unwrap().into_raw();
    let desc = CString::new("match on IMAP response line")
        .unwrap()
        .into_raw();
    let url = CString::new("/rules/imap-keywords.html#imap-response")
        .unwrap()
        .into_raw();
    let kw = SCSigTableAppLiteElmt {
        name,
        desc,
        url,
        Setup: Some(imap_detect_response_setup),
        flags: SIGMATCH_NOOPT
            | SIGMATCH_INFO_STICKY_BUFFER
            | SIGMATCH_INFO_MULTI_BUFFER
            | SIGMATCH_SUPPORT_FIREWALL,
        AppLayerTxMatch: None,
        Free: None,
    };
    let r = SCDetectHelperKeywordRegister(&kw);
    SCDetectHelperKeywordSetCleanCString(r);

    G_IMAP_RESPONSE_BUFFER_ID = SCDetectHelperMultiBufferProgressMpmRegister(
        b"imap.response\0".as_ptr() as *const libc::c_char,
        b"IMAP RESPONSE LINE\0".as_ptr() as *const libc::c_char,
        ALPROTO_IMAP,
        STREAM_TOCLIENT,
        Some(imap_tx_get_response),
        1,
    );
}
