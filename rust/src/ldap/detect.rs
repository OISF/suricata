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

use super::ldap::{LdapTransaction, ALPROTO_LDAP};
use crate::detect::uint::{
    detect_parse_uint_enum, rs_detect_u8_free, rs_detect_u8_match, DetectUintData,
};
use crate::detect::{
    DetectHelperBufferRegister, DetectHelperKeywordRegister, DetectSignatureSetAppProto,
    SCSigTableElmt, SigMatchAppendSMToList,
};
use crate::ldap::types::{LdapMessage, ProtocolOpCode};

use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::str::FromStr;

pub const DETECT_LDAP_RESP_ANY: i8 = -1;
pub const DETECT_LDAP_RESP_ALL: i8 = -2;

#[derive(Debug, PartialEq)]
pub struct DetectLdapRespData {
    pub response: DetectUintData<u8>, //ldap response code
    pub index: i8,
}

static mut G_LDAP_REQUEST_OPERATION_KW_ID: c_int = 0;
static mut G_LDAP_REQUEST_OPERATION_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_OPERATION_KW_ID: c_int = 0;
static mut G_LDAP_RESPONSES_OPERATION_BUFFER_ID: c_int = 0;

unsafe extern "C" fn ldap_parse_protocol_req_op(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u8, ProtocolOpCode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

pub fn aux_ldap_parse_protocol_resp_op(s: &str) -> Option<DetectLdapRespData> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() > 2 {
        return None;
    }
    let index = if parts.len() == 2 {
        if parts[1] == "all" {
            DETECT_LDAP_RESP_ALL
        } else if parts[1] == "any" {
            DETECT_LDAP_RESP_ANY
        } else {
            let u8_index = i8::from_str(parts[1]).ok()?;
            if u8_index < 0 {
                return None;
            }
            u8_index
        }
    } else {
        DETECT_LDAP_RESP_ANY
    };
    if let Some(ctx) = detect_parse_uint_enum::<u8, ProtocolOpCode>(parts[0]) {
        let response = ctx;
        return Some(DetectLdapRespData { response, index });
    }
    return None;
}

unsafe extern "C" fn ldap_parse_protocol_resp_op(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = aux_ldap_parse_protocol_resp_op(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn ldap_detect_request_operation_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = ldap_parse_protocol_req_op(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_LDAP_REQUEST_OPERATION_KW_ID,
        ctx,
        G_LDAP_REQUEST_OPERATION_BUFFER_ID,
    )
    .is_null()
    {
        ldap_detect_operation_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_responses_operation_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = ldap_parse_protocol_resp_op(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_LDAP_RESPONSES_OPERATION_KW_ID,
        ctx,
        G_LDAP_RESPONSES_OPERATION_BUFFER_ID,
    )
    .is_null()
    {
        ldap_detect_operation_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_request_operation_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(request) = &tx.request {
        let option: u8 = request.protocol_op.to_u8();
        return rs_detect_u8_match(option, ctx);
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_responses_operation_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectLdapRespData);

    match ctx.index {
        DETECT_LDAP_RESP_ANY => {
            for response in &tx.responses {
                let option: u8 = response.protocol_op.to_u8();
                if rs_detect_u8_match(option, &ctx.response) == 1 {
                    return 1;
                }
            }
            return 0;
        }
        DETECT_LDAP_RESP_ALL => {
            for response in &tx.responses {
                let option: u8 = response.protocol_op.to_u8();
                if rs_detect_u8_match(option, &ctx.response) == 0 {
                    return 0;
                }
            }
            return 1;
        }
        _ => {
            let index: usize = ctx.index as usize;
            if tx.responses.len() <= index {
                return 0;
            }
            let response: &LdapMessage = &tx.responses[index];
            let option: u8 = response.protocol_op.to_u8();
            if rs_detect_u8_match(option, &ctx.response) == 1 {
                return 1;
            }
            return 0;
        }
    }
}

unsafe extern "C" fn ldap_detect_operation_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    rs_detect_u8_free(ctx);
}

#[no_mangle]
pub unsafe extern "C" fn ScDetectLdapRegister() {
    let kw = SCSigTableElmt {
        name: b"ldap.request.operation\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAP request operation\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.request.operation\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_request_operation_match),
        Setup: ldap_detect_request_operation_setup,
        Free: Some(ldap_detect_operation_free),
        flags: 0,
    };
    G_LDAP_REQUEST_OPERATION_KW_ID = DetectHelperKeywordRegister(&kw);
    G_LDAP_REQUEST_OPERATION_BUFFER_ID = DetectHelperBufferRegister(
        b"ldap.request.operation\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        false, //to client
        true,  //to server
    );
    let kw = SCSigTableElmt {
        name: b"ldap.responses.operation\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAP responses operation\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.operation\0".as_ptr()
            as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_responses_operation_match),
        Setup: ldap_detect_responses_operation_setup,
        Free: Some(ldap_detect_operation_free),
        flags: 0,
    };
    G_LDAP_RESPONSES_OPERATION_KW_ID = DetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_OPERATION_BUFFER_ID = DetectHelperBufferRegister(
        b"ldap.responses.operation\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        true,  //to client
        false, //to server
    );
}
