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
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{
    detect_match_uint, detect_parse_array_uint_enum, detect_parse_uint_enum,
    detect_uint_match_at_index, DetectUintArrayData, DetectUintData, SCDetectU32Free,
    SCDetectU32Parse, SCDetectU8Free,
};
use crate::detect::{
    helper_keyword_register_multi_buffer, helper_keyword_register_sticky_buffer,
    SigTableElmtStickyBuffer, SIGMATCH_INFO_ENUM_UINT, SIGMATCH_INFO_MULTI_UINT,
    SIGMATCH_INFO_UINT32, SIGMATCH_INFO_UINT8,
};
use crate::ldap::types::*;
use ldap_parser::ldap::{LdapMessage, ProtocolOp};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperBufferRegister, SCDetectHelperKeywordRegister,
    SCDetectHelperMultiBufferMpmRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

use std::ffi::CStr;
use std::os::raw::{c_int, c_void};

static mut G_LDAP_REQUEST_OPERATION_KW_ID: u16 = 0;
static mut G_LDAP_REQUEST_OPERATION_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_OPERATION_KW_ID: u16 = 0;
static mut G_LDAP_RESPONSES_OPERATION_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_COUNT_KW_ID: u16 = 0;
static mut G_LDAP_RESPONSES_COUNT_BUFFER_ID: c_int = 0;
static mut G_LDAP_REQUEST_DN_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_DN_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_RESULT_CODE_KW_ID: u16 = 0;
static mut G_LDAP_RESPONSES_RESULT_CODE_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_MSG_BUFFER_ID: c_int = 0;
static mut G_LDAP_REQUEST_ATTRIBUTE_TYPE_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_ATTRIBUTE_TYPE_BUFFER_ID: c_int = 0;

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

unsafe extern "C" fn ldap_detect_request_operation_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = ldap_parse_protocol_req_op(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_LDAP_REQUEST_OPERATION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_LDAP_REQUEST_OPERATION_BUFFER_ID,
    )
    .is_null()
    {
        ldap_detect_request_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_request_operation_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(request) = &tx.request {
        let option = request.protocol_op.tag().0 as u8;
        return detect_match_uint(ctx, option) as c_int;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_request_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn ldap_parse_protocol_resp_op(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintArrayData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_array_uint_enum::<u8, ProtocolOpCode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn ldap_detect_responses_operation_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = ldap_parse_protocol_resp_op(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_LDAP_RESPONSES_OPERATION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_LDAP_RESPONSES_OPERATION_BUFFER_ID,
    )
    .is_null()
    {
        ldap_detect_responses_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_responses_operation_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u8>);

    return detect_uint_match_at_index::<LdapMessage, u8>(
        &tx.responses,
        ctx,
        |response| Some(response.protocol_op.tag().0 as u8),
        tx.complete,
    );
}

unsafe extern "C" fn ldap_detect_responses_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u8>);
    std::mem::drop(Box::from_raw(ctx));
}

unsafe extern "C" fn ldap_detect_responses_count_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = SCDetectU32Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_LDAP_RESPONSES_COUNT_KW_ID,
        ctx as *mut SigMatchCtx,
        G_LDAP_RESPONSES_COUNT_BUFFER_ID,
    )
    .is_null()
    {
        ldap_detect_responses_count_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_responses_count_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    let len = tx.responses.len() as u32;
    return detect_match_uint(ctx, len) as c_int;
}

unsafe extern "C" fn ldap_detect_responses_count_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    SCDetectU32Free(ctx);
}

unsafe extern "C" fn ldap_detect_request_dn_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_LDAP_REQUEST_DN_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_request_dn_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);

    *buffer = std::ptr::null();
    *buffer_len = 0;

    if let Some(request) = &tx.request {
        let str_buffer: &str = match &request.protocol_op {
            ProtocolOp::BindRequest(req) => req.name.0.as_ref(),
            ProtocolOp::AddRequest(req) => req.entry.0.as_ref(),
            ProtocolOp::SearchRequest(req) => req.base_object.0.as_ref(),
            ProtocolOp::ModifyRequest(req) => req.object.0.as_ref(),
            ProtocolOp::DelRequest(req) => req.0.as_ref(),
            ProtocolOp::ModDnRequest(req) => req.entry.0.as_ref(),
            ProtocolOp::CompareRequest(req) => req.entry.0.as_ref(),
            _ => return false,
        };
        *buffer = str_buffer.as_ptr();
        *buffer_len = str_buffer.len() as u32;
        return true;
    }
    return false;
}

unsafe extern "C" fn ldap_detect_responses_dn_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_LDAP_RESPONSES_DN_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_tx_get_responses_dn(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);

    if local_id as usize >= tx.responses.len() {
        return false;
    }
    *buffer = std::ptr::null();
    *buffer_len = 0;

    let response = &tx.responses[local_id as usize];
    // We expect every response in one tx to be the same protocol_op
    let str_buffer: &str = match &response.protocol_op {
        ProtocolOp::SearchResultEntry(resp) => resp.object_name.0.as_ref(),
        ProtocolOp::BindResponse(resp) => resp.result.matched_dn.0.as_ref(),
        ProtocolOp::SearchResultDone(resp) => resp.matched_dn.0.as_ref(),
        ProtocolOp::ModifyResponse(resp) => resp.result.matched_dn.0.as_ref(),
        ProtocolOp::AddResponse(resp) => resp.matched_dn.0.as_ref(),
        ProtocolOp::DelResponse(resp) => resp.matched_dn.0.as_ref(),
        ProtocolOp::ModDnResponse(resp) => resp.matched_dn.0.as_ref(),
        ProtocolOp::CompareResponse(resp) => resp.matched_dn.0.as_ref(),
        ProtocolOp::ExtendedResponse(resp) => resp.result.matched_dn.0.as_ref(),
        _ => "",
        // This ensures that the iteration continues,
        // allowing other responses in the transaction to be processed correctly
    };

    *buffer = str_buffer.as_ptr();
    *buffer_len = str_buffer.len() as u32;
    return true;
}

unsafe extern "C" fn ldap_parse_responses_result_code(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintArrayData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_array_uint_enum::<u32, LdapResultCode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn ldap_detect_responses_result_code_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = ldap_parse_responses_result_code(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_LDAP_RESPONSES_RESULT_CODE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_LDAP_RESPONSES_RESULT_CODE_BUFFER_ID,
    )
    .is_null()
    {
        ldap_detect_responses_result_code_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn get_ldap_result_code(response: &LdapMessage) -> Option<u32> {
    return match &response.protocol_op {
        ProtocolOp::BindResponse(resp) => Some(resp.result.result_code.0),
        ProtocolOp::SearchResultDone(resp) => Some(resp.result_code.0),
        ProtocolOp::ModifyResponse(resp) => Some(resp.result.result_code.0),
        ProtocolOp::AddResponse(resp) => Some(resp.result_code.0),
        ProtocolOp::DelResponse(resp) => Some(resp.result_code.0),
        ProtocolOp::ModDnResponse(resp) => Some(resp.result_code.0),
        ProtocolOp::CompareResponse(resp) => Some(resp.result_code.0),
        ProtocolOp::ExtendedResponse(resp) => Some(resp.result.result_code.0),
        _ => None,
    };
}

unsafe extern "C" fn ldap_detect_responses_result_code_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u32>);

    return detect_uint_match_at_index::<LdapMessage, u32>(
        &tx.responses,
        ctx,
        get_ldap_result_code,
        tx.complete,
    );
}

unsafe extern "C" fn ldap_detect_responses_result_code_free(
    _de: *mut DetectEngineCtx, ctx: *mut c_void,
) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u32>);
    std::mem::drop(Box::from_raw(ctx));
}

unsafe extern "C" fn ldap_detect_responses_msg_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_LDAP_RESPONSES_MSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_tx_get_responses_msg(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);

    if local_id as usize >= tx.responses.len() {
        return false;
    }
    *buffer = std::ptr::null();
    *buffer_len = 0;

    let response = &tx.responses[local_id as usize];
    // We expect every response in one tx to be the same protocol_op
    let str_buffer: &str = match &response.protocol_op {
        ProtocolOp::BindResponse(resp) => resp.result.diagnostic_message.0.as_ref(),
        ProtocolOp::SearchResultDone(resp) => resp.diagnostic_message.0.as_ref(),
        ProtocolOp::ModifyResponse(resp) => resp.result.diagnostic_message.0.as_ref(),
        ProtocolOp::AddResponse(resp) => resp.diagnostic_message.0.as_ref(),
        ProtocolOp::DelResponse(resp) => resp.diagnostic_message.0.as_ref(),
        ProtocolOp::ModDnResponse(resp) => resp.diagnostic_message.0.as_ref(),
        ProtocolOp::CompareResponse(resp) => resp.diagnostic_message.0.as_ref(),
        ProtocolOp::ExtendedResponse(resp) => resp.result.diagnostic_message.0.as_ref(),
        _ => "",
        // This ensures that the iteration continues,
        // allowing other responses in the transaction to be processed correctly
    };

    *buffer = str_buffer.as_ptr();
    *buffer_len = str_buffer.len() as u32;
    return true;
}

unsafe extern "C" fn ldap_detect_request_attibute_type_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_LDAP_REQUEST_ATTRIBUTE_TYPE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_tx_get_req_attribute_type(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);

    *buffer = std::ptr::null();
    *buffer_len = 0;
    if let Some(request) = &tx.request {
        let str_buffer: &str = match &request.protocol_op {
            ProtocolOp::SearchRequest(req) => {
                if local_id as usize >= req.attributes.len() {
                    return false;
                }
                req.attributes[local_id as usize].0.as_ref()
            }
            ProtocolOp::ModifyRequest(req) => {
                if local_id as usize >= req.changes.len() {
                    return false;
                }
                req.changes[local_id as usize]
                    .modification
                    .attr_type
                    .0
                    .as_ref()
            }
            ProtocolOp::AddRequest(req) => {
                if local_id as usize >= req.attributes.len() {
                    return false;
                }
                req.attributes[local_id as usize].attr_type.0.as_ref()
            }
            ProtocolOp::CompareRequest(req) => {
                if local_id > 0 {
                    return false;
                }
                req.ava.attribute_desc.0.as_ref()
            }
            _ => return false,
        };
        *buffer = str_buffer.as_ptr();
        *buffer_len = str_buffer.len() as u32;
        return true;
    }
    return false;
}

unsafe extern "C" fn ldap_detect_responses_attibute_type_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_LDAP_RESPONSES_ATTRIBUTE_TYPE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_tx_get_resp_attribute_type(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);

    let mut pos = 0_u32;
    for i in 0..tx.responses.len() {
        let response = &tx.responses[i];
        match &response.protocol_op {
            ProtocolOp::SearchResultEntry(resp) => {
                if local_id < pos + resp.attributes.len() as u32 {
                    let value = &resp.attributes[(local_id - pos) as usize].attr_type.0;
                    *buffer = value.as_ptr(); //unsafe
                    *buffer_len = value.len() as u32;
                    return true;
                } else {
                    pos += resp.attributes.len() as u32;
                }
            }
            _ => continue,
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectLdapRegister() {
    let kw = SCSigTableAppLiteElmt {
        name: b"ldap.request.operation\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAP request operation\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.request.operation\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_request_operation_match),
        Setup: Some(ldap_detect_request_operation_setup),
        Free: Some(ldap_detect_request_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_ENUM_UINT,
    };
    G_LDAP_REQUEST_OPERATION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_LDAP_REQUEST_OPERATION_BUFFER_ID = SCDetectHelperBufferRegister(
        b"ldap.request.operation\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOSERVER,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"ldap.responses.operation\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAP responses operation\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.operation\0".as_ptr()
            as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_responses_operation_match),
        Setup: Some(ldap_detect_responses_operation_setup),
        Free: Some(ldap_detect_responses_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_ENUM_UINT,
    };
    G_LDAP_RESPONSES_OPERATION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_OPERATION_BUFFER_ID = SCDetectHelperBufferRegister(
        b"ldap.responses.operation\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"ldap.responses.count\0".as_ptr() as *const libc::c_char,
        desc: b"match number of LDAP responses\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.count\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_responses_count_match),
        Setup: Some(ldap_detect_responses_count_setup),
        Free: Some(ldap_detect_responses_count_free),
        flags: SIGMATCH_INFO_UINT32,
    };
    G_LDAP_RESPONSES_COUNT_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_COUNT_BUFFER_ID = SCDetectHelperBufferRegister(
        b"ldap.responses.count\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOCLIENT,
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("ldap.request.dn"),
        desc: String::from("match request LDAPDN"),
        url: String::from("/rules/ldap-keywords.html#ldap.request.dn"),
        setup: ldap_detect_request_dn_setup,
    };
    let _g_ldap_request_dn_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_LDAP_REQUEST_DN_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"ldap.request.dn\0".as_ptr() as *const libc::c_char,
        b"LDAP REQUEST DISTINGUISHED_NAME\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOSERVER,
        Some(ldap_detect_request_dn_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("ldap.responses.dn"),
        desc: String::from("match responses LDAPDN"),
        url: String::from("/rules/ldap-keywords.html#ldap.responses.dn"),
        setup: ldap_detect_responses_dn_setup,
    };
    let _g_ldap_responses_dn_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_LDAP_RESPONSES_DN_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"ldap.responses.dn\0".as_ptr() as *const libc::c_char,
        b"LDAP RESPONSES DISTINGUISHED_NAME\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOCLIENT,
        Some(ldap_tx_get_responses_dn),
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"ldap.responses.result_code\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAPResult code\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.result_code\0".as_ptr()
            as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_responses_result_code_match),
        Setup: Some(ldap_detect_responses_result_code_setup),
        Free: Some(ldap_detect_responses_result_code_free),
        flags: SIGMATCH_INFO_UINT32 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_ENUM_UINT,
    };
    G_LDAP_RESPONSES_RESULT_CODE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_RESULT_CODE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"ldap.responses.result_code\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOCLIENT,
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("ldap.responses.message"),
        desc: String::from("match LDAPResult message for responses"),
        url: String::from("/rules/ldap-keywords.html#ldap.responses.message"),
        setup: ldap_detect_responses_msg_setup,
    };
    let _g_ldap_responses_dn_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_LDAP_RESPONSES_MSG_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"ldap.responses.message\0".as_ptr() as *const libc::c_char,
        b"LDAP RESPONSES DISTINGUISHED_NAME\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOCLIENT,
        Some(ldap_tx_get_responses_msg),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("ldap.request.attribute_type"),
        desc: String::from("match request LDAP attribute type"),
        url: String::from("/rules/ldap-keywords.html#ldap.request.attribute_type"),
        setup: ldap_detect_request_attibute_type_setup,
    };
    let _g_ldap_request_attribute_type_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_LDAP_REQUEST_ATTRIBUTE_TYPE_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"ldap.request.attribute_type\0".as_ptr() as *const libc::c_char,
        b"LDAP REQUEST ATTRIBUTE TYPE\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOSERVER,
        Some(ldap_tx_get_req_attribute_type),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("ldap.responses.attribute_type"),
        desc: String::from("match LDAP responses attribute type"),
        url: String::from("/rules/ldap-keywords.html#ldap.responses.attribute_type"),
        setup: ldap_detect_responses_attibute_type_setup,
    };
    let _g_ldap_responses_attribute_type_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_LDAP_RESPONSES_ATTRIBUTE_TYPE_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"ldap.responses.attribute_type\0".as_ptr() as *const libc::c_char,
        b"LDAP RESPONSES ATTRIBUTE TYPE\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        STREAM_TOCLIENT,
        Some(ldap_tx_get_resp_attribute_type),
    );
}
