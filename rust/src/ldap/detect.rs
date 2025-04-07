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
    detect_match_uint, detect_parse_uint_enum, DetectUintData, SCDetectU32Free, SCDetectU32Parse,
    SCDetectU8Free,
};
use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperBufferRegister,
    DetectHelperGetData, DetectHelperGetMultiData, DetectHelperKeywordRegister,
    DetectHelperMultiBufferMpmRegister, DetectSignatureSetAppProto, SCSigTableElmt,
    SigMatchAppendSMToList, SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
};
use crate::ldap::types::{LdapMessage, LdapResultCode, ProtocolOp, ProtocolOpCode};

use std::collections::VecDeque;
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::str::FromStr;

#[derive(Debug, PartialEq)]
enum LdapIndex {
    Any,
    All,
    Index(i32),
}

#[derive(Debug, PartialEq)]
struct DetectLdapRespOpData {
    /// Ldap response operation code
    pub du8: DetectUintData<u8>,
    /// Index can be Any to match with any responses index,
    /// All to match if all indices, or an i32 integer
    /// Negative values represent back to front indexing.
    pub index: LdapIndex,
}

struct DetectLdapRespResultData {
    /// Ldap result code
    pub du32: DetectUintData<u32>,
    /// Index can be Any to match with any responses index,
    /// All to match if all indices, or an i32 integer
    /// Negative values represent back to front indexing.
    pub index: LdapIndex,
}

static mut G_LDAP_REQUEST_OPERATION_KW_ID: c_int = 0;
static mut G_LDAP_REQUEST_OPERATION_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_OPERATION_KW_ID: c_int = 0;
static mut G_LDAP_RESPONSES_OPERATION_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_COUNT_KW_ID: c_int = 0;
static mut G_LDAP_RESPONSES_COUNT_BUFFER_ID: c_int = 0;
static mut G_LDAP_REQUEST_DN_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_DN_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_RESULT_CODE_KW_ID: c_int = 0;
static mut G_LDAP_RESPONSES_RESULT_CODE_BUFFER_ID: c_int = 0;
static mut G_LDAP_RESPONSES_MSG_BUFFER_ID: c_int = 0;

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
        ldap_detect_request_free(std::ptr::null_mut(), ctx);
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
        let option = request.protocol_op.to_u8();
        return detect_match_uint(ctx, option) as c_int;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_request_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

fn parse_ldap_index(parts: &[&str]) -> Option<LdapIndex> {
    let index = if parts.len() == 2 {
        match parts[1] {
            "all" => LdapIndex::All,
            "any" => LdapIndex::Any,
            _ => {
                let i32_index = i32::from_str(parts[1]).ok()?;
                LdapIndex::Index(i32_index)
            }
        }
    } else {
        LdapIndex::Any
    };
    return Some(index);
}

fn aux_ldap_parse_protocol_resp_op(s: &str) -> Option<DetectLdapRespOpData> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() > 2 {
        return None;
    }

    let index = parse_ldap_index(&parts)?;
    let du8 = detect_parse_uint_enum::<u8, ProtocolOpCode>(parts[0])?;

    Some(DetectLdapRespOpData { du8, index })
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
        ldap_detect_responses_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn match_at_index<T, U>(
    array: &VecDeque<T>, ctx_value: &DetectUintData<U>, get_value: impl Fn(&T) -> Option<U>,
    detect_match: impl Fn(U, &DetectUintData<U>) -> c_int, index: &LdapIndex,
) -> c_int {
    match index {
        LdapIndex::Any => {
            for response in array {
                if let Some(code) = get_value(response) {
                    if detect_match(code, ctx_value) == 1 {
                        return 1;
                    }
                }
            }
            return 0;
        }
        LdapIndex::All => {
            for response in array {
                if let Some(code) = get_value(response) {
                    if detect_match(code, ctx_value) == 0 {
                        return 0;
                    }
                }
            }
            return 1;
        }
        LdapIndex::Index(idx) => {
            let index = if *idx < 0 {
                // negative values for backward indexing.
                ((array.len() as i32) + idx) as usize
            } else {
                *idx as usize
            };
            if array.len() <= index {
                return 0;
            }
            if let Some(code) = get_value(&array[index]) {
                return detect_match(code, ctx_value);
            }
            return 0;
        }
    }
}

unsafe extern "C" fn ldap_detect_responses_operation_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectLdapRespOpData);

    return match_at_index::<LdapMessage, u8>(
        &tx.responses,
        &ctx.du8,
        |response| Some(response.protocol_op.to_u8()),
        |code, ctx_value| detect_match_uint(ctx_value, code) as c_int,
        &ctx.index,
    );
}

unsafe extern "C" fn ldap_detect_responses_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectLdapRespOpData);
    std::mem::drop(Box::from_raw(ctx));
}

unsafe extern "C" fn ldap_detect_responses_count_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = SCDetectU32Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_LDAP_RESPONSES_COUNT_KW_ID,
        ctx,
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    let len = tx.responses.len() as u32;
    return detect_match_uint(ctx, len) as c_int;
}

unsafe extern "C" fn ldap_detect_responses_count_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    SCDetectU32Free(ctx);
}

unsafe extern "C" fn ldap_detect_request_dn_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_LDAP_REQUEST_DN_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_request_dn_get_data(
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
        ldap_tx_get_request_dn,
    );
}

unsafe extern "C" fn ldap_tx_get_request_dn(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);

    *buffer = std::ptr::null();
    *buffer_len = 0;

    if let Some(request) = &tx.request {
        let str_buffer: &str = match &request.protocol_op {
            ProtocolOp::BindRequest(req) => req.name.0.as_str(),
            ProtocolOp::AddRequest(req) => req.entry.0.as_str(),
            ProtocolOp::SearchRequest(req) => req.base_object.0.as_str(),
            ProtocolOp::ModifyRequest(req) => req.object.0.as_str(),
            ProtocolOp::DelRequest(req) => req.0.as_str(),
            ProtocolOp::ModDnRequest(req) => req.entry.0.as_str(),
            ProtocolOp::CompareRequest(req) => req.entry.0.as_str(),
            _ => return false,
        };
        *buffer = str_buffer.as_ptr();
        *buffer_len = str_buffer.len() as u32;
        return true;
    }
    return false;
}

unsafe extern "C" fn ldap_detect_responses_dn_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_LDAP_RESPONSES_DN_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_responses_dn_get_data(
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
        ldap_tx_get_responses_dn,
    );
}

unsafe extern "C" fn ldap_tx_get_responses_dn(
    tx: *const c_void, _flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
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
        ProtocolOp::SearchResultEntry(resp) => resp.object_name.0.as_str(),
        ProtocolOp::BindResponse(resp) => resp.result.matched_dn.0.as_str(),
        ProtocolOp::SearchResultDone(resp) => resp.matched_dn.0.as_str(),
        ProtocolOp::ModifyResponse(resp) => resp.result.matched_dn.0.as_str(),
        ProtocolOp::AddResponse(resp) => resp.matched_dn.0.as_str(),
        ProtocolOp::DelResponse(resp) => resp.matched_dn.0.as_str(),
        ProtocolOp::ModDnResponse(resp) => resp.matched_dn.0.as_str(),
        ProtocolOp::CompareResponse(resp) => resp.matched_dn.0.as_str(),
        ProtocolOp::ExtendedResponse(resp) => resp.result.matched_dn.0.as_str(),
        _ => "",
        // This ensures that the iteration continues,
        // allowing other responses in the transaction to be processed correctly
    };

    *buffer = str_buffer.as_ptr();
    *buffer_len = str_buffer.len() as u32;
    return true;
}

fn aux_ldap_parse_resp_result_code(s: &str) -> Option<DetectLdapRespResultData> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() > 2 {
        return None;
    }

    let index = parse_ldap_index(&parts)?;
    let du32 = detect_parse_uint_enum::<u32, LdapResultCode>(parts[0])?;

    Some(DetectLdapRespResultData { du32, index })
}

unsafe extern "C" fn ldap_parse_responses_result_code(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = aux_ldap_parse_resp_result_code(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn ldap_detect_responses_result_code_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    let ctx = ldap_parse_responses_result_code(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_LDAP_RESPONSES_RESULT_CODE_KW_ID,
        ctx,
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, LdapTransaction);
    let ctx = cast_pointer!(ctx, DetectLdapRespResultData);

    return match_at_index::<LdapMessage, u32>(
        &tx.responses,
        &ctx.du32,
        get_ldap_result_code,
        |code, ctx_value| detect_match_uint(ctx_value, code) as c_int,
        &ctx.index,
    );
}

unsafe extern "C" fn ldap_detect_responses_result_code_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectLdapRespResultData);
    std::mem::drop(Box::from_raw(ctx));
}

unsafe extern "C" fn ldap_detect_responses_msg_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_LDAP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_LDAP_RESPONSES_MSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ldap_detect_responses_msg_get_data(
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
        ldap_tx_get_responses_msg,
    );
}

unsafe extern "C" fn ldap_tx_get_responses_msg(
    tx: *const c_void, _flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
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
        ProtocolOp::BindResponse(resp) => resp.result.diagnostic_message.0.as_str(),
        ProtocolOp::SearchResultDone(resp) => resp.diagnostic_message.0.as_str(),
        ProtocolOp::ModifyResponse(resp) => resp.result.diagnostic_message.0.as_str(),
        ProtocolOp::AddResponse(resp) => resp.diagnostic_message.0.as_str(),
        ProtocolOp::DelResponse(resp) => resp.diagnostic_message.0.as_str(),
        ProtocolOp::ModDnResponse(resp) => resp.diagnostic_message.0.as_str(),
        ProtocolOp::CompareResponse(resp) => resp.diagnostic_message.0.as_str(),
        ProtocolOp::ExtendedResponse(resp) => resp.result.diagnostic_message.0.as_str(),
        _ => "",
        // This ensures that the iteration continues,
        // allowing other responses in the transaction to be processed correctly
    };

    *buffer = str_buffer.as_ptr();
    *buffer_len = str_buffer.len() as u32;
    return true;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectLdapRegister() {
    let kw = SCSigTableElmt {
        name: b"ldap.request.operation\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAP request operation\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.request.operation\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_request_operation_match),
        Setup: ldap_detect_request_operation_setup,
        Free: Some(ldap_detect_request_free),
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
        Free: Some(ldap_detect_responses_free),
        flags: 0,
    };
    G_LDAP_RESPONSES_OPERATION_KW_ID = DetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_OPERATION_BUFFER_ID = DetectHelperBufferRegister(
        b"ldap.responses.operation\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        true,  //to client
        false, //to server
    );
    let kw = SCSigTableElmt {
        name: b"ldap.responses.count\0".as_ptr() as *const libc::c_char,
        desc: b"match number of LDAP responses\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.count\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_responses_count_match),
        Setup: ldap_detect_responses_count_setup,
        Free: Some(ldap_detect_responses_count_free),
        flags: 0,
    };
    G_LDAP_RESPONSES_COUNT_KW_ID = DetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_COUNT_BUFFER_ID = DetectHelperBufferRegister(
        b"ldap.responses.count\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        true,  //to client
        false, //to server
    );
    let kw = SCSigTableElmt {
        name: b"ldap.request.dn\0".as_ptr() as *const libc::c_char,
        desc: b"match request LDAPDN\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.request.dn\0".as_ptr() as *const libc::c_char,
        Setup: ldap_detect_request_dn_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_ldap_request_dn_kw_id = DetectHelperKeywordRegister(&kw);
    G_LDAP_REQUEST_DN_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"ldap.request.dn\0".as_ptr() as *const libc::c_char,
        b"LDAP REQUEST DISTINGUISHED_NAME\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        false, //to client
        true,  //to server
        ldap_detect_request_dn_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"ldap.responses.dn\0".as_ptr() as *const libc::c_char,
        desc: b"match responses LDAPDN\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.dn\0".as_ptr() as *const libc::c_char,
        Setup: ldap_detect_responses_dn_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_ldap_responses_dn_kw_id = DetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_DN_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"ldap.responses.dn\0".as_ptr() as *const libc::c_char,
        b"LDAP RESPONSES DISTINGUISHED_NAME\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        true,  //to client
        false, //to server
        ldap_detect_responses_dn_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"ldap.responses.result_code\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAPResult code\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.result_code\0".as_ptr()
            as *const libc::c_char,
        AppLayerTxMatch: Some(ldap_detect_responses_result_code_match),
        Setup: ldap_detect_responses_result_code_setup,
        Free: Some(ldap_detect_responses_result_code_free),
        flags: 0,
    };
    G_LDAP_RESPONSES_RESULT_CODE_KW_ID = DetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_RESULT_CODE_BUFFER_ID = DetectHelperBufferRegister(
        b"ldap.responses.result_code\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        true,  //to client
        false, //to server
    );
    let kw = SCSigTableElmt {
        name: b"ldap.responses.message\0".as_ptr() as *const libc::c_char,
        desc: b"match LDAPResult message for responses\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ldap-keywords.html#ldap.responses.message\0".as_ptr() as *const libc::c_char,
        Setup: ldap_detect_responses_msg_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_ldap_responses_dn_kw_id = DetectHelperKeywordRegister(&kw);
    G_LDAP_RESPONSES_MSG_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"ldap.responses.message\0".as_ptr() as *const libc::c_char,
        b"LDAP RESPONSES DISTINGUISHED_NAME\0".as_ptr() as *const libc::c_char,
        ALPROTO_LDAP,
        true,  //to client
        false, //to server
        ldap_detect_responses_msg_get_data,
    );
}
