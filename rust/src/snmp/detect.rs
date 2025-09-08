/* Copyright (C) 2017-2019 Open Information Security Foundation
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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use super::snmp::{SNMPTransaction, SnmpPduType, ALPROTO_SNMP};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{
    detect_parse_uint_enum, DetectUintData, SCDetectU32Free, SCDetectU32Match, SCDetectU32Parse,
};
use crate::detect::{
    helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer, SIGMATCH_INFO_ENUM_UINT,
    SIGMATCH_INFO_UINT32,
};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperBufferRegister, SCDetectHelperKeywordRegister,
    SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList, SCSigTableAppLiteElmt, SigMatchCtx,
    Signature,
};

static mut G_SNMP_VERSION_KW_ID: u16 = 0;
static mut G_SNMP_VERSION_BUFFER_ID: c_int = 0;
static mut G_SNMP_PDUTYPE_KW_ID: u16 = 0;
static mut G_SNMP_PDUTYPE_BUFFER_ID: c_int = 0;
static mut G_SNMP_USM_BUFFER_ID: c_int = 0;
static mut G_SNMP_COMMUNITY_BUFFER_ID: c_int = 0;

unsafe extern "C" fn snmp_detect_version_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    let ctx = SCDetectU32Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_SNMP_VERSION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_SNMP_VERSION_BUFFER_ID,
    )
    .is_null()
    {
        snmp_detect_version_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_version_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, SNMPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    return SCDetectU32Match(tx.version, ctx);
}

unsafe extern "C" fn snmp_detect_version_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    SCDetectU32Free(ctx);
}

unsafe extern "C" fn snmp_detect_pdutype_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u32, SnmpPduType>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn snmp_detect_pdutype_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    let ctx = snmp_detect_pdutype_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_SNMP_PDUTYPE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_SNMP_PDUTYPE_BUFFER_ID,
    )
    .is_null()
    {
        snmp_detect_pdutype_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_pdutype_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, SNMPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    if let Some(ref info) = tx.info {
        let pdu_type = info.pdu_type.0;
        return SCDetectU32Match(pdu_type, ctx);
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_pdutype_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    SCDetectU32Free(ctx);
}

unsafe extern "C" fn snmp_detect_usm_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SNMP_USM_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_usm_get_data(
    tx: *const c_void, _flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SNMPTransaction);
    if let Some(ref c) = tx.usm {
        *buffer = c.as_ptr();
        *buffer_len = c.len() as u32;
        return true;
    }
    return false;
}

unsafe extern "C" fn snmp_detect_community_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SNMP_COMMUNITY_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_community_get_data(
    tx: *const c_void, _flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SNMPTransaction);
    if let Some(ref c) = tx.community {
        *buffer = c.as_ptr();
        *buffer_len = c.len() as u32;
        return true;
    }
    return false;
}

pub(super) unsafe extern "C" fn detect_snmp_register() {
    let kw = SCSigTableAppLiteElmt {
        name: b"snmp.version\0".as_ptr() as *const libc::c_char,
        desc: b"match SNMP version\0".as_ptr() as *const libc::c_char,
        url: b"/rules/snmp-keywords.html#snmp-version\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(snmp_detect_version_match),
        Setup: Some(snmp_detect_version_setup),
        Free: Some(snmp_detect_version_free),
        flags: SIGMATCH_INFO_UINT32,
    };
    G_SNMP_VERSION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_SNMP_VERSION_BUFFER_ID = SCDetectHelperBufferRegister(
        b"snmp.version\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"snmp.pdu_type\0".as_ptr() as *const libc::c_char,
        desc: b"match SNMP PDU type\0".as_ptr() as *const libc::c_char,
        url: b"/rules/snmp-keywords.html#snmp-pdu-type\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(snmp_detect_pdutype_match),
        Setup: Some(snmp_detect_pdutype_setup),
        Free: Some(snmp_detect_pdutype_free),
        flags: SIGMATCH_INFO_UINT32 | SIGMATCH_INFO_ENUM_UINT,
    };
    G_SNMP_PDUTYPE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_SNMP_PDUTYPE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"snmp.pdu_type\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("snmp.usm"),
        desc: String::from("SNMP content modifier to match on the SNMP usm"),
        url: String::from("/rules/snmp-keywords.html#snmp-usm"),
        setup: snmp_detect_usm_setup,
    };
    let _g_snmp_usm_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SNMP_USM_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"snmp.usm\0".as_ptr() as *const libc::c_char,
        b"SNMP USM\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(snmp_detect_usm_get_data),
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("snmp.community"),
        desc: String::from("SNMP content modifier to match on the SNMP community"),
        url: String::from("/rules/snmp-keywords.html#snmp-community"),
        setup: snmp_detect_community_setup,
    };
    let _g_snmp_community_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SNMP_COMMUNITY_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"snmp.community\0".as_ptr() as *const libc::c_char,
        b"SNMP Community identifier\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(snmp_detect_community_get_data),
    );
}
