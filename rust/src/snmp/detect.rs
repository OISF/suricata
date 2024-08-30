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

use super::snmp::{SNMPTransaction, ALPROTO_SNMP};
use crate::detect::uint::{
    rs_detect_u32_free, rs_detect_u32_match, rs_detect_u32_parse, DetectUintData,
};
use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperBufferRegister,
    DetectHelperGetData, DetectHelperKeywordRegister, DetectSignatureSetAppProto, SCSigTableElmt,
    SigMatchAppendSMToList, SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
};
use std::os::raw::{c_int, c_void};

static mut G_SNMP_VERSION_KW_ID: c_int = 0;
static mut G_SNMP_VERSION_BUFFER_ID: c_int = 0;
static mut G_SNMP_PDUTYPE_KW_ID: c_int = 0;
static mut G_SNMP_PDUTYPE_BUFFER_ID: c_int = 0;
static mut G_SNMP_USM_BUFFER_ID: c_int = 0;
static mut G_SNMP_COMMUNITY_BUFFER_ID: c_int = 0;

unsafe extern "C" fn snmp_detect_version_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    let ctx = rs_detect_u32_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(de, s, G_SNMP_VERSION_KW_ID, ctx, G_SNMP_VERSION_BUFFER_ID).is_null()
    {
        snmp_detect_version_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_version_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, SNMPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    return rs_detect_u32_match(tx.version, ctx);
}

unsafe extern "C" fn snmp_detect_version_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    rs_detect_u32_free(ctx);
}

unsafe extern "C" fn snmp_detect_pdutype_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    let ctx = rs_detect_u32_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(de, s, G_SNMP_PDUTYPE_KW_ID, ctx, G_SNMP_PDUTYPE_BUFFER_ID).is_null()
    {
        snmp_detect_pdutype_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_pdutype_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, SNMPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    if let Some(ref info) = tx.info {
        let pdu_type = info.pdu_type.0;
        return rs_detect_u32_match(pdu_type, ctx);
    }
    return 0;
}

unsafe extern "C" fn snmp_detect_pdutype_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    rs_detect_u32_free(ctx);
}

pub unsafe extern "C" fn snmp_detect_usm_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SNMP_USM_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn snmp_detect_usm_get(
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

pub unsafe extern "C" fn snmp_detect_usm_get_data(
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
        snmp_detect_usm_get,
    );
}

pub unsafe extern "C" fn snmp_detect_community_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SNMP_COMMUNITY_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn snmp_detect_community_get(
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

pub unsafe extern "C" fn snmp_detect_community_get_data(
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
        snmp_detect_community_get,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ScDetectSNMPRegister() {
    let kw = SCSigTableElmt {
        name: b"snmp.version\0".as_ptr() as *const libc::c_char,
        desc: b"match SNMP version\0".as_ptr() as *const libc::c_char,
        url: b"/rules/snmp-keywords.html#snmp-version\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(snmp_detect_version_match),
        Setup: snmp_detect_version_setup,
        Free: Some(snmp_detect_version_free),
        flags: 0,
    };
    G_SNMP_VERSION_KW_ID = DetectHelperKeywordRegister(&kw);
    G_SNMP_VERSION_BUFFER_ID = DetectHelperBufferRegister(
        b"snmp.version\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        true,
        true,
    );

    let kw = SCSigTableElmt {
        name: b"snmp.pdu_type\0".as_ptr() as *const libc::c_char,
        desc: b"match SNMP PDU type\0".as_ptr() as *const libc::c_char,
        url: b"/rules/snmp-keywords.html#snmp-pdu-type\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(snmp_detect_pdutype_match),
        Setup: snmp_detect_pdutype_setup,
        Free: Some(snmp_detect_pdutype_free),
        flags: 0,
    };
    G_SNMP_PDUTYPE_KW_ID = DetectHelperKeywordRegister(&kw);
    G_SNMP_PDUTYPE_BUFFER_ID = DetectHelperBufferRegister(
        b"snmp.pdu_type\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        true,
        true,
    );

    let kw = SCSigTableElmt {
        name: b"snmp.usm\0".as_ptr() as *const libc::c_char,
        desc: b"SNMP content modifier to match on the SNMP usm\0".as_ptr() as *const libc::c_char,
        url: b"/rules/snmp-keywords.html#snmp-usm\0".as_ptr() as *const libc::c_char,
        Setup: snmp_detect_usm_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_snmp_usm_kw_id = DetectHelperKeywordRegister(&kw);
    G_SNMP_USM_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"snmp.usm\0".as_ptr() as *const libc::c_char,
        b"SNMP USM\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        true,
        true,
        snmp_detect_usm_get_data,
    );

    let kw = SCSigTableElmt {
        name: b"snmp.community\0".as_ptr() as *const libc::c_char,
        desc: b"SNMP content modifier to match on the SNMP community\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/snmp-keywords.html#snmp-community\0".as_ptr() as *const libc::c_char,
        Setup: snmp_detect_community_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_snmp_community_kw_id = DetectHelperKeywordRegister(&kw);
    G_SNMP_COMMUNITY_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"snmp.community\0".as_ptr() as *const libc::c_char,
        b"SNMP Community identifier\0".as_ptr() as *const libc::c_char,
        ALPROTO_SNMP,
        true,
        true,
        snmp_detect_community_get_data,
    );
}
