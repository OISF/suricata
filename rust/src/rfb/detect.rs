/* Copyright (C) 2020 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>

use super::parser::RFBSecurityResultStatus;
use super::rfb::{RFBTransaction, ALPROTO_RFB};
use crate::detect::uint::{
    detect_match_uint, detect_parse_uint_enum, rs_detect_u32_free, rs_detect_u32_parse,
    DetectUintData,
};
use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperBufferRegister,
    DetectHelperGetData, DetectHelperKeywordRegister, DetectSignatureSetAppProto, SCSigTableElmt,
    SigMatchAppendSMToList, SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::ptr;

unsafe extern "C" fn rfb_name_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, RFBTransaction);
    if let Some(ref r) = tx.tc_server_init {
        let p = &r.name;
        if !p.is_empty() {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return true;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn rfb_name_get(
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
        rfb_name_get_data,
    );
}

static mut G_RFB_NAME_BUFFER_ID: c_int = 0;
static mut G_RFB_SEC_TYPE_KW_ID: c_int = 0;
static mut G_RFB_SEC_TYPE_BUFFER_ID: c_int = 0;
static mut G_RFB_SEC_RESULT_KW_ID: c_int = 0;
static mut G_RFB_SEC_RESULT_BUFFER_ID: c_int = 0;

unsafe extern "C" fn rfb_name_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_RFB) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_RFB_NAME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn rfb_sec_type_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_RFB) != 0 {
        return -1;
    }
    let ctx = rs_detect_u32_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(de, s, G_RFB_SEC_TYPE_KW_ID, ctx, G_RFB_SEC_TYPE_BUFFER_ID).is_null()
    {
        rfb_sec_type_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn rfb_sec_type_match_aux(tx: &mut RFBTransaction, ctx: &DetectUintData<u32>) -> c_int {
    if let Some(r) = tx.chosen_security_type {
        if detect_match_uint(ctx, r) {
            return 1;
        }
    }
    return 0;
}

unsafe extern "C" fn rfb_sec_type_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    let tx = cast_pointer!(tx, RFBTransaction);
    return rfb_sec_type_match_aux(tx, ctx);
}

unsafe extern "C" fn rfb_sec_type_free(_de: *mut c_void, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    rs_detect_u32_free(ctx);
}

unsafe extern "C" fn rfb_parse_sec_result(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u32, RFBSecurityResultStatus>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn rfb_sec_result_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_RFB) != 0 {
        return -1;
    }
    let ctx = rfb_parse_sec_result(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_RFB_SEC_RESULT_KW_ID,
        ctx,
        G_RFB_SEC_RESULT_BUFFER_ID,
    )
    .is_null()
    {
        rfb_sec_result_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn rfb_sec_result_match_aux(tx: &RFBTransaction, ctx: &DetectUintData<u32>) -> c_int {
    if let Some(r) = &tx.tc_security_result {
        if detect_match_uint(ctx, r.status) {
            return 1;
        }
    }
    return 0;
}

unsafe extern "C" fn rfb_sec_result_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, RFBTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    return rfb_sec_result_match_aux(tx, ctx);
}

unsafe extern "C" fn rfb_sec_result_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    rs_detect_u32_free(ctx);
}

#[no_mangle]
pub unsafe extern "C" fn ScDetectRfbRegister() {
    let kw = SCSigTableElmt {
        name: b"rfb.name\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the RFB desktop name\0".as_ptr() as *const libc::c_char,
        url: b"/rules/rfb-keywords.html#rfb-name\0".as_ptr() as *const libc::c_char,
        Setup: rfb_name_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_rfb_name_kw_id = DetectHelperKeywordRegister(&kw);
    G_RFB_NAME_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"rfb.name\0".as_ptr() as *const libc::c_char,
        b"rfb name\0".as_ptr() as *const libc::c_char,
        ALPROTO_RFB,
        true, //toclient
        false,
        rfb_name_get,
    );
    let kw = SCSigTableElmt {
        name: b"rfb.sectype\0".as_ptr() as *const libc::c_char,
        desc: b"match RFB security type\0".as_ptr() as *const libc::c_char,
        url: b"/rules/rfb-keywords.html#rfb-sectype\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(rfb_sec_type_match),
        Setup: rfb_sec_type_setup,
        Free: Some(rfb_sec_type_free),
        flags: 0,
    };
    G_RFB_SEC_TYPE_KW_ID = DetectHelperKeywordRegister(&kw);
    G_RFB_SEC_TYPE_BUFFER_ID = DetectHelperBufferRegister(
        b"rfb.sectype\0".as_ptr() as *const libc::c_char,
        ALPROTO_RFB,
        false, // only to server
        true,
    );
    let kw = SCSigTableElmt {
        name: b"rfb.secresult\0".as_ptr() as *const libc::c_char,
        desc: b"match RFB security result\0".as_ptr() as *const libc::c_char,
        url: b"/rules/rfb-keywords.html#rfb-secresult\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(rfb_sec_result_match),
        Setup: rfb_sec_result_setup,
        Free: Some(rfb_sec_result_free),
        flags: 0,
    };
    G_RFB_SEC_RESULT_KW_ID = DetectHelperKeywordRegister(&kw);
    G_RFB_SEC_RESULT_BUFFER_ID = DetectHelperBufferRegister(
        b"rfb.secresult\0".as_ptr() as *const libc::c_char,
        ALPROTO_RFB,
        true, // only to client
        false,
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    #[test]
    fn test_rfb_parse_sec_result() {
        let ctx = detect_parse_uint_enum::<u32, RFBSecurityResultStatus>("fail").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
        assert!(detect_parse_uint_enum::<u32, RFBSecurityResultStatus>("invalidopt").is_none());
    }
}
