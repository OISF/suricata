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

use super::ntp::{NTPTransaction, ALPROTO_NTP};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{
    detect_parse_uint_enum, DetectUintData, SCDetectU8Free, SCDetectU8Match, SCDetectU8Parse,
};
use crate::detect::{
    helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer, SIGMATCH_INFO_ENUM_UINT,
    SIGMATCH_INFO_UINT8, SIGMATCH_SUPPORT_FIREWALL
};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferProgressMpmRegister, SCDetectHelperBufferProgressRegister,
    SCDetectHelperKeywordRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature
};

static mut G_NTP_VERSION_KW_ID: u16 = 0;
static mut G_NTP_MODE_KW_ID: u16 = 0;
static mut G_NTP_STRATUM_KW_ID: u16 = 0;
static mut G_NTP_GENERIC_BUFFER_ID: c_int = 0;
static mut G_NTP_REFERENCE_ID_BUFFER_ID: c_int = 0;

#[derive(Clone, Debug, PartialEq, EnumStringU8)]
#[repr(u8)]
pub enum NTPMode {
    Reserved = 0,
    SymmetricActive = 1,
    SymmetricPassive = 2,
    Client = 3,
    Server = 4,
    Broadcast = 5,
    Control = 6,
    Private = 7,
}

unsafe extern "C" fn ntp_detect_version_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_NTP) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_NTP_VERSION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_NTP_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        ntp_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ntp_detect_version_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, NTPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return SCDetectU8Match(tx.version, ctx);
}

unsafe extern "C" fn ntp_detect_u8_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn ntp_detect_mode_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_NTP) != 0 {
        return -1;
    }
    let ctx = ntp_parse_mode(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_NTP_MODE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_NTP_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        ntp_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ntp_parse_mode(ustr: *const std::os::raw::c_char) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr);
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u8, NTPMode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed);
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn ntp_detect_mode_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, NTPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return SCDetectU8Match(tx.mode, ctx);
}

unsafe extern "C" fn ntp_detect_stratum_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_NTP) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_NTP_STRATUM_KW_ID,
        ctx as *mut SigMatchCtx,
        G_NTP_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        ntp_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ntp_detect_stratum_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, NTPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return SCDetectU8Match(tx.stratum, ctx);
}

unsafe extern "C" fn ntp_detect_reference_id_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_NTP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_NTP_REFERENCE_ID_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ntp_detect_reference_id_get_data(
    tx: *const c_void, _flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, NTPTransaction);
    *buffer = tx.reference_id.as_ptr();
    *buffer_len = tx.reference_id.len() as u32;
    true
}

pub(super) unsafe extern "C" fn detect_ntp_register() {
    let kw = SCSigTableAppLiteElmt {
        name: b"ntp.version\0".as_ptr() as *const libc::c_char,
        desc: b"match NTP version\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ntp-keywords.html#ntp-version\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ntp_detect_version_match),
        Setup: Some(ntp_detect_version_setup),
        Free: Some(ntp_detect_u8_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_SUPPORT_FIREWALL,
    };
    G_NTP_VERSION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_NTP_GENERIC_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"ntp.generic\0".as_ptr() as *const libc::c_char,
        ALPROTO_NTP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        1,
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"ntp.mode\0".as_ptr() as *const libc::c_char,
        desc: b"match NTP mode\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ntp-keywords.html#ntp-mode\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ntp_detect_mode_match),
        Setup: Some(ntp_detect_mode_setup),
        Free: Some(ntp_detect_u8_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_ENUM_UINT | SIGMATCH_SUPPORT_FIREWALL,
    };
    G_NTP_MODE_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"ntp.stratum\0".as_ptr() as *const libc::c_char,
        desc: b"match NTP stratum\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ntp-keywords.html#ntp-stratum\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ntp_detect_stratum_match),
        Setup: Some(ntp_detect_stratum_setup),
        Free: Some(ntp_detect_u8_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_SUPPORT_FIREWALL,
    };
    G_NTP_STRATUM_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SigTableElmtStickyBuffer {
        name: String::from("ntp.reference_id"),
        desc: String::from("sticky buffer to match on the NTP reference ID"),
        url: String::from("/rules/ntp-keywords.html#ntp-reference-id"),
        setup: ntp_detect_reference_id_setup,
    };
    let _g_ntp_reference_id_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_NTP_REFERENCE_ID_BUFFER_ID = SCDetectHelperBufferProgressMpmRegister(
        b"ntp.reference_id\0".as_ptr() as *const libc::c_char,
        b"NTP reference ID\0".as_ptr() as *const libc::c_char,
        ALPROTO_NTP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(ntp_detect_reference_id_get_data),
        1,
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    #[test]
    fn test_ntp_parse_known_mode_strings() {
        let ctx = detect_parse_uint_enum::<u8, NTPMode>("reserved").unwrap();
        assert_eq!(ctx.arg1, 0);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, NTPMode>("symmetric_active").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, NTPMode>("symmetric_passive").unwrap();
        assert_eq!(ctx.arg1, 2);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, NTPMode>("client").unwrap();
        assert_eq!(ctx.arg1, 3);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, NTPMode>("server").unwrap();
        assert_eq!(ctx.arg1, 4);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, NTPMode>("broadcast").unwrap();
        assert_eq!(ctx.arg1, 5);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, NTPMode>("control").unwrap();
        assert_eq!(ctx.arg1, 6);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, NTPMode>("private").unwrap();
        assert_eq!(ctx.arg1, 7);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
    }

    #[test]
    fn test_ntp_parse_mode_integer() {
        let ctx = detect_parse_uint_enum::<u8, NTPMode>("255").unwrap();
        assert_eq!(ctx.arg1, 255);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
    }

    #[test]
    fn test_ntp_parse_mode_invalid() {
        assert!(detect_parse_uint_enum::<u8, NTPMode>("invalid_mode").is_none());
        assert!(detect_parse_uint_enum::<u8, NTPMode>("symmetric_private").is_none());
        assert!(detect_parse_uint_enum::<u8, NTPMode>("256").is_none());
    }
}
