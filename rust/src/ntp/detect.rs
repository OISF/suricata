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
use crate::detect::uint::{DetectUintData, SCDetectU8Free, SCDetectU8Match, SCDetectU8Parse};
use crate::detect::SIGMATCH_INFO_UINT8;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectHelperBufferProgressRegister,
    SCDetectHelperKeywordRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

static mut G_NTP_VERSION_KW_ID: u16 = 0;
static mut G_NTP_GENERIC_BUFFER_ID: c_int = 0;

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
        ntp_detect_version_free(std::ptr::null_mut(), ctx);
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

unsafe extern "C" fn ntp_detect_version_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

pub(super) unsafe extern "C" fn detect_ntp_register() {
    let kw = SCSigTableAppLiteElmt {
        name: b"ntp.version\0".as_ptr() as *const libc::c_char,
        desc: b"match NTP version\0".as_ptr() as *const libc::c_char,
        url: b"/rules/ntp-keywords.html#ntp-version\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(ntp_detect_version_match),
        Setup: Some(ntp_detect_version_setup),
        Free: Some(ntp_detect_version_free),
        flags: SIGMATCH_INFO_UINT8,
    };
    G_NTP_VERSION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_NTP_GENERIC_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"ntp.generic\0".as_ptr() as *const libc::c_char,
        ALPROTO_NTP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        1,
    );
}
