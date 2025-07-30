/* Copyright (C) 2022 Open Information Security Foundation
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

use super::dhcp::{
    DHCPTransaction, ALPROTO_DHCP, DHCP_OPT_ADDRESS_TIME, DHCP_OPT_REBINDING_TIME,
    DHCP_OPT_RENEWAL_TIME,
};
use super::parser::DHCPOptionWrapper;
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{DetectUintData, SCDetectU64Free, SCDetectU64Match, SCDetectU64Parse};
use crate::detect::SIGMATCH_INFO_UINT64;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectHelperBufferRegister,
    SCDetectHelperKeywordRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

fn dhcp_tx_get_time(tx: &DHCPTransaction, code: u8) -> Option<u64> {
    for option in &tx.message.options {
        if option.code == code {
            if let DHCPOptionWrapper::TimeValue(ref time_value) = option.option {
                return Some(time_value.seconds as u64);
            }
        }
    }
    return None;
}

static mut G_DHCP_LEASE_TIME_KW_ID: u16 = 0;
static mut G_DHCP_LEASE_TIME_BUFFER_ID: c_int = 0;
static mut G_DHCP_REBINDING_TIME_KW_ID: u16 = 0;
static mut G_DHCP_REBINDING_TIME_BUFFER_ID: c_int = 0;
static mut G_DHCP_RENEWAL_TIME_KW_ID: u16 = 0;
static mut G_DHCP_RENEWAL_TIME_BUFFER_ID: c_int = 0;

unsafe extern "C" fn dhcp_detect_leasetime_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DHCP) != 0 {
        return -1;
    }
    let ctx = SCDetectU64Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DHCP_LEASE_TIME_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DHCP_LEASE_TIME_BUFFER_ID,
    )
    .is_null()
    {
        dhcp_detect_time_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dhcp_detect_leasetime_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, DHCPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u64>);
    if let Some(val) = dhcp_tx_get_time(tx, DHCP_OPT_ADDRESS_TIME) {
        return SCDetectU64Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn dhcp_detect_time_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u64>);
    SCDetectU64Free(ctx);
}

unsafe extern "C" fn dhcp_detect_rebindingtime_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DHCP) != 0 {
        return -1;
    }
    let ctx = SCDetectU64Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DHCP_REBINDING_TIME_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DHCP_REBINDING_TIME_BUFFER_ID,
    )
    .is_null()
    {
        dhcp_detect_time_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dhcp_detect_rebindingtime_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, DHCPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u64>);
    if let Some(val) = dhcp_tx_get_time(tx, DHCP_OPT_REBINDING_TIME) {
        return SCDetectU64Match(val, ctx);
    }
    return 0;
}

unsafe extern "C" fn dhcp_detect_renewaltime_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DHCP) != 0 {
        return -1;
    }
    let ctx = SCDetectU64Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DHCP_RENEWAL_TIME_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DHCP_RENEWAL_TIME_BUFFER_ID,
    )
    .is_null()
    {
        dhcp_detect_time_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dhcp_detect_renewaltime_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, DHCPTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u64>);
    if let Some(val) = dhcp_tx_get_time(tx, DHCP_OPT_RENEWAL_TIME) {
        return SCDetectU64Match(val, ctx);
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectDHCPRegister() {
    let kw = SCSigTableAppLiteElmt {
        name: b"dhcp.leasetime\0".as_ptr() as *const libc::c_char,
        desc: b"match DHCP leasetime\0".as_ptr() as *const libc::c_char,
        url: b"/rules/dhcp-keywords.html#dhcp-leasetime\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dhcp_detect_leasetime_match),
        Setup: Some(dhcp_detect_leasetime_setup),
        Free: Some(dhcp_detect_time_free),
        flags: SIGMATCH_INFO_UINT64,
    };
    G_DHCP_LEASE_TIME_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_DHCP_LEASE_TIME_BUFFER_ID = SCDetectHelperBufferRegister(
        b"dhcp.leasetime\0".as_ptr() as *const libc::c_char,
        ALPROTO_DHCP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"dhcp.rebinding_time\0".as_ptr() as *const libc::c_char,
        desc: b"match DHCP rebinding time\0".as_ptr() as *const libc::c_char,
        url: b"/rules/dhcp-keywords.html#dhcp-rebinding-time\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dhcp_detect_rebindingtime_match),
        Setup: Some(dhcp_detect_rebindingtime_setup),
        Free: Some(dhcp_detect_time_free),
        flags: SIGMATCH_INFO_UINT64,
    };
    G_DHCP_REBINDING_TIME_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_DHCP_REBINDING_TIME_BUFFER_ID = SCDetectHelperBufferRegister(
        b"dhcp.rebinding-time\0".as_ptr() as *const libc::c_char,
        ALPROTO_DHCP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"dhcp.renewal_time\0".as_ptr() as *const libc::c_char,
        desc: b"match DHCP renewal time\0".as_ptr() as *const libc::c_char,
        url: b"/rules/dhcp-keywords.html#dhcp-renewal-time\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dhcp_detect_renewaltime_match),
        Setup: Some(dhcp_detect_renewaltime_setup),
        Free: Some(dhcp_detect_time_free),
        flags: SIGMATCH_INFO_UINT64,
    };
    G_DHCP_RENEWAL_TIME_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_DHCP_RENEWAL_TIME_BUFFER_ID = SCDetectHelperBufferRegister(
        b"dhcp.renewal-time\0".as_ptr() as *const libc::c_char,
        ALPROTO_DHCP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
}
