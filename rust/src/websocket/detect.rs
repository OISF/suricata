/* Copyright (C) 2023 Open Information Security Foundation
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

use super::websocket::{WebSocketTransaction, ALPROTO_WEBSOCKET};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{
    detect_parse_uint, detect_parse_uint_enum, DetectUintData, DetectUintMode, SCDetectU32Free,
    SCDetectU32Match, SCDetectU32Parse, SCDetectU8Free, SCDetectU8Match,
};
use crate::detect::{
    helper_keyword_register_sticky_buffer, DetectHelperBufferMpmRegister, DetectHelperGetData,
    DetectSignatureSetAppProto, SigMatchAppendSMToList, SigTableElmtStickyBuffer,
};
use crate::websocket::parser::WebSocketOpcode;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferRegister, SCDetectHelperKeywordRegister, SCSigTableAppLiteElmt,
    SigMatchCtx, Signature,
};

use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag};
use nom7::combinator::{opt, value};
use nom7::multi::many1;
use nom7::IResult;

use std::ffi::CStr;
use std::os::raw::{c_int, c_void};

unsafe extern "C" fn websocket_parse_opcode(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u8, WebSocketOpcode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

struct WebSocketFlag {
    neg: bool,
    value: u8,
}

fn parse_flag_list_item(s: &str) -> IResult<&str, WebSocketFlag> {
    let (s, _) = opt(is_a(" "))(s)?;
    let (s, neg) = opt(tag("!"))(s)?;
    let neg = neg.is_some();
    let (s, value) = alt((value(0x80, tag("fin")), value(0x40, tag("comp"))))(s)?;
    let (s, _) = opt(is_a(" ,"))(s)?;
    Ok((s, WebSocketFlag { neg, value }))
}

fn parse_flag_list(s: &str) -> IResult<&str, Vec<WebSocketFlag>> {
    return many1(parse_flag_list_item)(s);
}

fn parse_flags(s: &str) -> Option<DetectUintData<u8>> {
    // try first numerical value
    if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
        return Some(ctx);
    }
    // otherwise, try strings for bitmask
    if let Ok((_, l)) = parse_flag_list(s) {
        let mut arg1 = 0;
        let mut arg2 = 0;
        for elem in l.iter() {
            if elem.value & arg1 != 0 {
                SCLogWarning!("Repeated bitflag for websocket.flags");
                return None;
            }
            arg1 |= elem.value;
            if !elem.neg {
                arg2 |= elem.value;
            }
        }
        let ctx = DetectUintData::<u8> {
            arg1,
            arg2,
            mode: DetectUintMode::DetectUintModeBitmask,
        };
        return Some(ctx);
    }
    return None;
}

unsafe extern "C" fn websocket_parse_flags(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = parse_flags(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

static mut G_WEBSOCKET_OPCODE_KW_ID: c_int = 0;
static mut G_WEBSOCKET_OPCODE_BUFFER_ID: c_int = 0;
static mut G_WEBSOCKET_MASK_KW_ID: c_int = 0;
static mut G_WEBSOCKET_MASK_BUFFER_ID: c_int = 0;
static mut G_WEBSOCKET_FLAGS_KW_ID: c_int = 0;
static mut G_WEBSOCKET_FLAGS_BUFFER_ID: c_int = 0;
static mut G_WEBSOCKET_PAYLOAD_BUFFER_ID: c_int = 0;

unsafe extern "C" fn websocket_detect_opcode_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) != 0 {
        return -1;
    }
    let ctx = websocket_parse_opcode(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_WEBSOCKET_OPCODE_KW_ID,
        ctx,
        G_WEBSOCKET_OPCODE_BUFFER_ID,
    )
    .is_null()
    {
        websocket_detect_opcode_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn websocket_detect_opcode_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, WebSocketTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return SCDetectU8Match(tx.pdu.opcode, ctx);
}

unsafe extern "C" fn websocket_detect_opcode_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn websocket_detect_mask_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) != 0 {
        return -1;
    }
    let ctx = SCDetectU32Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_WEBSOCKET_MASK_KW_ID,
        ctx,
        G_WEBSOCKET_MASK_BUFFER_ID,
    )
    .is_null()
    {
        websocket_detect_mask_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn websocket_detect_mask_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, WebSocketTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    if let Some(xorkey) = tx.pdu.mask {
        return SCDetectU32Match(xorkey, ctx);
    }
    return 0;
}

unsafe extern "C" fn websocket_detect_mask_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    SCDetectU32Free(ctx);
}

unsafe extern "C" fn websocket_detect_flags_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) != 0 {
        return -1;
    }
    let ctx = websocket_parse_flags(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_WEBSOCKET_FLAGS_KW_ID,
        ctx,
        G_WEBSOCKET_FLAGS_BUFFER_ID,
    )
    .is_null()
    {
        websocket_detect_flags_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn websocket_detect_flags_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, WebSocketTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return SCDetectU8Match(tx.pdu.flags, ctx);
}

unsafe extern "C" fn websocket_detect_flags_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

pub unsafe extern "C" fn websocket_detect_payload_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_WEBSOCKET_PAYLOAD_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn websocket_detect_payload_get(
    tx: *const c_void, _flow_flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, WebSocketTransaction);
    *buffer = tx.pdu.payload.as_ptr();
    *buffer_len = tx.pdu.payload.len() as u32;
    return true;
}

pub unsafe extern "C" fn websocket_detect_payload_get_data(
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
        websocket_detect_payload_get,
    );
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectWebsocketRegister() {
    let kw = SCSigTableAppLiteElmt {
        name: b"websocket.opcode\0".as_ptr() as *const libc::c_char,
        desc: b"match WebSocket opcode\0".as_ptr() as *const libc::c_char,
        url: b"/rules/websocket-keywords.html#websocket-opcode\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(websocket_detect_opcode_match),
        Setup: Some(websocket_detect_opcode_setup),
        Free: Some(websocket_detect_opcode_free),
        flags: 0,
    };
    G_WEBSOCKET_OPCODE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_WEBSOCKET_OPCODE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"websocket.opcode\0".as_ptr() as *const libc::c_char,
        ALPROTO_WEBSOCKET,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"websocket.mask\0".as_ptr() as *const libc::c_char,
        desc: b"match WebSocket mask\0".as_ptr() as *const libc::c_char,
        url: b"/rules/websocket-keywords.html#websocket-mask\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(websocket_detect_mask_match),
        Setup: Some(websocket_detect_mask_setup),
        Free: Some(websocket_detect_mask_free),
        flags: 0,
    };
    G_WEBSOCKET_MASK_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_WEBSOCKET_MASK_BUFFER_ID = SCDetectHelperBufferRegister(
        b"websocket.mask\0".as_ptr() as *const libc::c_char,
        ALPROTO_WEBSOCKET,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"websocket.flags\0".as_ptr() as *const libc::c_char,
        desc: b"match WebSocket flags\0".as_ptr() as *const libc::c_char,
        url: b"/rules/websocket-keywords.html#websocket-flags\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(websocket_detect_flags_match),
        Setup: Some(websocket_detect_flags_setup),
        Free: Some(websocket_detect_flags_free),
        flags: 0,
    };
    G_WEBSOCKET_FLAGS_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_WEBSOCKET_FLAGS_BUFFER_ID = SCDetectHelperBufferRegister(
        b"websocket.flags\0".as_ptr() as *const libc::c_char,
        ALPROTO_WEBSOCKET,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("websocket.payload"),
        desc: String::from("match WebSocket payload"),
        url: String::from("/rules/websocket-keywords.html#websocket-payload"),
        setup: websocket_detect_payload_setup,
    };
    let _g_ws_payload_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_WEBSOCKET_PAYLOAD_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"websocket.payload\0".as_ptr() as *const libc::c_char,
        b"WebSocket payload\0".as_ptr() as *const libc::c_char,
        ALPROTO_WEBSOCKET,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        websocket_detect_payload_get_data,
    );
}
