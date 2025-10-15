/* Copyright (C) 2020-2024 Open Information Security Foundation
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

use super::http2::{
    HTTP2Event, HTTP2Frame, HTTP2FrameTypeData, HTTP2State, HTTP2Transaction, HTTP2TransactionState,
};
use super::parser;
use crate::detect::uint::{
    detect_match_uint, detect_parse_array_uint_enum, detect_uint_match_at_index,
    DetectUintArrayData, DetectUintData, DetectUintIndex, DetectUintMode,
};
use crate::detect::EnumString;
use crate::direction::Direction;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::ffi::CStr;
use std::os::raw::c_void;
use std::rc::Rc;
use suricata_sys::sys::DetectEngineThreadCtx;

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxHasFrametype(
    tx: *mut std::os::raw::c_void, direction: u8, ctx: *const std::os::raw::c_void,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u8>);
    let frames = if direction & Direction::ToServer as u8 != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    return detect_uint_match_at_index::<HTTP2Frame, u8>(
        frames,
        ctx,
        |f| Some(f.header.ftype),
        tx.state >= HTTP2TransactionState::HTTP2StateClosed,
    );
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2ParseFrametype(
    str: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_void {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_array_uint_enum::<u8, parser::HTTP2FrameType>(s) {
            let boxed = Box::new(ctx);
            // DetectUintArrayData<u8> cannot be cbindgend
            return Box::into_raw(boxed) as *mut c_void;
        }
    }
    return std::ptr::null_mut();
}

fn http2_tx_get_errorcode(f: &HTTP2Frame) -> Option<u32> {
    match &f.data {
        HTTP2FrameTypeData::GOAWAY(goaway) => Some(goaway.errorcode),
        HTTP2FrameTypeData::RSTSTREAM(rst) => Some(rst.errorcode),
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxHasErrorCode(
    tx: *mut std::os::raw::c_void, direction: u8, ctx: *const std::os::raw::c_void,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u32>);
    let frames = if direction & Direction::ToServer as u8 != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    return detect_uint_match_at_index::<HTTP2Frame, u32>(
        frames,
        ctx,
        http2_tx_get_errorcode,
        tx.state >= HTTP2TransactionState::HTTP2StateClosed,
    );
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2ParseErrorCode(
    str: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_void {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        // special case for backward compatibility, now parsed as HTTP11_REQUIRED
        if s.to_uppercase() == "HTTP_1_1_REQUIRED" {
            let ctx = DetectUintArrayData::<u32> {
                du: DetectUintData {
                    arg1: parser::HTTP2ErrorCode::Http11Required.into_u(),
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                index: DetectUintIndex::Any,
                start: 0,
                end: 0,
            };
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut c_void;
        }
        if let Some(ctx) = detect_parse_array_uint_enum::<u32, parser::HTTP2ErrorCode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut c_void;
        }
    }
    return std::ptr::null_mut();
}

fn get_http2_priority(frame: &HTTP2Frame) -> Option<u8> {
    return match &frame.data {
        HTTP2FrameTypeData::PRIORITY(prio) => Some(prio.weight),
        HTTP2FrameTypeData::HEADERS(hd) => {
            if let Some(prio) = hd.priority {
                return Some(prio.weight);
            }
            None
        }
        _ => None,
    };
}

fn http2_match_priority(
    tx: &HTTP2Transaction, direction: Direction, ctx: &DetectUintArrayData<u8>,
) -> std::os::raw::c_int {
    let frames = if direction == Direction::ToServer {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    let eof = tx.state >= HTTP2TransactionState::HTTP2StateClosed;
    return detect_uint_match_at_index::<HTTP2Frame, u8>(frames, ctx, get_http2_priority, eof);
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2PriorityMatch(
    tx: *mut std::os::raw::c_void, direction: u8, ctx: *const std::os::raw::c_void,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u8>);
    return http2_match_priority(tx, direction.into(), ctx);
}

fn get_http2_window(frame: &HTTP2Frame) -> Option<u32> {
    if let HTTP2FrameTypeData::WINDOWUPDATE(wu) = &frame.data {
        return Some(wu.sizeinc);
    }
    return None;
}

fn http2_match_window(
    tx: &HTTP2Transaction, direction: Direction, ctx: &DetectUintArrayData<u32>,
) -> std::os::raw::c_int {
    let frames = if direction == Direction::ToServer {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    let eof = tx.state >= HTTP2TransactionState::HTTP2StateClosed;
    return detect_uint_match_at_index::<HTTP2Frame, u32>(frames, ctx, get_http2_window, eof);
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2WindowMatch(
    tx: *mut std::os::raw::c_void, direction: u8, ctx: *const std::os::raw::c_void,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u32>);
    return http2_match_window(tx, direction.into(), ctx);
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2DetectSettingsCtxParse(
    str: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_void {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = parser::http2_parse_settingsctx(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2DetectSettingsCtxFree(ctx: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx as *mut parser::DetectHTTP2settingsSigCtx));
}

fn http2_detect_settings_match(
    set: &[parser::HTTP2FrameSettings], ctx: &parser::DetectHTTP2settingsSigCtx,
) -> std::os::raw::c_int {
    for e in set {
        if e.id == ctx.id {
            match &ctx.value {
                None => {
                    return 1;
                }
                Some(x) => {
                    if detect_match_uint(x, e.value) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

fn http2_detect_settingsctx_match(
    ctx: &parser::DetectHTTP2settingsSigCtx, tx: &HTTP2Transaction, direction: Direction,
) -> std::os::raw::c_int {
    if direction == Direction::ToServer {
        for i in 0..tx.frames_ts.len() {
            if let HTTP2FrameTypeData::SETTINGS(set) = &tx.frames_ts[i].data {
                if http2_detect_settings_match(set, ctx) != 0 {
                    return 1;
                }
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            if let HTTP2FrameTypeData::SETTINGS(set) = &tx.frames_tc[i].data {
                if http2_detect_settings_match(set, ctx) != 0 {
                    return 1;
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2DetectSettingsCtxMatch(
    ctx: *const std::os::raw::c_void, tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, parser::DetectHTTP2settingsSigCtx);
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_detect_settingsctx_match(ctx, tx, direction.into());
}

fn http2_detect_sizeupdate_match(
    blocks: &[parser::HTTP2FrameHeaderBlock], ctx: &DetectUintData<u64>,
) -> std::os::raw::c_int {
    for block in blocks.iter() {
        if block.error == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
            && detect_match_uint(ctx, block.sizeupdate)
        {
            return 1;
        }
    }
    return 0;
}

fn http2_header_blocks(frame: &HTTP2Frame) -> Option<&[parser::HTTP2FrameHeaderBlock]> {
    match &frame.data {
        HTTP2FrameTypeData::HEADERS(hd) => {
            return Some(&hd.blocks);
        }
        HTTP2FrameTypeData::CONTINUATION(hd) => {
            return Some(&hd.blocks);
        }
        HTTP2FrameTypeData::PUSHPROMISE(hd) => {
            return Some(&hd.blocks);
        }
        _ => {}
    }
    return None;
}

fn http2_detect_sizeupdatectx_match(
    ctx: &DetectUintData<u64>, tx: &HTTP2Transaction, direction: Direction,
) -> std::os::raw::c_int {
    if direction == Direction::ToServer {
        for i in 0..tx.frames_ts.len() {
            if let Some(blocks) = http2_header_blocks(&tx.frames_ts[i]) {
                if http2_detect_sizeupdate_match(blocks, ctx) != 0 {
                    return 1;
                }
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            if let Some(blocks) = http2_header_blocks(&tx.frames_tc[i]) {
                if http2_detect_sizeupdate_match(blocks, ctx) != 0 {
                    return 1;
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2DetectSizeUpdateCtxMatch(
    ctx: *const std::os::raw::c_void, tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, DetectUintData<u64>);
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_detect_sizeupdatectx_match(ctx, tx, direction.into());
}

//TODOask better syntax between SCHttp2TxGetHeaderName in argument
// and SCHttp2DetectSizeUpdateCtxMatch explicitly casting
#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHeaderName(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, direction: u8, nb: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    let mut pos = 0_u32;
    match direction.into() {
        Direction::ToServer => {
            for i in 0..tx.frames_ts.len() {
                if let Some(blocks) = http2_header_blocks(&tx.frames_ts[i]) {
                    if nb < pos + blocks.len() as u32 {
                        let value = &blocks[(nb - pos) as usize].name;
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return true;
                    } else {
                        pos += blocks.len() as u32;
                    }
                }
            }
        }
        Direction::ToClient => {
            for i in 0..tx.frames_tc.len() {
                if let Some(blocks) = http2_header_blocks(&tx.frames_tc[i]) {
                    if nb < pos + blocks.len() as u32 {
                        let value = &blocks[(nb - pos) as usize].name;
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return true;
                    } else {
                        pos += blocks.len() as u32;
                    }
                }
            }
        }
    }
    return false;
}

fn http2_frames_get_header_firstvalue<'a>(
    tx: &'a mut HTTP2Transaction, direction: Direction, name: &str,
) -> Result<&'a [u8], ()> {
    let frames = if direction == Direction::ToServer {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for frame in frames {
        if let Some(blocks) = http2_header_blocks(frame) {
            for block in blocks.iter() {
                if block.name.as_ref() == name.as_bytes() {
                    return Ok(&block.value);
                }
            }
        }
    }
    return Err(());
}

// same as http2_frames_get_header_value but returns a new Vec
// instead of using the transaction to store the result slice
pub fn http2_frames_get_header_value_vec(
    tx: &HTTP2Transaction, direction: Direction, name: &str,
) -> Result<Vec<u8>, ()> {
    let mut found = 0;
    let mut vec = Vec::new();
    let frames = if direction == Direction::ToServer {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for frame in frames {
        if let Some(blocks) = http2_header_blocks(frame) {
            for block in blocks.iter() {
                if block.name.as_ref() == name.as_bytes() {
                    if found == 0 {
                        vec.extend_from_slice(&block.value);
                        found = 1;
                    } else if found == 1 && Rc::strong_count(&block.name) <= 2 {
                        vec.extend_from_slice(b", ");
                        vec.extend_from_slice(&block.value);
                        found = 2;
                    } else if Rc::strong_count(&block.name) <= 2 {
                        vec.extend_from_slice(b", ");
                        vec.extend_from_slice(&block.value);
                    }
                }
            }
        }
    }
    if found == 0 {
        return Err(());
    } else {
        return Ok(vec);
    }
}

fn http2_frames_get_header_value<'a>(
    tx: &'a mut HTTP2Transaction, direction: Direction, name: &str,
) -> Result<&'a [u8], ()> {
    let mut found = 0;
    let mut vec = Vec::new();
    let mut single: Result<&[u8], ()> = Err(());
    let frames = if direction == Direction::ToServer {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for frame in frames {
        if let Some(blocks) = http2_header_blocks(frame) {
            for block in blocks.iter() {
                if block.name.as_ref() == name.as_bytes() {
                    if found == 0 {
                        single = Ok(&block.value);
                        found = 1;
                    } else if found == 1 && Rc::strong_count(&block.name) <= 2 {
                        if let Ok(s) = single {
                            vec.extend_from_slice(s);
                        }
                        vec.extend_from_slice(b", ");
                        vec.extend_from_slice(&block.value);
                        found = 2;
                    } else if Rc::strong_count(&block.name) <= 2 {
                        vec.extend_from_slice(b", ");
                        vec.extend_from_slice(&block.value);
                    }
                }
            }
        }
    }
    if found == 0 {
        return Err(());
    } else if found == 1 {
        return single;
    } else {
        tx.escaped.push(vec);
        let idx = tx.escaped.len() - 1;
        let value = &tx.escaped[idx];
        return Ok(value);
    }
}

// we mutate the tx to cache req_line
fn http2_tx_get_req_line(tx: &mut HTTP2Transaction) {
    if !tx.req_line.is_empty() {
        return;
    }
    let empty = Vec::new();
    let mut req_line = Vec::new();
    let method =
        if let Ok(value) = http2_frames_get_header_firstvalue(tx, Direction::ToServer, ":method") {
            value
        } else {
            &empty
        };
    req_line.extend(method);
    req_line.push(b' ');

    let uri =
        if let Ok(value) = http2_frames_get_header_firstvalue(tx, Direction::ToServer, ":path") {
            value
        } else {
            &empty
        };
    req_line.extend(uri);
    req_line.extend(b" HTTP/2\r\n");
    tx.req_line.extend(req_line)
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetRequestLine(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    http2_tx_get_req_line(tx);
    *buffer = tx.req_line.as_ptr(); //unsafe
    *buffer_len = tx.req_line.len() as u32;
    return 1;
}

fn http2_tx_get_resp_line(tx: &mut HTTP2Transaction) {
    if !tx.resp_line.is_empty() {
        return;
    }
    let empty = Vec::new();
    let mut resp_line: Vec<u8> = Vec::new();

    let status =
        if let Ok(value) = http2_frames_get_header_firstvalue(tx, Direction::ToClient, ":status") {
            value
        } else {
            &empty
        };
    resp_line.extend(b"HTTP/2 ");
    resp_line.extend(status);
    resp_line.extend(b"\r\n");
    tx.resp_line.extend(resp_line)
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetResponseLine(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    http2_tx_get_resp_line(tx);
    *buffer = tx.resp_line.as_ptr(); //unsafe
    *buffer_len = tx.resp_line.len() as u32;
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetUri(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_firstvalue(tx, Direction::ToServer, ":path") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetMethod(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_firstvalue(tx, Direction::ToServer, ":method") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHost(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_value(tx, Direction::ToServer, ":authority") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

fn http2_lower(value: &[u8]) -> Option<Vec<u8>> {
    for i in 0..value.len() {
        if value[i].is_ascii_uppercase() {
            // we got at least one upper character, need to transform
            let mut vec: Vec<u8> = Vec::with_capacity(value.len());
            vec.extend_from_slice(value);
            for e in &mut vec {
                e.make_ascii_lowercase();
            }
            return Some(vec);
        }
    }
    return None;
}

// returns a tuple with the value and its size
fn http2_normalize_host(value: &[u8]) -> &[u8] {
    match value.iter().position(|&x| x == b'@') {
        Some(i) => {
            let value = &value[i + 1..];
            match value.iter().position(|&x| x == b':') {
                Some(i) => {
                    return &value[..i];
                }
                None => {
                    return value;
                }
            }
        }
        None => match value.iter().position(|&x| x == b':') {
            Some(i) => {
                return &value[..i];
            }
            None => {
                return value;
            }
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHostNorm(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_value(tx, Direction::ToServer, ":authority") {
        let r = http2_normalize_host(value);
        // r is a tuple with the value and its size
        // this is useful when we only take a substring (before the port)
        match http2_lower(r) {
            Some(normval) => {
                // In case we needed some normalization,
                // the transaction needs to take ownership of this normalized host
                tx.escaped.push(normval);
                let idx = tx.escaped.len() - 1;
                let resvalue = &tx.escaped[idx];
                *buffer = resvalue.as_ptr(); //unsafe
                *buffer_len = resvalue.len() as u32;
                return 1;
            }
            None => {
                *buffer = r.as_ptr(); //unsafe
                *buffer_len = r.len() as u32;
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetUserAgent(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_value(tx, Direction::ToServer, "user-agent") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetStatus(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_firstvalue(tx, Direction::ToClient, ":status") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetCookie(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if direction == u8::from(Direction::ToServer) {
        if let Ok(value) = http2_frames_get_header_value(tx, Direction::ToServer, "cookie") {
            *buffer = value.as_ptr(); //unsafe
            *buffer_len = value.len() as u32;
            return 1;
        }
    } else if let Ok(value) = http2_frames_get_header_value(tx, Direction::ToClient, "set-cookie") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHeaderValue(
    tx: &mut HTTP2Transaction, direction: u8, strname: *const std::os::raw::c_char,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let hname: &CStr = CStr::from_ptr(strname); //unsafe
    if let Ok(s) = hname.to_str() {
        if let Ok(value) = http2_frames_get_header_value(tx, direction.into(), &s.to_lowercase()) {
            *buffer = value.as_ptr(); //unsafe
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    return 0;
}

fn http2_escape_header(blocks: &[parser::HTTP2FrameHeaderBlock], i: u32) -> Vec<u8> {
    //minimum size + 2 for escapes
    let normalsize = blocks[i as usize].value.len() + 2 + blocks[i as usize].name.len();
    let mut vec = Vec::with_capacity(normalsize);
    vec.extend_from_slice(&blocks[i as usize].name);
    vec.extend_from_slice(b": ");
    vec.extend_from_slice(&blocks[i as usize].value);
    return vec;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHeaderNames(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut vec = vec![b'\r', b'\n'];
    let frames = if direction & Direction::ToServer as u8 != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for frame in frames {
        if let Some(blocks) = http2_header_blocks(frame) {
            for block in blocks.iter() {
                // we do not escape linefeeds in headers names
                vec.extend_from_slice(&block.name);
                vec.extend_from_slice(b"\r\n");
            }
        }
    }
    if vec.len() > 2 {
        vec.extend_from_slice(b"\r\n");
        tx.escaped.push(vec);
        let idx = tx.escaped.len() - 1;
        let value = &tx.escaped[idx];
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

fn http2_header_iscookie(direction: Direction, hname: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(hname) {
        if direction == Direction::ToServer {
            if s.to_lowercase() == "cookie" {
                return true;
            }
        } else if s.to_lowercase() == "set-cookie" {
            return true;
        }
    }
    return false;
}

fn http2_header_trimspaces(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < value.len() {
        if value[start] == b' ' || value[start] == b'\t' {
            start += 1;
        } else {
            break;
        }
    }
    while end > start {
        if value[end - 1] == b' ' || value[end - 1] == b'\t' {
            end -= 1;
        } else {
            break;
        }
    }
    return &value[start..end];
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHeaders(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut vec = Vec::new();
    let frames = if direction & Direction::ToServer as u8 != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for frame in frames {
        if let Some(blocks) = http2_header_blocks(frame) {
            for block in blocks.iter() {
                if !http2_header_iscookie(direction.into(), &block.name) {
                    // we do not escape linefeeds nor : in headers names
                    vec.extend_from_slice(&block.name);
                    vec.extend_from_slice(b": ");
                    vec.extend_from_slice(http2_header_trimspaces(&block.value));
                    vec.extend_from_slice(b"\r\n");
                }
            }
        }
    }
    if !vec.is_empty() {
        tx.escaped.push(vec);
        let idx = tx.escaped.len() - 1;
        let value = &tx.escaped[idx];
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHeadersRaw(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut vec = Vec::new();
    let frames = if direction & Direction::ToServer as u8 != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for frame in frames {
        if let Some(blocks) = http2_header_blocks(frame) {
            for block in blocks.iter() {
                // we do not escape linefeeds nor : in headers names
                vec.extend_from_slice(&block.name);
                vec.extend_from_slice(b": ");
                vec.extend_from_slice(&block.value);
                vec.extend_from_slice(b"\r\n");
            }
        }
    }
    if !vec.is_empty() {
        tx.escaped.push(vec);
        let idx = tx.escaped.len() - 1;
        let value = &tx.escaped[idx];
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxGetHeader(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, direction: u8, nb: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    let mut pos = 0_u32;
    match direction.into() {
        Direction::ToServer => {
            for i in 0..tx.frames_ts.len() {
                if let Some(blocks) = http2_header_blocks(&tx.frames_ts[i]) {
                    if nb < pos + blocks.len() as u32 {
                        let ehdr = http2_escape_header(blocks, nb - pos);
                        tx.escaped.push(ehdr);
                        let idx = tx.escaped.len() - 1;
                        let value = &tx.escaped[idx];
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return true;
                    } else {
                        pos += blocks.len() as u32;
                    }
                }
            }
        }
        Direction::ToClient => {
            for i in 0..tx.frames_tc.len() {
                if let Some(blocks) = http2_header_blocks(&tx.frames_tc[i]) {
                    if nb < pos + blocks.len() as u32 {
                        let ehdr = http2_escape_header(blocks, nb - pos);
                        tx.escaped.push(ehdr);
                        let idx = tx.escaped.len() - 1;
                        let value = &tx.escaped[idx];
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return true;
                    } else {
                        pos += blocks.len() as u32;
                    }
                }
            }
        }
    }
    return false;
}

fn http2_tx_set_header(state: &mut HTTP2State, name: &[u8], input: &[u8]) {
    let head = parser::HTTP2FrameHeader {
        length: 0,
        ftype: parser::HTTP2FrameType::Headers as u8,
        flags: 0,
        reserved: 0,
        stream_id: 1,
    };
    let mut blocks = Vec::new();
    let b = parser::HTTP2FrameHeaderBlock {
        name: Rc::new(name.to_vec()),
        value: Rc::new(input.to_vec()),
        error: parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        sizeupdate: 0,
    };
    blocks.push(b);
    let hs = parser::HTTP2FrameHeaders {
        padlength: None,
        priority: None,
        blocks,
    };
    let txdata = HTTP2FrameTypeData::HEADERS(hs);
    let tx = state
        .find_or_create_tx(&head, &txdata, Direction::ToServer)
        .unwrap();
    tx.frames_ts.push(HTTP2Frame {
        header: head,
        data: txdata,
    });
    //we do not expect more data from client
    tx.state = HTTP2TransactionState::HTTP2StateHalfClosedClient;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxSetMethod(
    state: &mut HTTP2State, buffer: *const u8, buffer_len: u32,
) {
    let slice = build_slice!(buffer, buffer_len as usize);
    http2_tx_set_header(state, ":method".as_bytes(), slice)
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxSetUri(
    state: &mut HTTP2State, buffer: *const u8, buffer_len: u32,
) {
    let slice = build_slice!(buffer, buffer_len as usize);
    http2_tx_set_header(state, ":path".as_bytes(), slice)
}

fn http2_tx_set_settings(state: &mut HTTP2State, input: &[u8]) {
    match STANDARD.decode(input) {
        Ok(dec) => {
            if dec.len() % 6 != 0 {
                state.set_event(HTTP2Event::InvalidHttp1Settings);
            }

            let head = parser::HTTP2FrameHeader {
                length: dec.len() as u32,
                ftype: parser::HTTP2FrameType::Settings as u8,
                flags: 0,
                reserved: 0,
                stream_id: 0,
            };

            match parser::http2_parse_frame_settings(&dec) {
                Ok((_, set)) => {
                    let txdata = HTTP2FrameTypeData::SETTINGS(set);
                    let tx = state
                        .find_or_create_tx(&head, &txdata, Direction::ToServer)
                        .unwrap();
                    tx.frames_ts.push(HTTP2Frame {
                        header: head,
                        data: txdata,
                    });
                }
                Err(_) => {
                    state.set_event(HTTP2Event::InvalidHttp1Settings);
                }
            }
        }
        Err(_) => {
            state.set_event(HTTP2Event::InvalidHttp1Settings);
        }
    }
}

fn http2_caseinsensitive_cmp(s1: &[u8], s2: &str) -> bool {
    if let Ok(s) = std::str::from_utf8(s1) {
        return s.to_lowercase() == s2;
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2TxAddHeader(
    state: &mut HTTP2State, name: *const u8, name_len: u32, value: *const u8, value_len: u32,
) {
    let slice_name = build_slice!(name, name_len as usize);
    let slice_value = build_slice!(value, value_len as usize);
    if slice_name == "HTTP2-Settings".as_bytes() {
        http2_tx_set_settings(state, slice_value)
    } else if http2_caseinsensitive_cmp(slice_name, "host") {
        http2_tx_set_header(state, ":authority".as_bytes(), slice_value)
    } else {
        http2_tx_set_header(state, slice_name, slice_value)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_http2_normalize_host() {
        let buf0 = "aBC.com:1234".as_bytes();
        let r0 = http2_normalize_host(buf0);
        assert_eq!(r0, "aBC.com".as_bytes().to_vec());
        let buf1 = "oisf.net".as_bytes();
        let r1 = http2_normalize_host(buf1);
        assert_eq!(r1, "oisf.net".as_bytes().to_vec());
        let buf2 = "localhost:3000".as_bytes();
        let r2 = http2_normalize_host(buf2);
        assert_eq!(r2, "localhost".as_bytes().to_vec());
        let buf3 = "user:pass@localhost".as_bytes();
        let r3 = http2_normalize_host(buf3);
        assert_eq!(r3, "localhost".as_bytes().to_vec());
        let buf4 = "user:pass@localhost:123".as_bytes();
        let r4 = http2_normalize_host(buf4);
        assert_eq!(r4, "localhost".as_bytes().to_vec());
    }

    #[test]
    fn test_http2_header_trimspaces() {
        let buf0 = "nospaces".as_bytes();
        let r0 = http2_header_trimspaces(buf0);
        assert_eq!(r0, "nospaces".as_bytes());
        let buf1 = " spaces\t".as_bytes();
        let r1 = http2_header_trimspaces(buf1);
        assert_eq!(r1, "spaces".as_bytes());
        let buf2 = " \t".as_bytes();
        let r2 = http2_header_trimspaces(buf2);
        assert_eq!(r2, "".as_bytes());
    }

    #[test]
    fn test_http2_frames_get_header_value() {
        let mut tx = HTTP2Transaction::new();
        let head = parser::HTTP2FrameHeader {
            length: 0,
            ftype: parser::HTTP2FrameType::Headers as u8,
            flags: 0,
            reserved: 0,
            stream_id: 1,
        };
        let mut blocks = Vec::new();
        let b = parser::HTTP2FrameHeaderBlock {
            name: "Host".as_bytes().to_vec().into(),
            value: "abc.com".as_bytes().to_vec().into(),
            error: parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
            sizeupdate: 0,
        };
        blocks.push(b);
        let b2 = parser::HTTP2FrameHeaderBlock {
            name: "Host".as_bytes().to_vec().into(),
            value: "efg.net".as_bytes().to_vec().into(),
            error: parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
            sizeupdate: 0,
        };
        blocks.push(b2);
        let hs = parser::HTTP2FrameHeaders {
            padlength: None,
            priority: None,
            blocks,
        };
        let txdata = HTTP2FrameTypeData::HEADERS(hs);
        tx.frames_ts.push(HTTP2Frame {
            header: head,
            data: txdata,
        });
        match http2_frames_get_header_value(&mut tx, Direction::ToServer, "Host") {
            Ok(x) => {
                assert_eq!(x, "abc.com, efg.net".as_bytes());
            }
            Err(e) => {
                panic!("Result should not have been an error: {:?}", e);
            }
        }
    }
}
