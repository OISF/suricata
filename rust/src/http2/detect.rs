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

use super::http2::{
    HTTP2Event, HTTP2Frame, HTTP2FrameTypeData, HTTP2State, HTTP2Transaction, HTTP2TransactionState,
};
use super::parser;
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use std::ffi::CStr;
use std::mem::transmute;
use std::str::FromStr;

fn http2_tx_has_frametype(
    tx: &mut HTTP2Transaction, direction: u8, value: u8,
) -> std::os::raw::c_int {
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            if tx.frames_ts[i].header.ftype as u8 == value {
                return 1;
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            if tx.frames_tc[i].header.ftype as u8 == value {
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_has_frametype(
    tx: *mut std::os::raw::c_void, direction: u8, value: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_tx_has_frametype(tx, direction, value);
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_parse_frametype(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok(x) = parser::HTTP2FrameType::from_str(s) {
            return x as i32;
        }
    }
    return -1;
}

fn http2_tx_has_errorcode(
    tx: &mut HTTP2Transaction, direction: u8, code: u32,
) -> std::os::raw::c_int {
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            match tx.frames_ts[i].data {
                HTTP2FrameTypeData::GOAWAY(goaway) => {
                    if goaway.errorcode == code {
                        return 1;
                    }
                }
                HTTP2FrameTypeData::RSTSTREAM(rst) => {
                    if rst.errorcode == code {
                        return 1;
                    }
                }
                _ => {}
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            match tx.frames_tc[i].data {
                HTTP2FrameTypeData::GOAWAY(goaway) => {
                    if goaway.errorcode as u32 == code {
                        return 1;
                    }
                }
                HTTP2FrameTypeData::RSTSTREAM(rst) => {
                    if rst.errorcode as u32 == code {
                        return 1;
                    }
                }
                _ => {}
            }
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_has_errorcode(
    tx: *mut std::os::raw::c_void, direction: u8, code: u32,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_tx_has_errorcode(tx, direction, code);
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_parse_errorcode(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok(x) = parser::HTTP2ErrorCode::from_str(s) {
            return x as i32;
        }
    }
    return -1;
}

fn http2_tx_get_next_priority(
    tx: &mut HTTP2Transaction, direction: u8, nb: u32,
) -> std::os::raw::c_int {
    let mut pos = 0 as u32;
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            match &tx.frames_ts[i].data {
                HTTP2FrameTypeData::PRIORITY(prio) => {
                    if pos == nb {
                        return prio.weight as i32;
                    } else {
                        pos = pos + 1;
                    }
                }
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if let Some(prio) = hd.priority {
                        if pos == nb {
                            return prio.weight as i32;
                        } else {
                            pos = pos + 1;
                        }
                    }
                }
                _ => {}
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            match &tx.frames_tc[i].data {
                HTTP2FrameTypeData::PRIORITY(prio) => {
                    if pos == nb {
                        return prio.weight as i32;
                    } else {
                        pos = pos + 1;
                    }
                }
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if let Some(prio) = hd.priority {
                        if pos == nb {
                            return prio.weight as i32;
                        } else {
                            pos = pos + 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_next_priority(
    tx: *mut std::os::raw::c_void, direction: u8, nb: u32,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_tx_get_next_priority(tx, direction, nb);
}

fn http2_tx_get_next_window(
    tx: &mut HTTP2Transaction, direction: u8, nb: u32,
) -> std::os::raw::c_int {
    let mut pos = 0 as u32;
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            match tx.frames_ts[i].data {
                HTTP2FrameTypeData::WINDOWUPDATE(wu) => {
                    if pos == nb {
                        return wu.sizeinc as i32;
                    } else {
                        pos = pos + 1;
                    }
                }
                _ => {}
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            match tx.frames_tc[i].data {
                HTTP2FrameTypeData::WINDOWUPDATE(wu) => {
                    if pos == nb {
                        return wu.sizeinc as i32;
                    } else {
                        pos = pos + 1;
                    }
                }
                _ => {}
            }
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_next_window(
    tx: *mut std::os::raw::c_void, direction: u8, nb: u32,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_tx_get_next_window(tx, direction, nb);
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_parse_settingsid(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok(x) = parser::HTTP2SettingsId::from_str(s) {
            return x as i32;
        }
    }
    return -1;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_detect_settingsctx_parse(
    str: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_void {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = parser::http2_parse_settingsctx(s) {
            let boxed = Box::new(ctx);
            return transmute(boxed); //unsafe
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_detect_settingsctx_free(ctx: *mut std::os::raw::c_void) {
    // Just unbox...
    let _ctx: Box<parser::DetectHTTP2settingsSigCtx> = transmute(ctx);
}

fn http2_detect_settings_match(
    set: &[parser::HTTP2FrameSettings], ctx: &parser::DetectHTTP2settingsSigCtx,
) -> std::os::raw::c_int {
    for i in 0..set.len() {
        if set[i].id == ctx.id {
            match &ctx.value {
                None => {
                    return 1;
                }
                Some(x) => match x.mode {
                    parser::DetectUintMode::DetectUintModeEqual => {
                        if set[i].value == x.value {
                            return 1;
                        }
                    }
                    parser::DetectUintMode::DetectUintModeLt => {
                        if set[i].value <= x.value {
                            return 1;
                        }
                    }
                    parser::DetectUintMode::DetectUintModeGt => {
                        if set[i].value >= x.value {
                            return 1;
                        }
                    }
                    parser::DetectUintMode::DetectUintModeRange => {
                        if set[i].value <= x.value && set[i].value >= x.valrange {
                            return 1;
                        }
                    }
                },
            }
        }
    }
    return 0;
}

fn http2_detect_settingsctx_match(
    ctx: &mut parser::DetectHTTP2settingsSigCtx, tx: &mut HTTP2Transaction, direction: u8,
) -> std::os::raw::c_int {
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            match &tx.frames_ts[i].data {
                HTTP2FrameTypeData::SETTINGS(set) => {
                    if http2_detect_settings_match(&set, ctx) != 0 {
                        return 1;
                    }
                }
                _ => {}
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            match &tx.frames_tc[i].data {
                HTTP2FrameTypeData::SETTINGS(set) => {
                    if http2_detect_settings_match(&set, ctx) != 0 {
                        return 1;
                    }
                }
                _ => {}
            }
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_detect_settingsctx_match(
    ctx: *const std::os::raw::c_void, tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, parser::DetectHTTP2settingsSigCtx);
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_detect_settingsctx_match(ctx, tx, direction);
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u64_parse(
    str: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_void {
    let ft_name: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = parser::detect_parse_u64(s) {
            let boxed = Box::new(ctx);
            return transmute(boxed); //unsafe
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_u64_free(ctx: *mut std::os::raw::c_void) {
    // Just unbox...
    let _ctx: Box<parser::DetectU64Data> = transmute(ctx);
}

fn http2_detect_sizeupdate_match(
    blocks: &[parser::HTTP2FrameHeaderBlock], ctx: &parser::DetectU64Data,
) -> std::os::raw::c_int {
    for block in blocks.iter() {
        match ctx.mode {
            parser::DetectUintMode::DetectUintModeEqual => {
                if block.sizeupdate == ctx.value
                    && block.error == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
            parser::DetectUintMode::DetectUintModeLt => {
                if block.sizeupdate <= ctx.value
                    && block.error == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
            parser::DetectUintMode::DetectUintModeGt => {
                if block.sizeupdate >= ctx.value
                    && block.error == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
            parser::DetectUintMode::DetectUintModeRange => {
                if block.sizeupdate <= ctx.value
                    && block.sizeupdate >= ctx.valrange
                    && block.error == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
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
    ctx: &mut parser::DetectU64Data, tx: &mut HTTP2Transaction, direction: u8,
) -> std::os::raw::c_int {
    if direction & STREAM_TOSERVER != 0 {
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
pub extern "C" fn rs_http2_detect_sizeupdatectx_match(
    ctx: *const std::os::raw::c_void, tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, parser::DetectU64Data);
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return http2_detect_sizeupdatectx_match(ctx, tx, direction);
}

//TODOask better syntax between rs_http2_tx_get_header_name in argument
// and rs_http2_detect_sizeupdatectx_match explicitly casting
#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_header_name(
    tx: &mut HTTP2Transaction, direction: u8, nb: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut pos = 0 as u32;
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            if let Some(blocks) = http2_header_blocks(&tx.frames_ts[i]) {
                if nb < pos + blocks.len() as u32 {
                    let value = &blocks[(nb - pos) as usize].name;
                    *buffer = value.as_ptr(); //unsafe
                    *buffer_len = value.len() as u32;
                    return 1;
                } else {
                    pos = pos + blocks.len() as u32;
                }
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            if let Some(blocks) = http2_header_blocks(&tx.frames_tc[i]) {
                if nb < pos + blocks.len() as u32 {
                    let value = &blocks[(nb - pos) as usize].name;
                    *buffer = value.as_ptr(); //unsafe
                    *buffer_len = value.len() as u32;
                    return 1;
                } else {
                    pos = pos + blocks.len() as u32;
                }
            }
        }
    }
    return 0;
}

fn http2_frames_get_header_firstvalue<'a>(
    tx: &'a mut HTTP2Transaction, direction: u8, name: &str,
) -> Result<&'a [u8], ()> {
    let frames = if direction == STREAM_TOSERVER {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for i in 0..frames.len() {
        if let Some(blocks) = http2_header_blocks(&frames[i]) {
            for block in blocks.iter() {
                if block.name == name.as_bytes() {
                    return Ok(&block.value);
                }
            }
        }
    }
    return Err(());
}

fn http2_frames_get_header_value<'a>(
    tx: &'a mut HTTP2Transaction, direction: u8, name: &str,
) -> Result<&'a [u8], ()> {
    let mut found = 0;
    let mut vec = Vec::new();
    let mut single: Result<&[u8], ()> = Err(());
    let frames = if direction == STREAM_TOSERVER {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for i in 0..frames.len() {
        if let Some(blocks) = http2_header_blocks(&frames[i]) {
            for block in blocks.iter() {
                if block.name == name.as_bytes() {
                    if found == 0 {
                        single = Ok(&block.value);
                        found = 1;
                    } else if found == 1 {
                        if let Ok(s) = single {
                            vec.extend_from_slice(s);
                        }
                        vec.extend_from_slice(&[b',', b' ']);
                        vec.extend_from_slice(&block.value);
                        found = 2;
                    } else {
                        vec.extend_from_slice(&[b',', b' ']);
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
        return Ok(&value);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_uri(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_firstvalue(tx, STREAM_TOSERVER, ":path") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_method(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_firstvalue(tx, STREAM_TOSERVER, ":method") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_host(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_value(tx, STREAM_TOSERVER, ":authority") {
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
            for j in i..vec.len() {
                vec[j].make_ascii_lowercase();
            }
            return Some(vec);
        }
    }
    return None;
}

// returns a tuple with the value and its size
fn http2_normalize_host(value: &[u8]) -> (Option<Vec<u8>>, usize) {
    match value.iter().position(|&x| x == ':' as u8) {
        Some(i) => {
            return (http2_lower(&value[..i]), i);
        }
        None => {
            return (http2_lower(value), value.len());
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_host_norm(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_value(tx, STREAM_TOSERVER, ":authority") {
        let r = http2_normalize_host(value);
        // r is a tuple with the value and its size
        // this is useful when we only take a substring (before the port)
        match r.0 {
            Some(normval) => {
                // In case we needed some normalization,
                // the transaction needs to take ownership of this normalized host
                tx.escaped.push(normval);
                let idx = tx.escaped.len() - 1;
                let resvalue = &tx.escaped[idx];
                *buffer = resvalue.as_ptr(); //unsafe
                *buffer_len = r.1 as u32;
                return 1;
            }
            None => {
                *buffer = value.as_ptr(); //unsafe
                *buffer_len = r.1 as u32;
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_useragent(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_value(tx, STREAM_TOSERVER, "user-agent") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_status(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_firstvalue(tx, STREAM_TOCLIENT, ":status") {
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_cookie(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if direction == STREAM_TOSERVER {
        if let Ok(value) = http2_frames_get_header_value(tx, STREAM_TOSERVER, "cookie") {
            *buffer = value.as_ptr(); //unsafe
            *buffer_len = value.len() as u32;
            return 1;
        }
    } else {
        if let Ok(value) = http2_frames_get_header_value(tx, STREAM_TOCLIENT, "set-cookie") {
            *buffer = value.as_ptr(); //unsafe
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_header_value(
    tx: &mut HTTP2Transaction, direction: u8, strname: *const std::os::raw::c_char,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let hname: &CStr = CStr::from_ptr(strname); //unsafe
    if let Ok(s) = hname.to_str() {
        if let Ok(value) = http2_frames_get_header_value(tx, direction, &s.to_lowercase()) {
            *buffer = value.as_ptr(); //unsafe
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    return 0;
}

fn http2_escape_header(blocks: &[parser::HTTP2FrameHeaderBlock], i: u32) -> Vec<u8> {
    //minimum size + 2 for escapes
    let normalsize = blocks[i as usize].value.len() + 2 + blocks[i as usize].name.len() + 2;
    let mut vec = Vec::with_capacity(normalsize);
    for j in 0..blocks[i as usize].name.len() {
        vec.push(blocks[i as usize].name[j]);
        if blocks[i as usize].name[j] == ':' as u8 {
            vec.push(':' as u8);
        }
    }
    vec.extend_from_slice(&[b':', b' ']);
    for j in 0..blocks[i as usize].value.len() {
        vec.push(blocks[i as usize].value[j]);
        if blocks[i as usize].value[j] == ':' as u8 {
            vec.push(':' as u8);
        }
    }
    return vec;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_header_names(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut vec = vec![b'\r', b'\n'];
    let frames = if direction & STREAM_TOSERVER != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for i in 0..frames.len() {
        if let Some(blocks) = http2_header_blocks(&frames[i]) {
            for block in blocks.iter() {
                // we do not escape linefeeds in headers names
                vec.extend_from_slice(&block.name);
                vec.extend_from_slice(&[b'\r', b'\n']);
            }
        }
    }
    if vec.len() > 2 {
        vec.extend_from_slice(&[b'\r', b'\n']);
        tx.escaped.push(vec);
        let idx = tx.escaped.len() - 1;
        let value = &tx.escaped[idx];
        *buffer = value.as_ptr(); //unsafe
        *buffer_len = value.len() as u32;
        return 1;
    }
    return 0;
}

fn http2_header_iscookie(direction: u8, hname: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(hname) {
        if direction & STREAM_TOSERVER != 0 {
            if s.to_lowercase() == "cookie" {
                return true;
            }
        } else {
            if s.to_lowercase() == "set-cookie" {
                return true;
            }
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
pub unsafe extern "C" fn rs_http2_tx_get_headers(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut vec = Vec::new();
    let frames = if direction & STREAM_TOSERVER != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for i in 0..frames.len() {
        if let Some(blocks) = http2_header_blocks(&frames[i]) {
            for block in blocks.iter() {
                if !http2_header_iscookie(direction, &block.name) {
                    // we do not escape linefeeds nor : in headers names
                    vec.extend_from_slice(&block.name);
                    vec.extend_from_slice(&[b':', b' ']);
                    vec.extend_from_slice(http2_header_trimspaces(&block.value));
                    vec.extend_from_slice(&[b'\r', b'\n']);
                }
            }
        }
    }
    if vec.len() > 0 {
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
pub unsafe extern "C" fn rs_http2_tx_get_headers_raw(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut vec = Vec::new();
    let frames = if direction & STREAM_TOSERVER != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for i in 0..frames.len() {
        if let Some(blocks) = http2_header_blocks(&frames[i]) {
            for block in blocks.iter() {
                // we do not escape linefeeds nor : in headers names
                vec.extend_from_slice(&block.name);
                vec.extend_from_slice(&[b':', b' ']);
                vec.extend_from_slice(&block.value);
                vec.extend_from_slice(&[b'\r', b'\n']);
            }
        }
    }
    if vec.len() > 0 {
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
pub unsafe extern "C" fn rs_http2_tx_get_header(
    tx: &mut HTTP2Transaction, direction: u8, nb: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut pos = 0 as u32;
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            if let Some(blocks) = http2_header_blocks(&tx.frames_ts[i]) {
                if nb < pos + blocks.len() as u32 {
                    let ehdr = http2_escape_header(&blocks, nb - pos);
                    tx.escaped.push(ehdr);
                    let idx = tx.escaped.len() - 1;
                    let value = &tx.escaped[idx];
                    *buffer = value.as_ptr(); //unsafe
                    *buffer_len = value.len() as u32;
                    return 1;
                } else {
                    pos = pos + blocks.len() as u32;
                }
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            if let Some(blocks) = http2_header_blocks(&tx.frames_tc[i]) {
                if nb < pos + blocks.len() as u32 {
                    let ehdr = http2_escape_header(&blocks, nb - pos);
                    tx.escaped.push(ehdr);
                    let idx = tx.escaped.len() - 1;
                    let value = &tx.escaped[idx];
                    *buffer = value.as_ptr(); //unsafe
                    *buffer_len = value.len() as u32;
                    return 1;
                } else {
                    pos = pos + blocks.len() as u32;
                }
            }
        }
    }

    return 0;
}

fn http2_tx_set_header(state: &mut HTTP2State, name: &[u8], input: &[u8]) {
    let head = parser::HTTP2FrameHeader {
        length: 0,
        ftype: parser::HTTP2FrameType::HEADERS as u8,
        flags: 0,
        reserved: 0,
        stream_id: 1,
    };
    let mut blocks = Vec::new();
    let b = parser::HTTP2FrameHeaderBlock {
        name: name.to_vec(),
        value: input.to_vec(),
        error: parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        sizeupdate: 0,
    };
    blocks.push(b);
    let hs = parser::HTTP2FrameHeaders {
        padlength: None,
        priority: None,
        blocks: blocks,
    };
    let txdata = HTTP2FrameTypeData::HEADERS(hs);
    let tx = state.find_or_create_tx(&head, &txdata, STREAM_TOSERVER);
    tx.frames_ts.push(HTTP2Frame {
        header: head,
        data: txdata,
    });
    //we do not expect more data from client
    tx.state = HTTP2TransactionState::HTTP2StateHalfClosedClient;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_set_method(
    state: &mut HTTP2State, buffer: *const u8, buffer_len: u32,
) {
    let slice = build_slice!(buffer, buffer_len as usize);
    http2_tx_set_header(state, ":method".as_bytes(), slice)
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_set_uri(state: &mut HTTP2State, buffer: *const u8, buffer_len: u32) {
    let slice = build_slice!(buffer, buffer_len as usize);
    http2_tx_set_header(state, ":path".as_bytes(), slice)
}

#[derive(Debug, PartialEq)]
pub enum Http2Base64Error {
    InvalidBase64,
}

impl std::error::Error for Http2Base64Error {}

impl std::fmt::Display for Http2Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "invalid base64")
    }
}

fn http2_base64_map(input: u8) -> Result<u8, Http2Base64Error> {
    match input {
        43 => Ok(62),  // +
        47 => Ok(63),  // /
        48 => Ok(52),  // 0
        49 => Ok(53),  // 1
        50 => Ok(54),  // 2
        51 => Ok(55),  // 3
        52 => Ok(56),  // 4
        53 => Ok(57),  // 5
        54 => Ok(58),  // 6
        55 => Ok(59),  // 7
        56 => Ok(60),  // 8
        57 => Ok(61),  // 9
        65 => Ok(0),   // A
        66 => Ok(1),   // B
        67 => Ok(2),   // C
        68 => Ok(3),   // D
        69 => Ok(4),   // E
        70 => Ok(5),   // F
        71 => Ok(6),   // G
        72 => Ok(7),   // H
        73 => Ok(8),   // I
        74 => Ok(9),   // J
        75 => Ok(10),  // K
        76 => Ok(11),  // L
        77 => Ok(12),  // M
        78 => Ok(13),  // N
        79 => Ok(14),  // O
        80 => Ok(15),  // P
        81 => Ok(16),  // Q
        82 => Ok(17),  // R
        83 => Ok(18),  // S
        84 => Ok(19),  // T
        85 => Ok(20),  // U
        86 => Ok(21),  // V
        87 => Ok(22),  // W
        88 => Ok(23),  // X
        89 => Ok(24),  // Y
        90 => Ok(25),  // Z
        97 => Ok(26),  // a
        98 => Ok(27),  // b
        99 => Ok(28),  // c
        100 => Ok(29), // d
        101 => Ok(30), // e
        102 => Ok(31), // f
        103 => Ok(32), // g
        104 => Ok(33), // h
        105 => Ok(34), // i
        106 => Ok(35), // j
        107 => Ok(36), // k
        108 => Ok(37), // l
        109 => Ok(38), // m
        110 => Ok(39), // n
        111 => Ok(40), // o
        112 => Ok(41), // p
        113 => Ok(42), // q
        114 => Ok(43), // r
        115 => Ok(44), // s
        116 => Ok(45), // t
        117 => Ok(46), // u
        118 => Ok(47), // v
        119 => Ok(48), // w
        120 => Ok(49), // x
        121 => Ok(50), // y
        122 => Ok(51), // z
        _ => Err(Http2Base64Error::InvalidBase64),
    }
}

fn http2_decode_base64(input: &[u8]) -> Result<Vec<u8>, Http2Base64Error> {
    if input.len() % 4 != 0 {
        return Err(Http2Base64Error::InvalidBase64);
    }
    let mut r = vec![0; (input.len() * 3) / 4];
    for i in 0..input.len() / 4 {
        let i1 = http2_base64_map(input[4 * i])?;
        let i2 = http2_base64_map(input[4 * i + 1])?;
        let i3 = http2_base64_map(input[4 * i + 2])?;
        let i4 = http2_base64_map(input[4 * i + 3])?;
        r[3 * i] = (i1 << 2) | (i2 >> 4);
        r[3 * i + 1] = (i2 << 4) | (i3 >> 2);
        r[3 * i + 2] = (i3 << 6) | i4;
    }
    return Ok(r);
}

fn http2_tx_set_settings(state: &mut HTTP2State, input: &[u8]) {
    match http2_decode_base64(input) {
        Ok(dec) => {
            if dec.len() % 6 != 0 {
                state.set_event(HTTP2Event::InvalidHTTP1Settings);
            }

            let head = parser::HTTP2FrameHeader {
                length: dec.len() as u32,
                ftype: parser::HTTP2FrameType::SETTINGS as u8,
                flags: 0,
                reserved: 0,
                stream_id: 0,
            };

            match parser::http2_parse_frame_settings(&dec) {
                Ok((_, set)) => {
                    let txdata = HTTP2FrameTypeData::SETTINGS(set);
                    let tx = state.find_or_create_tx(&head, &txdata, STREAM_TOSERVER);
                    tx.frames_ts.push(HTTP2Frame {
                        header: head,
                        data: txdata,
                    });
                }
                Err(_) => {
                    state.set_event(HTTP2Event::InvalidHTTP1Settings);
                }
            }
        }
        Err(_) => {
            state.set_event(HTTP2Event::InvalidHTTP1Settings);
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
pub extern "C" fn rs_http2_tx_add_header(
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
        match r0.0 {
            Some(r) => {
                assert_eq!(r, "abc.com".as_bytes().to_vec());
            }
            None => {
                panic!("Result should not have been None");
            }
        }
        let buf1 = "oisf.net".as_bytes();
        let r1 = http2_normalize_host(buf1);
        match r1.0 {
            Some(r) => {
                panic!("Result should not have been None, not {:?}", r);
            }
            None => {}
        }
        assert_eq!(r1.1, "oisf.net".len());
        let buf2 = "localhost:3000".as_bytes();
        let r2 = http2_normalize_host(buf2);
        match r2.0 {
            Some(r) => {
                panic!("Result should not have been None, not {:?}", r);
            }
            None => {}
        }
        assert_eq!(r2.1, "localhost".len());
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
            ftype: parser::HTTP2FrameType::HEADERS as u8,
            flags: 0,
            reserved: 0,
            stream_id: 1,
        };
        let mut blocks = Vec::new();
        let b = parser::HTTP2FrameHeaderBlock {
            name: "Host".as_bytes().to_vec(),
            value: "abc.com".as_bytes().to_vec(),
            error: parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
            sizeupdate: 0,
        };
        blocks.push(b);
        let b2 = parser::HTTP2FrameHeaderBlock {
            name: "Host".as_bytes().to_vec(),
            value: "efg.net".as_bytes().to_vec(),
            error: parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
            sizeupdate: 0,
        };
        blocks.push(b2);
        let hs = parser::HTTP2FrameHeaders {
            padlength: None,
            priority: None,
            blocks: blocks,
        };
        let txdata = HTTP2FrameTypeData::HEADERS(hs);
        tx.frames_ts.push(HTTP2Frame {
            header: head,
            data: txdata,
        });
        match http2_frames_get_header_value(&mut tx, STREAM_TOSERVER, "Host") {
            Ok(x) => {
                assert_eq!(x, "abc.com, efg.net".as_bytes());
            }
            Err(e) => {
                panic!("Result should not have been an error: {:?}", e);
            }
        }
    }
}
