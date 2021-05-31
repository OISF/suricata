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
use crate::core::STREAM_TOSERVER;
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
    set: &Vec<parser::HTTP2FrameSettings>, ctx: &parser::DetectHTTP2settingsSigCtx,
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
    hd: &parser::HTTP2FrameHeaders, ctx: &parser::DetectU64Data,
) -> std::os::raw::c_int {
    for i in 0..hd.blocks.len() {
        match ctx.mode {
            parser::DetectUintMode::DetectUintModeEqual => {
                if hd.blocks[i].sizeupdate == ctx.value
                    && hd.blocks[i].error
                        == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
            parser::DetectUintMode::DetectUintModeLt => {
                if hd.blocks[i].sizeupdate <= ctx.value
                    && hd.blocks[i].error
                        == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
            parser::DetectUintMode::DetectUintModeGt => {
                if hd.blocks[i].sizeupdate >= ctx.value
                    && hd.blocks[i].error
                        == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
            parser::DetectUintMode::DetectUintModeRange => {
                if hd.blocks[i].sizeupdate <= ctx.value
                    && hd.blocks[i].sizeupdate >= ctx.valrange
                    && hd.blocks[i].error
                        == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}

fn http2_detect_sizeupdatectx_match(
    ctx: &mut parser::DetectU64Data, tx: &mut HTTP2Transaction, direction: u8,
) -> std::os::raw::c_int {
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            match &tx.frames_ts[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if http2_detect_sizeupdate_match(&hd, ctx) != 0 {
                        return 1;
                    }
                }
                _ => {}
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            match &tx.frames_tc[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if http2_detect_sizeupdate_match(&hd, ctx) != 0 {
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
            match &tx.frames_ts[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if nb < pos + hd.blocks.len() as u32 {
                        let value = &hd.blocks[(nb - pos) as usize].name;
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return 1;
                    } else {
                        pos = pos + hd.blocks.len() as u32;
                    }
                }
                _ => {}
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            match &tx.frames_tc[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if nb < pos + hd.blocks.len() as u32 {
                        let value = &hd.blocks[(nb - pos) as usize].name;
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return 1;
                    } else {
                        pos = pos + hd.blocks.len() as u32;
                    }
                }
                _ => {}
            }
        }
    }
    return 0;
}

fn http2_blocks_get_header_value<'a>(
    blocks: &'a Vec<parser::HTTP2FrameHeaderBlock>, name: &str,
) -> Result<&'a [u8], ()> {
    for j in 0..blocks.len() {
        if blocks[j].name == name.as_bytes().to_vec() {
            return Ok(&blocks[j].value);
        }
    }
    return Err(());
}

fn http2_frames_get_header_value<'a>(
    frames: &'a Vec<HTTP2Frame>, name: &str,
) -> Result<&'a [u8], ()> {
    for i in 0..frames.len() {
        match &frames[i].data {
            HTTP2FrameTypeData::HEADERS(hd) => {
                if let Ok(value) = http2_blocks_get_header_value(&hd.blocks, name) {
                    return Ok(value);
                }
            }
            HTTP2FrameTypeData::PUSHPROMISE(hd) => {
                if let Ok(value) = http2_blocks_get_header_value(&hd.blocks, name) {
                    return Ok(value);
                }
            }
            HTTP2FrameTypeData::CONTINUATION(hd) => {
                if let Ok(value) = http2_blocks_get_header_value(&hd.blocks, name) {
                    return Ok(value);
                }
            }
            _ => {}
        }
    }

    return Err(());
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_uri(
    tx: &mut HTTP2Transaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Ok(value) = http2_frames_get_header_value(&tx.frames_ts, ":path") {
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
    if let Ok(value) = http2_frames_get_header_value(&tx.frames_ts, ":method") {
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
    if let Ok(value) = http2_frames_get_header_value(&tx.frames_ts, ":authority") {
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
    if let Ok(value) = http2_frames_get_header_value(&tx.frames_ts, ":authority") {
        let r = http2_normalize_host(value);
        // r is a tuple with the value and its size
        // this is useful when we only take a substring (before the port)
        match r.0 {
            Some(normval) => {
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
    if let Ok(value) = http2_frames_get_header_value(&tx.frames_ts, "user-agent") {
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
    if let Ok(value) = http2_frames_get_header_value(&tx.frames_tc, ":status") {
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
        if let Ok(value) = http2_frames_get_header_value(&tx.frames_ts, "cookie") {
            *buffer = value.as_ptr(); //unsafe
            *buffer_len = value.len() as u32;
            return 1;
        }
    } else {
        if let Ok(value) = http2_frames_get_header_value(&tx.frames_tc, "set-cookie") {
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
        let frames = if direction == STREAM_TOSERVER {
            &tx.frames_ts
        } else {
            &tx.frames_tc
        };
        if let Ok(value) = http2_frames_get_header_value(frames, &s.to_lowercase()) {
            *buffer = value.as_ptr(); //unsafe
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    return 0;
}

fn http2_escape_header(hd: &parser::HTTP2FrameHeaders, i: u32) -> Vec<u8> {
    //minimum size + 2 for escapes
    let normalsize = hd.blocks[i as usize].value.len() + 2 + hd.blocks[i as usize].name.len() + 2;
    let mut vec = Vec::with_capacity(normalsize);
    for j in 0..hd.blocks[i as usize].name.len() {
        vec.push(hd.blocks[i as usize].name[j]);
        if hd.blocks[i as usize].name[j] == ':' as u8 {
            vec.push(':' as u8);
        }
    }
    vec.push(':' as u8);
    vec.push(' ' as u8);
    for j in 0..hd.blocks[i as usize].value.len() {
        vec.push(hd.blocks[i as usize].value[j]);
        if hd.blocks[i as usize].value[j] == ':' as u8 {
            vec.push(':' as u8);
        }
    }
    return vec;
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_header_names(
    tx: &mut HTTP2Transaction, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut vec = Vec::new();
    vec.push('\r' as u8);
    vec.push('\n' as u8);
    let frames = if direction & STREAM_TOSERVER != 0 {
        &tx.frames_ts
    } else {
        &tx.frames_tc
    };
    for i in 0..frames.len() {
        match &frames[i].data {
            HTTP2FrameTypeData::HEADERS(hd) => {
                for j in 0..hd.blocks.len() {
                    // we do not escape linefeeds in headers names
                    vec.extend_from_slice(&hd.blocks[j].name);
                    vec.push('\r' as u8);
                    vec.push('\n' as u8);
                }
            }
            _ => {}
        }
    }
    if vec.len() > 2 {
        vec.push('\r' as u8);
        vec.push('\n' as u8);
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
            match &tx.frames_ts[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if nb < pos + hd.blocks.len() as u32 {
                        let ehdr = http2_escape_header(&hd, nb - pos);
                        tx.escaped.push(ehdr);
                        let idx = tx.escaped.len() - 1;
                        let value = &tx.escaped[idx];
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return 1;
                    } else {
                        pos = pos + hd.blocks.len() as u32;
                    }
                }
                _ => {}
            }
        }
    } else {
        for i in 0..tx.frames_tc.len() {
            match &tx.frames_tc[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if nb < pos + hd.blocks.len() as u32 {
                        let ehdr = http2_escape_header(&hd, nb - pos);
                        tx.escaped.push(ehdr);
                        let idx = tx.escaped.len() - 1;
                        let value = &tx.escaped[idx];
                        *buffer = value.as_ptr(); //unsafe
                        *buffer_len = value.len() as u32;
                        return 1;
                    } else {
                        pos = pos + hd.blocks.len() as u32;
                    }
                }
                _ => {}
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
}
