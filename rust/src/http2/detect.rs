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

use super::http2::{HTTP2FrameTypeData, HTTP2Transaction};
use super::parser;
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use std::ffi::CStr;
use std::mem::transmute;
use std::str::FromStr;

#[no_mangle]
pub extern "C" fn rs_http2_tx_has_frametype(
    tx: *mut std::os::raw::c_void, direction: u8, value: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            if tx.frames_ts[i].header.ftype as u8 == value {
                return 1;
            }
        }
    }
    if direction & STREAM_TOCLIENT != 0 {
        for i in 0..tx.frames_tc.len() {
            if tx.frames_tc[i].header.ftype as u8 == value {
                return 1;
            }
        }
    }
    return 0;
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

#[no_mangle]
pub extern "C" fn rs_http2_tx_has_errorcode(
    tx: *mut std::os::raw::c_void, direction: u8, code: u32,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
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
    }
    if direction & STREAM_TOCLIENT != 0 {
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

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_next_priority(
    tx: *mut std::os::raw::c_void, direction: u8, nb: u32,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
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
    }
    if direction & STREAM_TOCLIENT != 0 {
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
pub extern "C" fn rs_http2_tx_get_next_window(
    tx: *mut std::os::raw::c_void, direction: u8, nb: u32,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
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
    }
    if direction & STREAM_TOCLIENT != 0 {
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

#[no_mangle]
pub extern "C" fn rs_http2_detect_settingsctx_match(
    ctx: *const std::os::raw::c_void, tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, parser::DetectHTTP2settingsSigCtx);
    let tx = cast_pointer!(tx, HTTP2Transaction);
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
    }
    if direction & STREAM_TOCLIENT != 0 {
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

#[no_mangle]
pub extern "C" fn rs_http2_detect_sizeupdatectx_match(
    ctx: *const std::os::raw::c_void, tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let ctx = cast_pointer!(ctx, parser::DetectU64Data);
    let tx = cast_pointer!(tx, HTTP2Transaction);
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
    }
    if direction & STREAM_TOCLIENT != 0 {
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
    }
    if direction & STREAM_TOCLIENT != 0 {
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
pub unsafe extern "C" fn rs_http2_tx_get_header(
    tx: &mut HTTP2Transaction, direction: u8, nb: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    let mut pos = 0 as u32;
    if direction & STREAM_TOSERVER != 0 {
        for i in 0..tx.frames_ts.len() {
            match &tx.frames_ts[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if nb < pos + hd.blocks.len() as u32 {
                        let vec = http2_escape_header(&hd, nb - pos);
                        let value = &vec;
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
    if direction & STREAM_TOCLIENT != 0 {
        for i in 0..tx.frames_tc.len() {
            match &tx.frames_tc[i].data {
                HTTP2FrameTypeData::HEADERS(hd) => {
                    if nb < pos + hd.blocks.len() as u32 {
                        let vec = http2_escape_header(&hd, nb - pos);
                        let value = &vec;
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
