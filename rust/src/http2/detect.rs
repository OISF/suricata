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
pub extern "C" fn rs_http2_tx_get_frametype(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    //TODO6tx check use of direction
    match direction {
        STREAM_TOSERVER => match &tx.ftype {
            None => {
                return -1;
            }
            Some(x) => {
                return *x as i32;
            }
        },
        STREAM_TOCLIENT => match &tx.ftype {
            None => {
                return -1;
            }
            Some(x) => {
                return *x as i32;
            }
        },
        _ => {}
    }

    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_frametype(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = unsafe { CStr::from_ptr(str) };
    if let Ok(s) = ft_name.to_str() {
        if let Ok(x) = parser::HTTP2FrameType::from_str(s) {
            return x as i32;
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_errorcode(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    match direction {
        STREAM_TOSERVER => match &tx.type_data {
            Some(HTTP2FrameTypeData::GOAWAY(goaway)) => {
                return goaway.errorcode as i32;
            }
            Some(HTTP2FrameTypeData::RSTSTREAM(rst)) => {
                return rst.errorcode as i32;
            }
            _ => {
                return -1;
            }
        },
        STREAM_TOCLIENT => match &tx.type_data {
            Some(HTTP2FrameTypeData::GOAWAY(goaway)) => {
                return goaway.errorcode as i32;
            }
            Some(HTTP2FrameTypeData::RSTSTREAM(rst)) => {
                return rst.errorcode as i32;
            }
            _ => {
                return -1;
            }
        },
        _ => {}
    }

    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_errorcode(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = unsafe { CStr::from_ptr(str) };
    if let Ok(s) = ft_name.to_str() {
        if let Ok(x) = parser::HTTP2ErrorCode::from_str(s) {
            return x as i32;
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_priority(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    match direction {
        STREAM_TOSERVER => match &tx.type_data {
            Some(HTTP2FrameTypeData::PRIORITY(prio)) => {
                return prio.weight as i32;
            }
            Some(HTTP2FrameTypeData::HEADERS(hd)) => {
                if let Some(prio) = hd.priority {
                    return prio.weight as i32;
                }
            }
            _ => {
                return -1;
            }
        },
        STREAM_TOCLIENT => match &tx.type_data {
            Some(HTTP2FrameTypeData::PRIORITY(prio)) => {
                return prio.weight as i32;
            }
            Some(HTTP2FrameTypeData::HEADERS(hd)) => {
                if let Some(prio) = hd.priority {
                    return prio.weight as i32;
                }
            }
            _ => {
                return -1;
            }
        },
        _ => {}
    }

    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_window(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    match direction {
        STREAM_TOSERVER => match &tx.type_data {
            Some(HTTP2FrameTypeData::WINDOWUPDATE(wu)) => {
                return wu.sizeinc as i32;
            }
            _ => {
                return -1;
            }
        },
        STREAM_TOCLIENT => match &tx.type_data {
            Some(HTTP2FrameTypeData::WINDOWUPDATE(wu)) => {
                return wu.sizeinc as i32;
            }
            _ => {
                return -1;
            }
        },
        _ => {}
    }

    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_settingsid(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = unsafe { CStr::from_ptr(str) };
    if let Ok(s) = ft_name.to_str() {
        if let Ok(x) = parser::HTTP2SettingsId::from_str(s) {
            return x as i32;
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_http2_detect_settingsctx_parse(
    str: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_void {
    let ft_name: &CStr = unsafe { CStr::from_ptr(str) };
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = parser::http2_parse_settingsctx(s) {
            let boxed = Box::new(ctx);
            return unsafe { transmute(boxed) };
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub extern "C" fn rs_http2_detect_settingsctx_free(ctx: *mut std::os::raw::c_void) {
    // Just unbox...
    let _ctx: Box<parser::DetectHTTP2settingsSigCtx> = unsafe { transmute(ctx) };
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
    match direction {
        STREAM_TOSERVER => match &tx.type_data {
            Some(HTTP2FrameTypeData::SETTINGS(set)) => {
                return http2_detect_settings_match(set, ctx)
            }
            _ => {}
        },
        STREAM_TOCLIENT => match &tx.type_data {
            Some(HTTP2FrameTypeData::SETTINGS(set)) => {
                return http2_detect_settings_match(set, ctx)
            }
            _ => {}
        },
        _ => {}
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_header_name(
    tx: *mut std::os::raw::c_void, direction: u8, i: u32, buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    match direction {
        STREAM_TOSERVER => match &tx.type_data {
            Some(HTTP2FrameTypeData::HEADERS(hd)) => {
                if (i as usize) < hd.blocks.len() {
                    let value = &hd.blocks[i as usize].name;
                    unsafe {
                        *buffer = value.as_ptr();
                        *buffer_len = value.len() as u32;
                    }
                    return 1;
                }
            }
            _ => {
                return 0;
            }
        },
        STREAM_TOCLIENT => match &tx.type_data {
            Some(HTTP2FrameTypeData::HEADERS(hd)) => {
                if (i as usize) < hd.blocks.len() {
                    let value = &hd.blocks[i as usize].name;
                    unsafe {
                        *buffer = value.as_ptr();
                        *buffer_len = value.len() as u32;
                    }
                    return 1;
                }
            }
            _ => {
                return 0;
            }
        },
        _ => {}
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
pub extern "C" fn rs_http2_tx_get_header(
    tx: *mut std::os::raw::c_void, direction: u8, i: u32, buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    match direction {
        STREAM_TOSERVER => match &tx.type_data {
            Some(HTTP2FrameTypeData::HEADERS(hd)) => {
                if (i as usize) < hd.blocks.len() {
                    let vec = http2_escape_header(hd, i);
                    let value = &vec;
                    unsafe {
                        *buffer = value.as_ptr();
                        *buffer_len = value.len() as u32;
                    }
                    return 1;
                }
            }
            _ => {
                return 0;
            }
        },
        STREAM_TOCLIENT => match &tx.type_data {
            Some(HTTP2FrameTypeData::HEADERS(hd)) => {
                if (i as usize) < hd.blocks.len() {
                    let mut vec = Vec::new();
                    for j in 0..hd.blocks[i as usize].name.len() {
                        vec.push(hd.blocks[i as usize].name[j]);
                        /* this escaping is needed
                         * to avoid amibguity with separator between name and value
                         */
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
                    let value = &vec;
                    unsafe {
                        *buffer = value.as_ptr();
                        *buffer_len = value.len() as u32;
                    }
                    return 1;
                }
            }
            _ => {
                return 0;
            }
        },
        _ => {}
    }

    return 0;
}
