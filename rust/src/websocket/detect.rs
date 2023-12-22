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

use super::websocket::WebSocketTransaction;
use crate::detect::uint::{
    detect_parse_uint, detect_parse_uint_enum, DetectUintData, DetectUintMode,
};
use crate::websocket::parser::WebSocketOpcode;

use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag};
use nom7::combinator::{opt, value};
use nom7::multi::many1;
use nom7::IResult;

use std::ffi::CStr;

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetOpcode(tx: &mut WebSocketTransaction) -> u8 {
    return tx.pdu.opcode;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetFlags(tx: &mut WebSocketTransaction) -> u8 {
    return tx.pdu.flags;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetPayload(
    tx: &WebSocketTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    *buffer = tx.pdu.payload.as_ptr();
    *buffer_len = tx.pdu.payload.len() as u32;
    return true;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketGetMask(
    tx: &mut WebSocketTransaction, value: *mut u32,
) -> bool {
    if let Some(xorkey) = tx.pdu.mask {
        *value = xorkey;
        return true;
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketParseOpcode(
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

#[no_mangle]
pub unsafe extern "C" fn SCWebSocketParseFlags(
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
