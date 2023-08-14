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

use super::bacnetip::BacNetIpTransaction;
use super::parser::BacNetPacket;
use crate::core::*;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

#[derive(Debug, PartialEq, Eq)]
pub struct DetectBvlcFunc {
    negate: bool,
    bvlcfunc: u8,
}

fn parse_bvlcfunc(bvlcfunc: &str) -> Result<DetectBvlcFunc, ()> {
    let mut negated = false;
    for (i, c) in bvlcfunc.chars().enumerate() {
        match c {
            ' ' | '\t' => {
                continue;
            }
            '!' => {
                negated = true;
            }
            _ => {
                let bvlcfunc_code: u8 = bvlcfunc[i..].parse().map_err(|_| ())?;
                return Ok(DetectBvlcFunc {
                    negate: negated,
                    bvlcfunc: bvlcfunc_code,
                });
            }
        }
    }
    Err(())
}

/// Perform the DNS opcode match.
///
/// 1 will be returned on match, otherwise 0 will be returned.
#[no_mangle]
pub extern "C" fn rs_bacnet_bvlcfunc_match(
    tx: &mut BacNetIpTransaction, detect: &mut DetectBvlcFunc, flags: u8,
) -> u8 {
    let packet: &BacNetPacket = if flags & Direction::ToServer as u8 != 0 {
        if let Some(request) = &tx.request {
            request
        } else {
            return 0;
        }
    } else if flags & Direction::ToClient as u8 != 0 {
        if let Some(response) = &tx.response {
            response
        } else {
            return 0;
        }
    } else {
        // Not to server or to client??
        return 0;
    };

    match_bvlcfunc(detect, packet.bvlc_func).into()
}

fn match_bvlcfunc(detect: &DetectBvlcFunc, bvlcfunc: u8) -> bool {
    if detect.negate {
        detect.bvlcfunc != bvlcfunc
    } else {
        detect.bvlcfunc == bvlcfunc
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_bacnetip_bvlcfunc_parse(carg: *const c_char) -> *mut c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }
    let arg = match CStr::from_ptr(carg).to_str() {
        Ok(arg) => arg,
        _ => {
            return std::ptr::null_mut();
        }
    };

    match parse_bvlcfunc(arg) {
        Ok(detect) => Box::into_raw(Box::new(detect)) as *mut _,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_bacnetip_detect_bvlcfunc_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        std::mem::drop(Box::from_raw(ptr as *mut DetectBvlcFunc));
    }
}
