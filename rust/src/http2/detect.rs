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
use std::str::FromStr;

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_frametype(
    tx: *mut std::os::raw::c_void,
    direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
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

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_frametype(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = unsafe { CStr::from_ptr(str) };
    match ft_name.to_str() {
        Ok(s) => {
            let p = parser::HTTP2FrameType::from_str(s);
            match p {
                Ok(x) => {
                    return x as i32;
                }
                Err(_) => {
                    return -1;
                }
            }
        }
        Err(_) => {
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_errorcode(
    tx: *mut std::os::raw::c_void,
    direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    match direction {
        STREAM_TOSERVER => match &tx.type_data {
            Some(HTTP2FrameTypeData::GOAWAY(goaway)) => {
                return goaway.errorcode as i32;
            }
            _ => {
                return -1;
            }
        },
        STREAM_TOCLIENT => match &tx.type_data {
            Some(HTTP2FrameTypeData::GOAWAY(goaway)) => {
                return goaway.errorcode as i32;
            }
            _ => {
                return -1;
            }
        },
        _ => {}
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_errorcode(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let ft_name: &CStr = unsafe { CStr::from_ptr(str) };
    match ft_name.to_str() {
        Ok(s) => {
            let p = parser::HTTP2ErrorCode::from_str(s);
            match p {
                Ok(x) => {
                    return x as i32;
                }
                Err(_) => {
                    return -1;
                }
            }
        }
        Err(_) => {
            return -1;
        }
    }
}
