/* Copyright (C) 2019-2022 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::core::Direction;
use crate::sip::sip::SIPTransaction;
use std::ptr;

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_method(
    tx: &mut SIPTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.request {
        let m = &r.method;
        if m.len() > 0 {
            *buffer = m.as_ptr();
            *buffer_len = m.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_uri(
    tx: &mut SIPTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.request {
        let p = &r.path;
        if p.len() > 0 {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_protocol(
    tx: &mut SIPTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
    direction: u8,
) -> u8 {
    match direction.into() {
        Direction::ToServer => {
            if let Some(ref r) = tx.request {
                let v = &r.version;
                if v.len() > 0 {
                    *buffer = v.as_ptr();
                    *buffer_len = v.len() as u32;
                    return 1;
                }
            }
        }
        Direction::ToClient => {
            if let Some(ref r) = tx.response {
                let v = &r.version;
                if v.len() > 0 {
                    *buffer = v.as_ptr();
                    *buffer_len = v.len() as u32;
                    return 1;
                }
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_stat_code(
    tx: &mut SIPTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.response {
        let c = &r.code;
        if c.len() > 0 {
            *buffer = c.as_ptr();
            *buffer_len = c.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_stat_msg(
    tx: &mut SIPTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.response {
        let re = &r.reason;
        if re.len() > 0 {
            *buffer = re.as_ptr();
            *buffer_len = re.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_request_line(
    tx: &mut SIPTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.request_line {
        if r.len() > 0 {
            *buffer = r.as_ptr();
            *buffer_len = r.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_sip_tx_get_response_line(
    tx: &mut SIPTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.response_line {
        if r.len() > 0 {
            *buffer = r.as_ptr();
            *buffer_len = r.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}
