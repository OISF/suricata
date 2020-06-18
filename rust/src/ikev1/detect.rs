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

// Author: Frank Honza <frank.honza@dcso.de>

use crate::ikev1::ikev1::*;
use crate::log::*;
use std::ptr;
use std::ffi::CStr;

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_exch_type(
    tx: &mut IKEV1Transaction,
    exch_type: *mut u32,
) -> u8 {
    if exch_type == std::ptr::null_mut() {
        return 0;
    }

    if let Some(r) = tx.exchange_type {
        unsafe{
            *exch_type = r as u32;
        }
        return 1;
    }

    unsafe {
        *exch_type = 0;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_spi_initiator(
    tx: &mut IKEV1Transaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut() {
        return 0;
    }

    if let Some(ref r) = tx.spi_initiator {
        unsafe {
            *buffer = r.as_ptr();
            *buffer_len = r.len() as u32;
        }
        return 1;
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_spi_responder(
    tx: &mut IKEV1Transaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut() {
        return 0;
    }

    if let Some(ref r) = tx.spi_responder {
        unsafe {
            *buffer = r.as_ptr();
            *buffer_len = r.len() as u32;
        }
        return 1;
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_nonce(
    tx: &mut IKEV1Transaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut() {
        return 0;
    }

    if !tx.nonce.is_empty() {
        let p = &tx.nonce;
        unsafe {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
        }
        return 1;
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_key_exchange(
    tx: &mut IKEV1Transaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut() {
        return 0;
    }

    if !tx.key_exchange.is_empty() {
        let p = &tx.key_exchange;
        unsafe {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
        }
        return 1;
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ikev1_state_vendors_contain(
    tx: &mut IKEV1Transaction,
    input: *const std::os::raw::c_char,
) -> u8 {
    if let Ok(vendor_id) = CStr::from_ptr(input).to_str() {
        if tx.vendor_ids.contains(vendor_id) {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ikev1_state_get_sa_attribute(
    tx: &mut IKEV1Transaction,
    sa_type: *const std::os::raw::c_char,
    value: *mut u32,
) -> u8 {
    if value == std::ptr::null_mut() {
        return 0;
    }

    if let Ok(sa) = CStr::from_ptr(sa_type).to_str() {
        for (i, server_transform) in tx.transforms.iter().enumerate() {
            if i >= 1 {
                SCLogDebug!("More than one chosen proposal from responder, should not happen.");
                break;
            }
            for attr in server_transform {
                if attr.attribute_type.to_string() == sa {
                    if let Some(numeric_value) = attr.numeric_value {
                        *value = numeric_value;
                        return 1;
                    }
                }
            }
        }
    }

    *value = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ikev1_state_get_key_exchange_payload_length(
    tx: &mut IKEV1Transaction,
    value: *mut u32,
) -> u8 {
    if value == std::ptr::null_mut() {
        return 0;
    }

    if !tx.key_exchange.is_empty() {
        *value = tx.key_exchange.len() as u32;
        return 1;
    }

    *value = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ikev1_state_get_nonce_payload_length(
    tx: &mut IKEV1Transaction,
    value: *mut u32,
) -> u8 {
    if value == std::ptr::null_mut() {
        return 0;
    }

    if !tx.nonce.is_empty() {
        *value = tx.nonce.len() as u32;
        return 1;
    }

    *value = 0;
    return 0;
}