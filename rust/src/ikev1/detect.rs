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
use std::ptr;
use std::ffi::CStr;

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_exch_type(
    tx: &mut IKEV1Transaction,
    exch_type: *mut u32,
) -> u8 {
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
    if let Some(ref r) = tx.spi_initiator {
        let p = &format!("{:016x}", r);
        if p.len() > 0 {
            unsafe {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
            }
            return 1;
        }
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
    if let Some(ref r) = tx.spi_responder {
        let p = &format!("{:016x}", r);
        if p.len() > 0 {
            unsafe {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
            }
            return 1;
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_client_nonce(
    state: &mut IKEV1State,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if !state.client_nonce.is_empty() {
        let p = &state.client_nonce;
        if p.len() > 0 {
            unsafe {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
            }
            return 1;
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_server_nonce(
    state: &mut IKEV1State,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if !state.server_nonce.is_empty() {
        let p = &state.server_nonce;
        if p.len() > 0 {
            unsafe {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
            }
            return 1;
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_client_key_exchange(
    state: &mut IKEV1State,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if !state.client_key_exchange.is_empty() {
        let p = &state.client_key_exchange;
        if p.len() > 0 {
            unsafe {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
            }
            return 1;
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_server_key_exchange(
    state: &mut IKEV1State,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if !state.server_key_exchange.is_empty() {
        let p = &state.server_key_exchange;
        if p.len() > 0 {
            unsafe {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
            }
            return 1;
        }
    }

    unsafe {
        *buffer = ptr::null();
        *buffer_len = 0;
    }

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ikev1_state_vendors_contain(
    state: &mut IKEV1State,
    input: *const std::os::raw::c_char,
) -> u8 {
    if let Ok(vendor_id) = CStr::from_ptr(input).to_str() {
        if state.client_vendor_ids.contains(vendor_id) {
            return 1;
        }
        if state.server_vendor_ids.contains(vendor_id) {
            return 1;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ikev1_state_get_sa_attribute(
    state: &mut IKEV1State,
    sa_type: *const std::os::raw::c_char,
    value: *mut u32,
) -> u8 {
    if let Ok(sa) = CStr::from_ptr(sa_type).to_str() {
        let mut index = 0;
        for server_transform in &state.server_transforms {
            if index >= 1 {
                // this should never happen!
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
            index += 1;
        }
    }

    *value = 0;

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_key_exchange_payload_length(
    state: &mut IKEV1State,
    host_type: u32,
    value: *mut u32,
) -> u8 {
    if host_type == 1 && !state.client_key_exchange.is_empty() {
        unsafe {
            *value = state.client_key_exchange.len() as u32;
        }
        return 1;
    } else if host_type == 2 && !state.server_key_exchange.is_empty() {
        unsafe {
            *value = state.server_key_exchange.len() as u32;
        }
        return 1;
    }

    unsafe {
        *value = 0;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ikev1_state_get_nonce_payload_length(
    state: &mut IKEV1State,
    host_type: u32,
    value: *mut u32,
) -> u8 {
    if host_type == 1 && !state.client_nonce.is_empty() {
        unsafe {
            *value = state.client_nonce.len() as u32;
        }
        return 1;
    } else if host_type == 2 && !state.server_nonce.is_empty() {
        unsafe {
            *value = state.server_nonce.len() as u32;
        }
        return 1;
    }

    unsafe{
        *value = 0;
    }
    return 0;
}