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

use crate::ike::ike::*;
use std::ptr;
use std::ffi::CStr;
use super::ipsec_parser::IkeV2Transform;

#[no_mangle]
pub extern "C" fn rs_ike_state_get_exch_type(
    tx: &mut IKETransaction,
    exch_type: *mut u8,
) -> u8 {
    debug_validate_bug_on!(exch_type == std::ptr::null_mut());

    if tx.ike_version == 1 {
        if let Some(r) = tx.hdr.ikev1_header.exchange_type {
            unsafe {
                *exch_type = r;
            }
            return 1;
        }
    } else if tx.ike_version == 2 {
        unsafe {
            *exch_type = tx.hdr.ikev2_header.exch_type.0;
        }
        return 1;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_spi_initiator(
    tx: &mut IKETransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    debug_validate_bug_on!(buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut());

    unsafe {
        *buffer = tx.hdr.spi_initiator.as_ptr();
        *buffer_len = tx.hdr.spi_initiator.len() as u32;
    }
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_spi_responder(
    tx: &mut IKETransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    debug_validate_bug_on!(buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut());

    unsafe {
        *buffer = tx.hdr.spi_responder.as_ptr();
        *buffer_len = tx.hdr.spi_responder.len() as u32;
    }
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ike_state_get_nonce(
    tx: &mut IKETransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    debug_validate_bug_on!(buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.nonce.is_empty() {
        let p = &tx.hdr.ikev1_header.nonce;
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
pub extern "C" fn rs_ike_state_get_key_exchange(
    tx: &mut IKETransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    debug_validate_bug_on!(buffer == std::ptr::null_mut() || buffer_len == std::ptr::null_mut());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.key_exchange.is_empty() {
        let p = &tx.hdr.ikev1_header.key_exchange;
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
pub extern "C" fn rs_ike_tx_get_vendor(
    tx: &IKETransaction,
    i: u16,
    buf: *mut *const u8,
    len: *mut u32)
    -> u8
{
    if tx.ike_version == 1 && i < tx.hdr.ikev1_header.vendor_ids.len() as u16 {
        unsafe {
            *len = tx.hdr.ikev1_header.vendor_ids[i as usize].len() as u32;
            *buf = tx.hdr.ikev1_header.vendor_ids[i as usize].as_ptr();
        }
        return 1;
    }

    unsafe {
        *buf = ptr::null();
        *len = 0;
    }

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ike_state_get_sa_attribute(
    tx: &mut IKETransaction,
    sa_type: *const std::os::raw::c_char,
    value: *mut u32,
) -> u8 {
    debug_validate_bug_on!(value == std::ptr::null_mut());

    if let Ok(sa) = CStr::from_ptr(sa_type).to_str() {
        if tx.ike_version == 1 {
            for (i, server_transform) in tx.hdr.ikev1_transforms.iter().enumerate() {
                if i >= 1 {
                    debug_validate_bug_on!(true);
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
        else if tx.ike_version == 2 {
            for server_transform in tx.hdr.ikev2_transforms.iter() {
                for attr in server_transform {
                    match attr {
                        IkeV2Transform::Encryption(e) => {
                            if sa == "alg_enc" {
                                *value = e.0 as u32;
                                return 1;
                            }
                        },
                        IkeV2Transform::Auth(e) => {
                            if sa == "alg_auth" {
                                *value = e.0 as u32;
                                return 1;
                            }
                        },
                        IkeV2Transform::PRF(ref e) => {
                            if sa == "alg_prf" {
                                *value = e.0 as u32;
                                return 1;
                            }
                        },
                        IkeV2Transform::DH(ref e) => {
                            if sa == "alg_dh" {
                                *value = e.0 as u32;
                                return 1;
                            }
                        },
                        _ => ()
                    }
                }
            }
        }
    }

    *value = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ike_state_get_key_exchange_payload_length(
    tx: &mut IKETransaction,
    value: *mut u32,
) -> u8 {
    debug_validate_bug_on!(value == std::ptr::null_mut());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.key_exchange.is_empty() {
        *value = tx.hdr.ikev1_header.key_exchange.len() as u32;
        return 1;
    }

    *value = 0;
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ike_state_get_nonce_payload_length(
    tx: &mut IKETransaction,
    value: *mut u32,
) -> u8 {
    debug_validate_bug_on!(value == std::ptr::null_mut());

    if tx.ike_version == 1 && !tx.hdr.ikev1_header.nonce.is_empty() {
        *value = tx.hdr.ikev1_header.nonce.len() as u32;
        return 1;
    }

    *value = 0;
    return 0;
}