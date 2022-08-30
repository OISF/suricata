/* Copyright (C) 2021-2022 Open Information Security Foundation
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

use crate::quic::quic::QuicTransaction;
use std::ptr;

#[no_mangle]
pub unsafe extern "C" fn rs_quic_tx_get_ua(
    tx: &QuicTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ua) = &tx.ua {
        *buffer = ua.as_ptr();
        *buffer_len = ua.len() as u32;
        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_quic_tx_get_sni(
    tx: &QuicTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(sni) = &tx.sni {
        *buffer = sni.as_ptr();
        *buffer_len = sni.len() as u32;
        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_quic_tx_get_ja3(
    tx: &QuicTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ja3) = &tx.ja3 {
        *buffer = ja3.as_ptr();
        *buffer_len = ja3.len() as u32;
        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_quic_tx_get_version(
    tx: &QuicTransaction, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if tx.header.flags.is_long {
        let s = &tx.header.version_buf;
        *buffer = s.as_ptr();
        *buffer_len = s.len() as u32;
        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_quic_tx_get_cyu_hash(
    tx: &QuicTransaction, i: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.hash;

        *buffer = p.as_ptr();
        *buffer_len = p.len() as u32;

        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;

        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_quic_tx_get_cyu_string(
    tx: &QuicTransaction, i: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.string;

        *buffer = p.as_ptr();
        *buffer_len = p.len() as u32;
        1
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;

        0
    }
}
