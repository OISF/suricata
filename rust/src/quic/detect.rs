/* Copyright (C) 2021 Open Information Security Foundation
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

use crate::quic::quic::{QuicState, QuicTransaction};
use std::ptr;

#[no_mangle]
pub extern "C" fn rs_quic_tx_get_cyu_hash(
    tx: &QuicTransaction, i: u16, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.hash;

        unsafe {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
        }

        1
    } else {
        unsafe {
            *buffer = ptr::null();
            *buffer_len = 0;
        }

        0
    }
}

#[no_mangle]
pub extern "C" fn rs_quic_tx_get_cyu_string(
    tx: &QuicTransaction, i: u16, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.string;

        unsafe {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
        }

        1
    } else {
        unsafe {
            *buffer = ptr::null();
            *buffer_len = 0;
        }

        0
    }
}

#[no_mangle]
pub extern "C" fn rs_quic_tx_get_version(tx: &QuicState) -> u32 {
    tx.version
}
