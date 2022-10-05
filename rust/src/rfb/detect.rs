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

use crate::rfb::rfb::*;
use std::ptr;

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_tx_get_name(
    tx: &mut RFBTransaction,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.tc_server_init {
        let p = &r.name;
        if p.len() > 0 {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_tx_get_sectype(
    tx: &mut RFBTransaction,
    sectype: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.chosen_security_type {
        *sectype = *r;
        return 1;
    }

    *sectype = 0;

    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_tx_get_secresult(
    tx: &mut RFBTransaction,
    secresult: *mut u32,
) -> u8 {
    if let Some(ref r) = tx.tc_security_result {
        *secresult = r.status;
        return 1;
    }

    0
}