/* Copyright (C) 2018 Open Information Security Foundation
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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use crate::krb::krb5::KRB5Transaction;

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_msgtype(tx: &mut KRB5Transaction, ptr: *mut u32) {
    *ptr = tx.msg_type.0;
}

/// Get error code, if present in transaction
/// Return 0 if error code was filled, else 1
#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_errcode(tx: &mut KRB5Transaction, ptr: *mut i32) -> u32 {
    match tx.error_code {
        Some(ref e) => {
            *ptr = e.0;
            0
        }
        None => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_cname(
    tx: &mut KRB5Transaction, i: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref s) = tx.cname {
        if (i as usize) < s.name_string.len() {
            let value = &s.name_string[i as usize];
            *buffer = value.as_ptr();
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_sname(
    tx: &mut KRB5Transaction, i: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref s) = tx.sname {
        if (i as usize) < s.name_string.len() {
            let value = &s.name_string[i as usize];
            *buffer = value.as_ptr();
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    0
}
