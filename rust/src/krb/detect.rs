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

use libc;
use std::ffi::CStr;

use krb::krb5::KRB5Transaction;

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_msgtype(tx:  &mut KRB5Transaction,
                                                ptr: *mut libc::uint32_t)
{
    *ptr = tx.msg_type.0;
}

/// Compare provided name with cname in transaction
/// Returns 0 if equal
#[no_mangle]
pub extern "C" fn rs_krb5_tx_cmp_cname(tx:  &mut KRB5Transaction,
                                              ptr: *const libc::c_char) -> i32
{
    match tx.cname {
        None        => -1,
        Some(ref s) => {
            let c_str: &CStr = unsafe { CStr::from_ptr(ptr) };
            if let Ok(str_slice) = c_str.to_str() {
                if s.name_string.iter().any(|x| &str_slice == &x) { 0 } else { 1 }
            } else {
                -1
            }
        }
    }
}

/// Compare provided name with sname in transaction
/// Returns 0 if equal
#[no_mangle]
pub extern "C" fn rs_krb5_tx_cmp_sname(tx:  &mut KRB5Transaction,
                                              ptr: *const libc::c_char) -> i32
{
    match tx.sname {
        None        => -1,
        Some(ref s) => {
            let c_str: &CStr = unsafe { CStr::from_ptr(ptr) };
            if let Ok(str_slice) = c_str.to_str() {
                if s.name_string.iter().any(|x| &str_slice == &x) { 0 } else { 1 }
            } else {
                -1
            }
        }
    }
}
