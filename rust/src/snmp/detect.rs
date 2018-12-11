/* Copyright (C) 2017-2018 Open Information Security Foundation
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
use snmp::snmp::SNMPTransaction;

#[no_mangle]
pub extern "C" fn rs_snmp_tx_get_version(tx: &mut SNMPTransaction,
                                         version: *mut libc::uint32_t)
{
    debug_assert!(tx.version != 0, "SNMP version is 0");
    unsafe {
        *version = tx.version as libc::uint32_t;
    }
}

#[no_mangle]
pub extern "C" fn rs_snmp_tx_get_community(tx: &mut SNMPTransaction,
                                           buf: *mut *const libc::uint8_t,
                                           len: *mut libc::uint32_t)
{
    match tx.community {
        Some(ref c) => {
            unsafe {
                *buf = (&c).as_ptr();
                *len = c.len() as libc::uint32_t;
            }
        },
        None        => ()
    }
}
