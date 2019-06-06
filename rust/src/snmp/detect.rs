/* Copyright (C) 2017-2019 Open Information Security Foundation
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

use snmp::snmp::SNMPTransaction;

#[no_mangle]
pub extern "C" fn rs_snmp_tx_get_version(tx: &mut SNMPTransaction,
                                         version: *mut u32)
{
    debug_assert!(tx.version != 0, "SNMP version is 0");
    unsafe {
        *version = tx.version as u32;
    }
}

#[no_mangle]
pub extern "C" fn rs_snmp_tx_get_community(tx: &mut SNMPTransaction,
                                           buf: *mut *const u8,
                                           len: *mut u32)
{
    match tx.community {
        Some(ref c) => {
            unsafe {
                *buf = (&c).as_ptr();
                *len = c.len() as u32;
            }
        },
        None        => ()
    }
}

#[no_mangle]
pub extern "C" fn rs_snmp_tx_get_pdu_type(tx: &mut SNMPTransaction,
                                          pdu_type: *mut u32)
{
    unsafe {
        match tx.info {
            Some(ref info) => {
                *pdu_type = info.pdu_type.0 as u32;
            },
            None           => {
                *pdu_type = 0xffffffff;
            }
        }
    }
}
