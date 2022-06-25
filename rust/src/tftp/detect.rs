/* Copyright (C) 2022 Open Information Security Foundation
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

use crate::tftp::tftp::TFTPTransaction;

#[no_mangle]
pub unsafe extern "C" fn rs_tftp_tx_get_file(
    tx: &mut TFTPTransaction, buf: *mut *const u8, len: *mut u32,
) {
    *buf = tx.filename.as_ptr();
    *len = tx.filename.len() as u32;
}
