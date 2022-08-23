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

use std::ptr;

#[no_mangle]
pub unsafe extern "C" fn rs_get_domain(input: *const u8, len: u32, output: *mut u8, olen: *mut u64) -> bool {
    let slice: &[u8] = std::slice::from_raw_parts(input as *mut u8, len as usize);
    let result = psl::domain(slice);
    match result {
        Some(x) => {
            let domain = x.as_bytes();
            ptr::copy(domain.as_ptr(), output, domain.len());
            *olen = domain.len() as u64;
            true
        },
        None    => false
    }
}
