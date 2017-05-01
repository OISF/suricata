/* Copyright (C) 2017 Open Information Security Foundation
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

extern crate libc;
extern crate nom;

use std::slice;

use dns::parser::*;

#[no_mangle]
pub extern "C" fn rs_dns_probe(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::uint8_t
{
    let slice: &[u8] = unsafe {
        slice::from_raw_parts(input as *mut u8, len as usize)
    };
    match dns_parse_request(slice) {
        nom::IResult::Done(_, _) => {
            return 1;
        }
        _ => {
            return 0;
        }
    }
}
