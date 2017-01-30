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

//! Definition from Suricata core.

extern crate libc;

pub const STREAM_TOSERVER: u8 = 0x04;
pub const STREAM_TOCLIENT: u8 = 0x08;

// Callbacks into Suricata core.
extern {
    pub fn DetectEngineContentInspection(de_ctx: *mut libc::c_void,
                                         det_ctx: *mut libc::c_void,
                                         s: *mut libc::c_void,
                                         sm: *mut libc::c_void,
                                         f: *mut libc::c_void,
                                         buffer: *const libc::uint8_t,
                                         buffer_len: libc::uint32_t,
                                         stream_start_offset: libc::uint32_t,
                                         inspection_mode: libc::uint8_t,
                                         data: *mut libc::c_void) -> u32;
}
