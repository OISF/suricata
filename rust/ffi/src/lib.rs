/* Copyright (C) 2026 Open Information Security Foundation
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

pub mod conf;
pub mod debug;
pub mod detect;
pub mod eve;
pub mod jsonbuilder;
pub mod plugin;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub const STREAM_START: u8 = 0x01;
pub const STREAM_EOF: u8 = 0x02;
pub const STREAM_TOSERVER: u8 = 0x04;
pub const STREAM_TOCLIENT: u8 = 0x08;
pub const STREAM_GAP: u8 = 0x10;
pub const STREAM_DEPTH: u8 = 0x20;
pub const STREAM_MIDSTREAM: u8 = 0x40;

/// Cast pointer to a variable, as a mutable reference to an object
///
/// UNSAFE !
#[macro_export]
macro_rules! cast_pointer {
    ($ptr:ident, $ty:ty) => {
        &mut *($ptr as *mut $ty)
    };
}

/// Create a slice, given a buffer and a length
///
/// UNSAFE !
#[macro_export]
macro_rules! build_slice {
    ($buf:ident, $len:expr) => {
        std::slice::from_raw_parts($buf, $len)
    };
}
