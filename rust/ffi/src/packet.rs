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

use std::marker::PhantomData;

use suricata_sys::sys;

pub struct Packet<'a> {
    ptr: *const sys::Packet,
    _marker: PhantomData<&'a sys::Packet>,
}

impl<'a> Packet<'a> {
    pub fn from_ptr(ptr: *const sys::Packet) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn as_ptr(&self) -> *const sys::Packet {
        self.ptr
    }
}
