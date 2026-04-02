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

//! Conf utils.

use crate::SCLogDebug;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use suricata_sys::sys::SCConfGet;

// Return the string value of a configuration value.
pub fn conf_get(key: &str) -> Option<&str> {
    let mut vptr: *const c_char = ptr::null_mut();

    unsafe {
        let s = CString::new(key).unwrap();
        if SCConfGet(s.as_ptr(), &mut vptr) != 1 {
            SCLogDebug!("Failed to find value for key {}", key);
            return None;
        }
    }

    if vptr.is_null() {
        return None;
    }

    let value = std::str::from_utf8(unsafe { CStr::from_ptr(vptr).to_bytes() }).unwrap();

    Some(value)
}
