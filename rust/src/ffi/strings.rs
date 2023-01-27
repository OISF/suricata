/* Copyright (C) 2023 Open Information Security Foundation
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

use std::ffi::CString;
use std::os::raw::c_char;

/// FFI utility function to copy a Rust string to a C string buffer.
///
/// Return true on success. On error, false will be returned.
///
/// An error will be returned if the provided string cannot be
/// converted to a C string (for example, it contains NULs), or if the
/// provided buffer is not large enough.
///
/// # Safety
///
/// Unsafe as this depends on the caller providing valid buf and size
/// parameters.
pub unsafe fn copy_to_c_char(src: String, buf: *mut c_char, size: usize) -> bool {
    if let Ok(src) = CString::new(src) {
        let src = src.as_bytes_with_nul();
        if size >= src.len() {
            let buf = std::slice::from_raw_parts_mut(buf as *mut u8, size);
            buf[0..src.len()].copy_from_slice(src);
            return true;
        }
    }
    false
}
