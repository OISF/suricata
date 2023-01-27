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

use crate::jsonbuilder::JsonBuilder;
use crate::x509::time::format_timestamp;
use std::ffi::CStr;
use std::os::raw::c_char;

/// Helper function to log a TLS timestamp from C to JSON with the
/// provided key. The format of the timestamp is ISO 8601 timestamp
/// with no sub-second or offset information as UTC is assumed.
///
/// # Safety
///
/// FFI function that dereferences pointers from C.
#[no_mangle]
pub unsafe extern "C" fn sc_x509_log_timestamp(
    jb: &mut JsonBuilder, key: *const c_char, timestamp: i64,
) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        if let Ok(timestamp) = format_timestamp(timestamp) {
            return jb.set_string(key, &timestamp).is_ok();
        }
    }
    false
}
