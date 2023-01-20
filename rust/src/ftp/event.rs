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

use crate::core::AppLayerEventType;
use std::os::raw::{c_char, c_int};

#[derive(Debug, PartialEq, Eq, AppLayerEvent)]
#[repr(C)]
pub enum FtpEvent {
    #[name("request_command_too_long")]
    FtpEventRequestCommandTooLong,
    #[name("response_command_too_long")]
    FtpEventResponseCommandTooLong,
}

/// Wrapper around the Rust generic function for get_event_info.
///
/// # Safety
/// Unsafe as called from C.
#[no_mangle]
pub unsafe extern "C" fn ftp_get_event_info(
    event_name: *const c_char, event_id: *mut c_int, event_type: *mut AppLayerEventType,
) -> c_int {
    crate::applayer::get_event_info::<FtpEvent>(event_name, event_id, event_type)
}

/// Wrapper around the Rust generic function for get_event_info_by_id.
///
/// # Safety
/// Unsafe as called from C.
#[no_mangle]
pub unsafe extern "C" fn ftp_get_event_info_by_id(
    event_id: c_int, event_name: *mut *const c_char, event_type: *mut AppLayerEventType,
) -> c_int {
    crate::applayer::get_event_info_by_id::<FtpEvent>(event_id, event_name, event_type) as c_int
}
