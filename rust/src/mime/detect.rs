/* Copyright (C) 2025 Open Information Security Foundation
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

use super::mime;
use super::smtp::MimeStateSMTP;
use crate::mime::smtp::MimeSmtpMd5State;
use std::ffi::CStr;
use std::ptr;

/// Intermediary function used in detect-email.c to access data from the MimeStateSMTP structure.
/// The hname parameter determines which data will be returned.
#[no_mangle]
pub unsafe extern "C" fn SCDetectMimeEmailGetData(
    ctx: &MimeStateSMTP, buffer: *mut *const u8, buffer_len: *mut u32,
    hname: *const std::os::raw::c_char,
) -> u8 {
    let c_str = CStr::from_ptr(hname); //unsafe
    let str = c_str.to_str().unwrap_or("");

    for h in &ctx.headers[..ctx.main_headers_nb] {
        if mime::slice_equals_lowercase(&h.name, str.as_bytes()) {
            *buffer = h.value.as_ptr();
            *buffer_len = h.value.len() as u32;
            return 1;
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectMimeEmailGetUrl(
    ctx: &MimeStateSMTP, buffer: *mut *const u8, buffer_len: *mut u32, idx: u32,
) -> u8 {
    if !ctx.urls.is_empty() && idx < ctx.urls.len() as u32 {
        let url = &ctx.urls[idx as usize];
        *buffer = url.as_ptr();
        *buffer_len = url.len() as u32;
        return 1;
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

static mut HASH_BUF: Option<String> = None;
#[no_mangle]
pub unsafe extern "C" fn SCDetectMimeEmailGetBodyMd5(
    ctx: &MimeStateSMTP, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if ctx.md5_state == MimeSmtpMd5State::MimeSmtpMd5Completed {
        HASH_BUF = Some(format!("{:x}", ctx.md5_result));
        let hash = HASH_BUF.as_ref().unwrap();

        *buffer = hash.as_ptr();
        *buffer_len = hash.len() as u32;
        return 1;
    }

    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}
