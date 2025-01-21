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

//! Bindings to Suricata C EVE related functions such as creating a
//! filetype.

use std::ffi::{c_char, c_int, c_void, CString};

/// cbindgen:ignore
extern "C" {
    pub fn SCRegisterEveFileType(filetype: *const EveFileType) -> bool;
}

pub type EveFileInitFn =
    unsafe extern "C" fn(conf: *const c_void, threaded: bool, init_data: *mut *mut c_void) -> c_int;
pub type EveFileDeinitFn = unsafe extern "C" fn(init_data: *const c_void);
pub type EveFileWriteFn = unsafe extern "C" fn(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
    thread_data: *const c_void,
) -> c_int;
pub type EveFileThreadInitFn = unsafe extern "C" fn(
    init_data: *const c_void,
    thread_id: std::os::raw::c_int,
    thread_data: *mut *mut c_void,
) -> c_int;
pub type EveFileThreadDeinitFn =
    unsafe extern "C" fn(init_data: *const c_void, thread_data: *mut c_void);

/// Rust equivalent to C SCEveFileType.
///
/// NOTE: Needs to be kept in sync with SCEveFileType.
///
/// cbindgen:ignore
#[repr(C)]
pub struct EveFileType {
    name: *const c_char,
    open: EveFileInitFn,
    thread_init: EveFileThreadInitFn,
    write: EveFileWriteFn,
    thread_deinit: EveFileThreadDeinitFn,
    close: EveFileDeinitFn,
    pad: [usize; 2],
}

impl EveFileType {
    pub fn new(
        name: &str, open: EveFileInitFn, close: EveFileDeinitFn, write: EveFileWriteFn,
        thread_init: EveFileThreadInitFn, thread_deinit: EveFileThreadDeinitFn,
    ) -> *const Self {
        // Convert the name to C and forget.
        let name = CString::new(name).unwrap().into_raw();
        let file_type = Self {
            name,
            open,
            close,
            write,
            thread_init,
            thread_deinit,
            pad: [0, 0],
        };
        Box::into_raw(Box::new(file_type))
    }
}
