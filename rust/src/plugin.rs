/* Copyright (C) 2020 Open Information Security Foundation
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

//! Plugin utility module.

use core::ffi::c_int;

pub fn init() {
    unsafe {
        let context = super::core::SCGetContext();
        super::core::init_ffi(context);

        super::debug::SCSetRustLogLevel(super::debug::SCLogGetLogLevel());
    }
}

// Struct definitions
#[repr(C)]
#[allow(non_snake_case)]
pub struct SCPlugin {
    pub name: *const libc::c_char,
    pub license: *const libc::c_char,
    pub author: *const libc::c_char,
    pub Init: extern "C" fn(),
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct SCAppLayerPlugin {
    pub version: u64,
    pub name: *const libc::c_char,
    pub Register: unsafe extern "C" fn(),
    pub KeywordsRegister: unsafe extern "C" fn(),
    pub logname: *const libc::c_char,
    pub confname: *const libc::c_char,
    pub Logger: unsafe extern "C" fn(
        tx: *const std::os::raw::c_void,
        jb: *mut std::os::raw::c_void,
    ) -> bool,
}

// Every change in the API used by plugins should change this number
pub const SC_PLUGIN_API_VERSION: u64 = 8;

/// cbindgen:ignore
extern {
    pub fn SCPluginRegisterAppLayer(plugin: *const SCAppLayerPlugin) -> c_int;
}
