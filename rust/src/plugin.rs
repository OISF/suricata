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

use std::ffi::{c_char, CString};

/// Rust representation of a C plugin.
///
/// Mirror of SCPlugin from C and they should be kept in sync.
#[repr(C)]
pub struct SCPlugin {
    name: *const c_char,
    license: *const c_char,
    author: *const c_char,
    init: unsafe extern "C" fn(),
}

impl SCPlugin {
    pub fn new(
        name: &str, license: &str, author: &str, init_fn: unsafe extern "C" fn(),
    ) -> *const Self {
        let name = CString::new(name).unwrap();
        let license = CString::new(license).unwrap();
        let author = CString::new(author).unwrap();
        let plugin = SCPlugin {
            name: name.into_raw(),
            license: license.into_raw(),
            author: author.into_raw(),
            init: init_fn,
        };
        Box::into_raw(Box::new(plugin))
    }
}

pub fn init() {
    unsafe {
        let context = crate::core::SCGetContext();
        crate::core::init_ffi(context);

        crate::debug::LEVEL = crate::debug::SCLogGetLogLevel();
    }
}
