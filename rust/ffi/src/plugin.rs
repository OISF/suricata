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

//! Plugin utility module.

use std::{ffi::CString, os::raw::c_char};
use suricata_sys::sys::{SCLogGetLogLevel, SCPlugin, SC_API_VERSION, SC_PACKAGE_VERSION};

pub fn init() {
    unsafe {
        crate::ndebug::set_log_level(SCLogGetLogLevel());
    }
}

pub struct Plugin {
    pub name: &'static str,

    /// Plugin version.
    pub version: &'static str,
    pub license: &'static str,
    pub author: &'static str,
    pub init: unsafe extern "C" fn(),
}

impl Plugin {
    /// Convert the plugin into a raw pointer suitable for plugin
    /// registration.
    pub fn into_raw(self) -> *mut SCPlugin {
        let name = CString::new(self.name)
            .expect("plugin name must not contain NUL bytes")
            .into_raw() as *const c_char;
        let plugin_version = CString::new(self.version)
            .expect("plugin version must not contain NUL bytes")
            .into_raw() as *const c_char;
        let license = CString::new(self.license)
            .expect("plugin license must not contain NUL bytes")
            .into_raw() as *const c_char;
        let author = CString::new(self.author)
            .expect("plugin author must not contain NUL bytes")
            .into_raw() as *const c_char;

        let plugin = SCPlugin {
            version: SC_API_VERSION,
            suricata_version: SC_PACKAGE_VERSION.as_ptr() as *const c_char,
            name,
            plugin_version,
            license,
            author,
            Init: Some(self.init),
        };

        Box::into_raw(Box::new(plugin))
    }
}
