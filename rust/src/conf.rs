/* Copyright (C) 2017 Open Information Security Foundation
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

use std::os::raw::c_char;
use std::os::raw::c_void;
use std::os::raw::c_int;
use std::ffi::{CString, CStr};
use std::ptr;
use std::str;

use crate::log::*;

extern {
    fn ConfGet(key: *const c_char, res: *mut *const c_char) -> i8;
    fn ConfGetChildValue(conf: *const c_void, key: *const c_char,
                         vptr: *mut *const c_char) -> i8;
    fn ConfGetChildValueBool(conf: *const c_void, key: *const c_char,
                             vptr: *mut c_int) -> i8;
}

// Return the string value of a configuration value.
pub fn conf_get(key: &str) -> Option<&str> {
    let mut vptr: *const c_char = ptr::null_mut();

    unsafe {
        if ConfGet(CString::new(key).unwrap().as_ptr(), &mut vptr) != 1 {
            SCLogInfo!("Failed to find value for key {}", key);
            return None;
        }
    }

    if vptr == ptr::null() {
        return None;
    }

    let value = str::from_utf8(unsafe{
        CStr::from_ptr(vptr).to_bytes()
    }).unwrap();

    return Some(value);
}

// Return the value of key as a boolean. A value that is not set is
// the same as having it set to false.
pub fn conf_get_bool(key: &str) -> bool {
    match conf_get(key) {
        Some(val) => {
            match val {
                "1" | "yes" | "true" | "on" => {
                    return true;
                },
                _ => {},
            }
        },
        None => {},
    }

    return false;
}

/// Wrap a Suricata ConfNode and expose some of its methods with a
/// Rust friendly interface.
pub struct ConfNode {
    pub conf: *const c_void,
}

impl ConfNode {

    pub fn wrap(conf: *const c_void) -> ConfNode {
        return ConfNode{
            conf: conf,
        }
    }

    pub fn get_child_value(&self, key: &str) -> Option<&str> {
        let mut vptr: *const c_char = ptr::null_mut();

        unsafe {
            if ConfGetChildValue(self.conf,
                                 CString::new(key).unwrap().as_ptr(),
                                 &mut vptr) != 1 {
                return None;
            }
        }

        if vptr == ptr::null() {
            return None;
        }

        let value = str::from_utf8(unsafe{
            CStr::from_ptr(vptr).to_bytes()
        }).unwrap();

        return Some(value);
    }

    pub fn get_child_bool(&self, key: &str) -> bool {
        let mut vptr: c_int = 0;

        unsafe {
            if ConfGetChildValueBool(self.conf,
                                     CString::new(key).unwrap().as_ptr(),
                                     &mut vptr) != 1 {
                return false;
            }
        }

        if vptr == 1 {
            return true;
        }
        return false;
    }

}
